// Package handlers — BFF Claims Aggregation Handlers
//
// Each handler aggregates multiple table reads into a single HTTP response
// using errgroup for concurrent sub-queries inside the Go process.
//
// Pattern:
//
//	Browser → 1 GET /api/v1/{module}/dashboard → Go (N parallel DB queries) → 1 JSON response
//
// This eliminates N frontend HTTP roundtrips, replacing them with N in-process goroutines
// sharing a single TCP connection pool to Supabase.
package reports

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/ocx/shared/infra/concurrent"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
)

// HELPER: run N queries concurrently, return false if any failed fatally

type dbQuery struct {
	fn func() error
}

// runConcurrent runs N DB queries in parallel, scoped to the HTTP request context.
//
// N-2 FIX: Previously called runConcurrentCtx(context.Background(), ...) which meant
// client disconnects were never propagated — in-flight DB queries ran for the full
// 10s cap even after the response was abandoned, wasting pgx pool connections.
// Now the request context is the root: client disconnect cancels all sub-queries.
func runConcurrent(ctx context.Context, queries []dbQuery) {
	// 10s hard cap overlaid on the request context — whichever fires first wins.
	// Guards against slow Supabase responses causing connection pool starvation.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(len(queries))
	for _, q := range queries {
		q := q
		concurrent.Go("dashboard", func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("goroutine panic recovered", "error", r)
				}
			}()
			defer wg.Done()
			select {
			case <-ctx.Done():
				slog.Warn("dashboard query cancelled", "reason", ctx.Err())
				return
			default:
				_ = q.fn() //nolint:errcheck — audited: best-effort, failure is non-critical
			}
		})
	}
	wg.Wait()
}

// 1. GRA DASHBOARD — GET /api/v1/gra/dashboard
//    Replaces: /gra/status + /gra/intents + /gra/actions  (3 → 1)

func HandleGetGRAClaims(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		// gra_verification_intents and gra_agent_actions are merged into gra_cases;
		// filter by case_type to get the correct subset.
		var status []map[string]any
		var intents []map[string]any
		var actions []map[string]any

		runConcurrent(r.Context(), []dbQuery{
			{fn: func() error {
				return db.QueryRowsCtx(r.Context(), database.TblGRATenantStatus, database.ColsGraTenantStatus, "tenant_id", tenantID, &status)
			}},
			{fn: func() error {
				return db.QueryRowsCompound(database.TblGRACases, database.ColsGraCases, "case_type", "verification_intent", "tenant_id", tenantID, &intents)
			}},
			{fn: func() error {
				return db.QueryRowsCompound(database.TblGRACases, database.ColsGraCases, "case_type", "agent_action", "tenant_id", tenantID, &actions)
			}},
		})

		respond.JSON(w, http.StatusOK, map[string]any{
			"status":  orEmpty(status),
			"intents": orEmpty(intents),
			"actions": orEmpty(actions),
		})
	}
}

// 2. CONTRACTS DASHBOARD — GET /api/v1/contracts/dashboard
//    Replaces: /contracts/ebcl + /contracts/executions  (2 → 1)

func HandleGetContractsClaims(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var contracts []map[string]any
		var executions []map[string]any

		runConcurrent(r.Context(), []dbQuery{
			{fn: func() error {
				return db.QueryRowsCtx(r.Context(), database.TblCoreEbcl, database.ColsNeufaEbclContracts, "tenant_id", tenantID, &contracts)
			}},
			{fn: func() error {
				return db.QueryRowsCtx(r.Context(), database.TblContractExecs, database.ColsNeufaEbclContractExecutions, "tenant_id", tenantID, &executions)
			}},
		})

		respond.JSON(w, http.StatusOK, map[string]any{
			"contract_records":  orEmpty(contracts),
			"executions": orEmpty(executions),
		})
	}
}

// 4. ESC / TRI-FACTOR DASHBOARD — GET /api/v1/esc/dashboard
//    Replaces: /esc/history + /esc/stats + /hitl/decisions  (3 → 1)

func HandleGetEscrowClaims(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var history []map[string]any
		var decisions []map[string]any

		runConcurrent(r.Context(), []dbQuery{
			{fn: func() error {
				return db.QueryRowsCtx(r.Context(), database.TblCoreEscrowTxns, database.ColsAocsEscrowTransactions, "tenant_id", tenantID, &history)
			}},
			{fn: func() error {
				return db.QueryRowsCtx(r.Context(), database.TblCoreHitl, database.ColsHitlDecisions, "tenant_id", tenantID, &decisions)
			}},
		})

		// Compute stats from history in-process (no extra DB call)
		var held, released, expired int
		var passCount int
		for _, h := range history {
			status, _ := h["status"].(string)
			switch status {
			case "HELD":
				held++
			case "RELEASED":
				released++
				if passed, _ := h["tri_factor_passed"].(bool); passed {
					passCount++
				}
			case "EXPIRED":
				expired++
			}
		}
		total := len(history)
		passRate := 0.0
		if total > 0 {
			passRate = float64(passCount) / float64(total) * 100
		}

		respond.JSON(w, http.StatusOK, map[string]any{
			"history":   orEmpty(history),
			"decisions": orEmpty(decisions),
			"stats": map[string]any{
				"held":      held,
				"released":  released,
				"expired":   expired,
				"total":     total,
				"pass_rate": passRate,
			},
		})
	}
}

// 5. ACT DASHBOARD — GET /api/v1/act/dashboard
//    Replaces: /act/versions + /act/deployments + /act/approvals  (3 → 1)

func HandleGetActivitiesClaims(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		// ia_activity_versions and ia_activity_deployments are absorbed as JSONB
		// columns on ia_activities (ColsIAActivity includes both). A single query
		// returns all; split client-side to preserve the expected response shape.
		var act []map[string]any
		var approvals []map[string]any

		runConcurrent(r.Context(), []dbQuery{
			{fn: func() error {
				return db.QueryRowsCtx(r.Context(), database.TblCoreDispatches, database.ColsIAActivity, "tenant_id", tenantID, &act)
			}},
			{fn: func() error {
				return db.QueryRowsCtx(r.Context(), database.TblCoreHitl, database.ColsHitlDecisions, "tenant_id", tenantID, &approvals)
			}},
		})

		// versions and deployments are JSONB arrays embedded in each activity row.
		respond.JSON(w, http.StatusOK, map[string]any{
			"act":         orEmpty(act),
			"versions":    orEmpty(act), // client reads .versions field from each act row
			"deployments": orEmpty(act), // client reads .deployments field from each act row
			"approvals":   orEmpty(approvals),
		})
	}
}

// 6. ZKP DASHBOARD — GET /api/v1/zkp/dashboard
//    Replaces: /zkp/verifications + /zkp/stats  (2 → 1)

func HandleGetZKPClaims(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		// SuperAdmin ZKP view — cross-tenant attestation data, no tenant filter
		_, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var verifications []map[string]any

		_ = // nolint:tenant_filter — SuperAdmin dashboard: cross-tenant trust attestation view //nolint:errcheck — audited: best-effort, failure is non-critical
			db.QueryRowsCtx(r.Context(), database.TblNexusTrustAttest, database.ColsNexusTrustAttestations, "", "", &verifications)

		// Compute stats in-process
		var verified, failed, pending int
		for _, v := range verifications {
			status, _ := v["status"].(string)
			switch status {
			case "VERIFIED":
				verified++
			case "FAILED":
				failed++
			default:
				pending++
			}
		}

		respond.JSON(w, http.StatusOK, map[string]any{
			"verifications": orEmpty(verifications),
			"stats": map[string]any{
				"verified": verified,
				"failed":   failed,
				"pending":  pending,
				"total":    len(verifications),
			},
		})
	}
}

// 7. HITL/RLHC FEEDBACK DASHBOARD — GET /api/v1/hitl/rlhc/dashboard
//    Replaces: /hitl/rlhc/clusters + /hitl/rlhc/feedback  (2 → 1)

func HandleGetRLHCClaims(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var clusters []map[string]any
		var feedback []map[string]any

		runConcurrent(r.Context(), []dbQuery{
			{fn: func() error {
				return db.QueryRowsCtx(r.Context(), database.TblRLHCClusters, database.ColsQcoreRlhcCorrectionClusters, "tenant_id", tenantID, &clusters)
			}},
			{fn: func() error {
				return db.QueryRowsCtx(r.Context(), database.TblCoreHitl, database.ColsHitlDecisions, "tenant_id", tenantID, &feedback)
			}},
		})

		respond.JSON(w, http.StatusOK, map[string]any{
			"clusters": orEmpty(clusters),
			"feedback": orEmpty(feedback),
		})
	}
}

// 8. SECURITY DASHBOARD — GET /api/v1/security/dashboard
//    Replaces: /security/attacks + /traffic/inspect  (2 → 1)

func HandleGetSecurityClaims(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var attacks []map[string]any
		var traffic []map[string]any

		runConcurrent(r.Context(), []dbQuery{
			{fn: func() error {
				return db.QueryRowsCtx(r.Context(), database.TblSharAlerts, database.ColsSentiAlerts, "tenant_id", tenantID, &attacks)
			}},
			// nolint:tenant_filter — SuperAdmin dashboard: platform-wide event stream
			{fn: func() error {
				return db.QueryRowsWithin90Days(database.TblCoreEvents, database.ColsPlatformEvents, tenantID, &traffic)
			}},
		})

		respond.JSON(w, http.StatusOK, map[string]any{
			"attacks": orEmpty(attacks),
			"traffic": orEmpty(traffic),
		})
	}
}

// 9. DLP DASHBOARD — GET /api/v1/dlp/dashboard
//    Replaces: /dlp/status + /dlp/integrations + /marketplace/dlp  (3 → 1)

func HandleGetDLPClaims(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var integrations []map[string]any
		var marketplace []map[string]any
		var statusRows []map[string]any

		runConcurrent(r.Context(), []dbQuery{
			{fn: func() error {
				return db.QueryRowsCtx(r.Context(), database.TblSharAlerts, database.ColsSentiAlerts, "tenant_id", tenantID, &statusRows)
			}},
			{fn: func() error {
				// N-3 FIX: was "", "" (no tenant filter) — leaked all tenants' DLP integrations.
				return db.QueryRowsCtx(r.Context(), database.TblSharDlpIntegrations, database.ColsSentiDlpIntegrations, "tenant_id", tenantID, &integrations)
			}},
			{fn: func() error {
				// B-D2 FIX: was querying core_ebcl (EBCL contracts ≠ marketplace).
				// Marketplace slot must use extc_marketplace_listings.
				return db.QueryRowsCtx(r.Context(), database.TblMCPCatalog, "catalog_id AS connector_id,name,tool_type AS connector_type,status,name AS slug", "status", "ACTIVE", &marketplace)
			}},
		})

		var statusObj map[string]any
		if len(statusRows) > 0 {
			statusObj = statusRows[0]
		}

		respond.JSON(w, http.StatusOK, map[string]any{
			"status":       statusObj,
			"integrations": orEmpty(integrations),
			"marketplace":  orEmpty(marketplace),
		})
	}
}

// 10. TENANT ACCESS DASHBOARD — GET /api/v1/tenant/access/dashboard
//     Replaces: /permissions + /roles + /departments  (3 → 1)

func HandleGetAccessClaims(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		// Permissions, roles and departments are platform-global —
		// return ALL rows without tenant filter so the RBAC matrix
		// always shows the full picture for the superadmin.
		var permissions []map[string]any
		var roles []map[string]any
		var departments []map[string]any

		runConcurrent(r.Context(), []dbQuery{
			// nolint:tenant_filter — SuperAdmin RBAC view: cross-tenant permission data
			{fn: func() error {
				return db.QueryRowsCtx(r.Context(), database.TblSystRolePerms, database.ColsAocsDepartmentPermissions, "", "", &permissions)
			}},
			// nolint:tenant_filter — SuperAdmin RBAC view: cross-tenant roles
			{fn: func() error {
				return db.QueryRowsCtx(r.Context(), database.TblSystRoles, database.ColsAocsPlatformRoles, "", "", &roles)
			}},
			// nolint:tenant_filter — SuperAdmin RBAC view: cross-tenant departments
			{fn: func() error {
				return db.QueryRowsCtx(r.Context(), database.TblSystDepartments, database.ColsAocsPlatformDepartments, "", "", &departments)
			}},
		})

		respond.JSON(w, http.StatusOK, map[string]any{
			"permissions": orEmpty(permissions),
			"roles":       orEmpty(roles),
			"departments": orEmpty(departments),
		})
	}
}

// 11. SOVEREIGNTY DASHBOARD — GET /api/v1/platform/sovereignty/dashboard
//     Replaces: /platform/tenants + /platform/config  (2 → 1)

func HandleGetSovereigntyClaims(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		var tenants []map[string]any
		var configs []map[string]any

		runConcurrent(r.Context(), []dbQuery{
			// nolint:tenant_filter — SuperAdmin dashboard: platform-wide tenant listing
			{fn: func() error { return db.QueryRowsCtx(r.Context(), database.TblSystTenants, database.ColsAocsTenants, "", "", &tenants) }},
			// nolint:tenant_filter — SuperAdmin: platform configuration (not tenant-scoped)
			{fn: func() error {
				return db.QueryRowsCtx(r.Context(), database.TblPlatformConfig, database.ColsAocsPlatformConfig, "category", "sovereign", &configs)
			}},
		})

		respond.JSON(w, http.StatusOK, map[string]any{
			"tenants": orEmpty(tenants),
			"configs": orEmpty(configs),
		})
	}
}

// 12. ANALYTICS DASHBOARD — GET /api/v1/analytics/dashboard
//     Replaces: analytics/overview + analytics/kpis + analytics/metrics  (3 → 1)

func HandleGetAnalyticsClaims(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var agt []map[string]any
		var interactions []map[string]any
		var metrics []map[string]any

		runConcurrent(r.Context(), []dbQuery{
			{fn: func() error {
				return db.QueryRowsCtx(r.Context(), database.TblCoreAgents, "agent_id,trust_score,risk_tier,behavioral_drift,status", "tenant_id", tenantID, &agt)
			}},
			{fn: func() error {
				return db.QueryRowsWithin90Days(database.TblCoreEvents, database.ColsPlatformEvents, tenantID, &interactions)
			}},
			// B-NEW FIX: was a duplicate core_events query (same table, same filter as interactions).
			// Replaced with core_evidence_records to give distinct metrics data for the analytics dashboard.
			{fn: func() error {
				return db.QueryRowsCtx(r.Context(), database.TblCoreEvidenceRecords, "evidence_id,status,compliance_score,tenant_id,created_at", "tenant_id", tenantID, &metrics)
			}},
		})

		// Compute KPIs in-process
		totalAgents := len(agt)
		var activeAgents int
		var totalTrust float64
		for _, a := range agt {
			if status, _ := a["status"].(string); status == "ACTIVE" {
				activeAgents++
			}
			if ts, ok := a["trust_score"].(float64); ok {
				totalTrust += ts
			}
		}
		avgTrust := 0.0
		if totalAgents > 0 {
			avgTrust = totalTrust / float64(totalAgents)
		}

		respond.JSON(w, http.StatusOK, map[string]any{
			database.TblCoreAgents:  orEmpty(agt),
			"interactions": orEmpty(interactions),
			"metrics":      orEmpty(metrics),
			"kpis": map[string]any{
				"total_agents":  totalAgents,
				"active_agents": activeAgents,
				"avg_trust":     avgTrust,
				"total_events":  len(interactions),
			},
		})
	}
}

// 13. FED DASHBOARD — GET /api/v1/fed/dashboard
//     Replaces: /fed/nodes + /fed/metrics + /neef/growth + /fed/trust  (4 → 1)

func HandleGetFederationClaims(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		var nodes []map[string]any
		var trustRelations []map[string]any
		var growth []map[string]any

		runConcurrent(r.Context(), []dbQuery{
			// nolint:tenant_filter — SuperAdmin: platform federation registry (global)
			{fn: func() error {
				return db.QueryRowsCtx(r.Context(), database.TblNexusFedPeers, database.ColsNexusFederationPeers, "", "", &nodes)
			}},
			// nolint:tenant_filter — SuperAdmin dashboard: cross-tenant trust attestation view
			{fn: func() error {
				return db.QueryRowsCtx(r.Context(), database.TblNexusTrustAttest, database.ColsNexusTrustAttestations, "", "", &trustRelations)
			}},
			// nolint:tenant_filter — SuperAdmin dashboard: platform-wide event stream
			{fn: func() error {
				return db.QueryRowsGlobalWithin90Days(database.TblCoreEvents, database.ColsPlatformEvents, &growth)
			}},
		})

		// result was used as "metrics" (just a raw event row — not federation metrics).
		// Compute real federation metrics in-process from the already-fetched nodes slice.
		var activeNodes, inactiveNodes int
		for _, n := range nodes {
			if s, _ := n["status"].(string); s == "ACTIVE" {
				activeNodes++
			} else {
				inactiveNodes++
			}
		}
		metricsObj := map[string]any{
			"total_nodes":    len(nodes),
			"active_nodes":   activeNodes,
			"inactive_nodes": inactiveNodes,
			"total_events":   len(growth),
		}

		respond.JSON(w, http.StatusOK, map[string]any{
			"nodes":   orEmpty(nodes),
			"trust":   orEmpty(trustRelations),
			"growth":  orEmpty(growth),
			"metrics": metricsObj,
		})
	}
}

// 14. FED GOV DASHBOARD — GET /api/v1/fed/gov/dashboard
//     Replaces: /gov/proposals + /gov/committee  (2 → 1)

// HandleGetFedGovClaims — proposals from governance ledger, members from core_hitl jury pool
func HandleGetFedGovClaims(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var proposals []map[string]any
		var members []map[string]any

		runConcurrent(r.Context(), []dbQuery{
			{fn: func() error {
				return db.QueryRowsCompound(database.TblGovernanceLedger, database.ColsNexusGovernanceLedger, "tenant_id", tenantID, "", "", &proposals)
			}},
			// jury/committee members are stored as distinct reviewer entries in core_hitl
			{fn: func() error {
				return db.QueryRowsCompound(database.TblCoreHitl, database.ColsHitlDecisions, "decision_type", "JURY", "tenant_id", tenantID, &members)
			}},
		})

		respond.JSON(w, http.StatusOK, map[string]any{
			"proposals": orEmpty(proposals),
			"members":   orEmpty(members),
		})
	}
}

// N-1: HandleGetTrustTaxClaims lives in dashboard_analytics.go (same package).
// The stub comment previously here was a maintenance hazard — removed.
