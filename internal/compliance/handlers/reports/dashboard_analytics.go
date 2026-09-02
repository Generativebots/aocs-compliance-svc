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
	"log/slog"
	"net/http"

	"github.com/ocx/shared/respond"

	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
)

func HandleGetTrustTaxClaims(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var taxes []map[string]any
		var configRows []map[string]any

		runConcurrent(r.Context(), []dbQuery{
			// Trust tax transactions live in nexus_staking_ledger with event_type='FEDERATION_TAX'
			{fn: func() error {
				return db.QueryRowsCompound(database.TblNexusStakingLedger, database.ColsNexusStakingLedger,
					"event_type", "FEDERATION_TAX", "tenant_id", tenantID, &taxes)
			}},
			{fn: func() error {
				return db.QueryRowsCtx(r.Context(), database.TblCoreGovConfig, database.ColsAocsTenantGovernanceConfig, "tenant_id", tenantID, &configRows)
			}},
		})

		var configObj map[string]any
		if len(configRows) > 0 {
			configObj = configRows[0]
		}

		respond.JSON(w, http.StatusOK, map[string]any{
			"taxes":  orEmpty(taxes),
			"config": configObj,
		})
	}
}

// 16. NETWORK EFFECTS DASHBOARD — GET /api/v1/neef/dashboard
//     Replaces: /neef/growth + /fed/metrics  (2 → 1)

// 17. IMPACT ANALYSIS DASHBOARD — GET /api/v1/impact/dashboard
//     Replaces: /impact/assumptions + /impact/estimates + /impact/simulations
//               + /impact/reports + /impact/templates  (5 → 1)

func HandleGetImpactClaims(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		// OPTIMISED: Was 4 concurrent hits on the same core_evidence table.
		// Now: 1 query loads all rows, Go partitions by impact_type in a single pass.
		// NOTE: the real column is impact_type, not record_type (schema verified).
		var allImpact []map[string]any
		var reports []map[string]any

		// Expanded projection includes impact_type for partitioning
		const impactCols = "estimate_id,tenant_id,policy_id,impact_type,impact_score," +
			"impact_description,current_monthly_cost,a2a_monthly_savings," +
			"net_monthly_savings,annual_roi,confidence_pct,created_at"

		runConcurrent(r.Context(), []dbQuery{
			{fn: func() error {
				return db.QueryRowsCtx(r.Context(), database.TblCoreEvidence, impactCols, "tenant_id", tenantID, &allImpact)
			}},
			{fn: func() error {
				return db.QueryRowsCtx(r.Context(), database.TblSharComplianceReports, database.ColsNexusComplianceReports, "tenant_id", tenantID, &reports)
			}},
		})

		// Partition by impact_type in one pass — avoids 3 extra DB round-trips.
		// real column: impact_type (core_evidence schema, verified 2026-07-17)
		var assumptions, estimates, simulations, templates []map[string]any
		for _, row := range allImpact {
			it, _ := row["impact_type"].(string)
			switch it {
			case "assumption":
				assumptions = append(assumptions, row)
			case "estimate":
				estimates = append(estimates, row)
			case "simulation":
				simulations = append(simulations, row)
			case "template":
				templates = append(templates, row)
			default:
				// Rows with no impact_type land in estimates (backward compat)
				estimates = append(estimates, row)
			}
		}

		respond.JSON(w, http.StatusOK, map[string]any{
			"assumptions": orEmpty(assumptions),
			"estimates":   orEmpty(estimates),
			"simulations": orEmpty(simulations),
			"reports":     orEmpty(reports),
			"templates":   orEmpty(templates),
		})
	}
}

// 18. GOV TESTING DASHBOARD — GET /api/v1/gov/testing/dashboard
//     Replaces: /gov/tests + /gov/coverage  (2 → 1)

func HandleGetGovernanceTestingClaims(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var tests []map[string]any
		var coverage []map[string]any

		runConcurrent(r.Context(), []dbQuery{
			{fn: func() error {
				return db.QueryRowsCtx(r.Context(), database.TblCorePolicies, database.ColsQcorePolicies, "tenant_id", tenantID, &tests)
			}},
			{fn: func() error {
				return db.QueryRowsCtx(r.Context(), database.TblSharComplianceReports, database.ColsNexusComplianceReports, "tenant_id", tenantID, &coverage)
			}},
		})

		var coverageObj map[string]any
		if len(coverage) > 0 {
			coverageObj = coverage[0]
		}

		respond.JSON(w, http.StatusOK, map[string]any{
			"tests":    orEmpty(tests),
			"coverage": coverageObj,
		})
	}
}

// 19. MARKETPLACE ANALYTICS DASHBOARD — GET /api/v1/marketplace/analytics/dashboard
//     Replaces: /marketplace/revenue/analytics + /marketplace/billing/summary  (2 → 1)

func HandleGetMarketplaceAnalyticsClaims(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var revenue []map[string]any
		var billing []map[string]any

		runConcurrent(r.Context(), []dbQuery{
			{fn: func() error {
				return db.QueryRowsCtx(r.Context(), database.TblSharLedger, database.ColsNufaMarketplaceRevenuePayouts, "buyer_tenant_id", tenantID, &revenue)
			}},
			{fn: func() error {
				return db.QueryRowsCtx(r.Context(), database.TblConnectorInstalls, database.ColsNufaMarketplaceInstallations, "tenant_id", tenantID, &billing)
			}},
		})

		var revenueObj map[string]any
		if len(revenue) > 0 {
			revenueObj = revenue[0]
		}

		respond.JSON(w, http.StatusOK, map[string]any{
			"analytics": revenueObj,
			"billing":   orEmpty(billing),
		})
	}
}

// 20. TRIFACTOR DASHBOARD — GET /api/v1/trifactor/dashboard
//     Replaces: /esc/history + /esc/stats + /hitl/decisions  (3 → 1)
//     Supports: ?start=<ISO>&end=<ISO> date filters

func HandleGetTrifactorClaims(db database.DB) http.HandlerFunc {
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
		var held, released, expired, passCount int
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
			"history":             orEmpty(history),
			"core_hitl": orEmpty(decisions),
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

// 21. TENANT PERMISSIONS DASHBOARD — GET /api/v1/tenant/permissions/dashboard
//     Alias of /tenant/access/dashboard — permissions + roles + departments  (3 → 1)

// HandleGetTenantPermissionsClaims is an alias of HandleGetAccessClaims
// surfaced at the /tenant/permissions/dashboard path for the permissions matrix page.
var HandleGetTenantPermissionsClaims = HandleGetAccessClaims

// HELPER: nil-safe empty slice for JSON output

func orEmpty(s []map[string]any) []map[string]any {
	if s == nil {
		return []map[string]any{}
	}
	return s
}

// SANCTION SUMMARY — GET /api/v1/sanction-summary
// Sanctions are the enforcement outcome of jury verdicts. This is core proof
// that the Cognitive Auditor is issuing enforceable outcomes.

// HandleGetSanctionSummary returns a summary of enforcement sanctions for the tenant.
// Queries core_enforcement_actions for sanction-type entries.
func HandleGetSanctionSummary(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var actions []struct {
			ID         string  `json:"id"`
			TenantID   string  `json:"tenant_id"`
			AgentID    *string `json:"agent_id,omitempty"`
			ActionType string  `json:"action_type"`
			Severity   string  `json:"severity"`
			Status     string  `json:"status"`
			Reason     string  `json:"reason,omitempty"`
			CreatedAt  string  `json:"created_at"`
		}

		// X-08 FIX: DB query failure returned empty array → dashboard showed "0 violations"
		// during outages. Operators saw clean dashboard during most dangerous periods.
		dataUnavailable := false
		if tenantID != "" {
			if _dbErr := db.QueryRowsCtx(r.Context(), database.TblCoreCompliance, database.ColsComplianceCases, "tenant_id", tenantID, &actions); _dbErr != nil {
				slog.Error("X-08: compliance actions DB query failed — dashboard will show DATA_UNAVAILABLE",
					"tenant_id", tenantID, "err", _dbErr)
				dataUnavailable = true
			}
		} else {
			if _dbErr := db.QueryRowsCtx(r.Context(), database.TblCoreCompliance, database.ColsComplianceCases, "tenant_id", tenantID, &actions); _dbErr != nil {
				slog.Error("X-08: compliance actions DB query failed (no tenant filter) — dashboard will show DATA_UNAVAILABLE", "err", _dbErr)
				dataUnavailable = true
			}
		}
		if actions == nil {
			actions = []struct {
				ID         string  `json:"id"`
				TenantID   string  `json:"tenant_id"`
				AgentID    *string `json:"agent_id,omitempty"`
				ActionType string  `json:"action_type"`
				Severity   string  `json:"severity"`
				Status     string  `json:"status"`
				Reason     string  `json:"reason,omitempty"`
				CreatedAt  string  `json:"created_at"`
			}{}
		}

		// Aggregate by action_type and severity
		byType := map[string]int{}
		bySeverity := map[string]int{}
		active, resolved := 0, 0
		for _, a := range actions {
			byType[a.ActionType]++
			bySeverity[a.Severity]++
			if a.Status == "active" || a.Status == "ACTIVE" || a.Status == "pending" {
				active++
			} else {
				resolved++
			}
		}

		respond.OK(w, map[string]any{
			"total":            len(actions),
			"active":           active,
			"resolved":         resolved,
			"by_type":          byType,
			"by_severity":      bySeverity,
			"sanctions":        actions,
			"tenant_id":        tenantID,
			"data_unavailable": dataUnavailable,
		})
	}
}

// VIOLATION SUMMARY — GET /api/v1/violation-summary
// for the entire jury/HITL governance loop.

// HandleGetViolationSummary returns a summary of violations triggering jury workflow.
// Queries core_enforcement_actions (compliance_violation type) + gra_cases.
func HandleGetViolationSummary(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		// core_enforcement_actions: compliance_violation entries
		var actions []struct {
			ID         string  `json:"id"`
			TenantID   string  `json:"tenant_id"`
			AgentID    *string `json:"agent_id,omitempty"`
			ActionType string  `json:"action_type"`
			Severity   string  `json:"severity"`
			Status     string  `json:"status"`
			Reason     string  `json:"reason,omitempty"`
			CreatedAt  string  `json:"created_at"`
		}
		if tenantID != "" {
			if _dbErr := db.QueryRowsCompound(database.TblCoreCompliance, database.ColsComplianceCases, "action_type", "compliance_violation", "tenant_id", tenantID, &actions); _dbErr != nil {
				slog.Error("db operation failed", "method", "QueryRowsCompound", "error", _dbErr)
			}
		} else {
			if _dbErr := db.QueryRowsCompoundCtx(r.Context(), database.TblCoreCompliance, database.ColsComplianceCases, "action_type", "compliance_violation", "tenant_id", tenantID, &actions); _dbErr != nil {
				slog.Error("db operation failed", "method", "QueryRows", "error", _dbErr)
			}
		}
		if actions == nil {
			actions = []struct {
				ID         string  `json:"id"`
				TenantID   string  `json:"tenant_id"`
				AgentID    *string `json:"agent_id,omitempty"`
				ActionType string  `json:"action_type"`
				Severity   string  `json:"severity"`
				Status     string  `json:"status"`
				Reason     string  `json:"reason,omitempty"`
				CreatedAt  string  `json:"created_at"`
			}{}
		}

		// gra_cases: open risk/verification cases
		var cases []struct {
			ID        string  `json:"id"`
			TenantID  string  `json:"tenant_id"`
			AgentID   *string `json:"agent_id,omitempty"`
			CaseType  string  `json:"case_type"`
			Status    string  `json:"status"`
			RiskLevel string  `json:"risk_level"`
			RiskScore float64 `json:"risk_score"`
			CreatedAt string  `json:"created_at"`
		}
		if tenantID != "" {
			if _dbErr := db.QueryRowsCtx(r.Context(), database.TblGRACases, "gra_case_id,tenant_id,agent_id,case_type,status,risk_level,risk_score,created_at", "tenant_id", tenantID, &cases); _dbErr != nil {
				slog.Error("db operation failed", "method", "QueryRows", "error", _dbErr)
			}
		}
		if cases == nil {
			cases = []struct {
				ID        string  `json:"id"`
				TenantID  string  `json:"tenant_id"`
				AgentID   *string `json:"agent_id,omitempty"`
				CaseType  string  `json:"case_type"`
				Status    string  `json:"status"`
				RiskLevel string  `json:"risk_level"`
				RiskScore float64 `json:"risk_score"`
				CreatedAt string  `json:"created_at"`
			}{}
		}

		// Aggregate
		bySeverity := map[string]int{}
		byRisk := map[string]int{}
		for _, a := range actions {
			bySeverity[a.Severity]++
		}
		for _, c := range cases {
			byRisk[c.RiskLevel]++
		}

		respond.OK(w, map[string]any{
			"total_violations": len(actions),
			"total_cases":      len(cases),
			"by_severity":      bySeverity,
			"by_risk_level":    byRisk,
			"violations":       actions,
			"cases":            cases,
			"tenant_id":        tenantID,
		})
	}
}
