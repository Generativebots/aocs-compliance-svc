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

// 16. NETWORK EFFECTS DASHBOARD — GET /api/v1/neef/dashboard
//     Replaces: /neef/growth + /fed/metrics  (2 → 1)

// 17. IMPACT ANALYSIS DASHBOARD — GET /api/v1/impact/dashboard
//     Replaces: /impact/assumptions + /impact/estimates + /impact/simulations
//               + /impact/reports + /impact/templates  (5 → 1)

// 18. GOV TESTING DASHBOARD — GET /api/v1/gov/testing/dashboard
//     Replaces: /gov/tests + /gov/coverage  (2 → 1)

// 19. MARKETPLACE ANALYTICS DASHBOARD — GET /api/v1/marketplace/analytics/dashboard
//     Replaces: /marketplace/revenue/analytics + /marketplace/billing/summary  (2 → 1)

// 20. TRIFACTOR DASHBOARD — GET /api/v1/trifactor/dashboard
//     Replaces: /esc/history + /esc/stats + /hitl/decisions  (3 → 1)
//     Supports: ?start=<ISO>&end=<ISO> date filters

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
