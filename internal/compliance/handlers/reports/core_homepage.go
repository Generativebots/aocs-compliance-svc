package reports

import (
	"log/slog"
	"net/http"

	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
)

// HandleGetAnalyticsCoreHomepage aggregates platform summary metrics for the AOCS homepage dashboard.
//
// GET /api/v1/monitor/insights
//
// Response shape (matches CoreHomepage interface in homepage-api.ts):
//
//	{
//	  "total_agents":   42,
//	  "total_policies": 18,
//	  "total_alerts":   5,
//	  "system_metrics": {
//	    "uptime_pct":    99.2,
//	    "breach_count":  3,
//	    "open_hitl":     12,
//	    "active_agents": 38
//	  }
//	}
func HandleGetAnalyticsCoreHomepage(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized, "missing tenant_id")
			return
		}

		// Count core_agents
		var agents []map[string]any
		if _dbErr := db.QueryRowsCtx(r.Context(), database.TblCoreAgents, "agent_id,status", "tenant_id", tenantID, &agents); _dbErr != nil {
			slog.Error("db operation failed", "method", "QueryRows", "error", _dbErr)
		}
		totalAgents := len(agents)
		activeAgents := 0
		for _, a := range agents {
			if s, ok := a["status"].(string); ok && (s == "Active" || s == "ACTIVE") {
				activeAgents++
			}
		}

		// Count policies — canonical table is qcore_policies (gov_policies was a naming error)
		var policies []map[string]any
		if _dbErr := db.QueryRowsCtx(r.Context(), database.TblQCorePolicies, "policy_id", "tenant_id", tenantID, &policies); _dbErr != nil {
			slog.Error("db operation failed", "method", "QueryRows", "error", _dbErr)
		}

		// Count open alerts from senti_alerts
		var alerts []map[string]any
		if _dbErr := db.QueryRowsCtx(r.Context(), database.TblSharAlerts, "senti_alert_id,status", "tenant_id", tenantID, &alerts); _dbErr != nil {
			slog.Error("db operation failed", "method", "QueryRows", "error", _dbErr)
		}
		openAlerts := 0
		for _, a := range alerts {
			if s, ok := a["status"].(string); ok && (s == "OPEN" || s == "ACKNOWLEDGED") {
				openAlerts++
			}
		}

		// Count pending HITL cases
		var hitlCases []map[string]any
		if _dbErr := db.QueryRowsCtx(r.Context(), database.TblCoreHitl, "decision_id,status,sla_breach_at", "tenant_id", tenantID, &hitlCases); _dbErr != nil {
			slog.Error("db operation failed", "method", "QueryRows", "error", _dbErr)
		}
		openHITL := 0
		breachCount := 0
		for _, c := range hitlCases {
			if s, ok := c["status"].(string); ok && (s == "PENDING" || s == "OPEN" || s == "IN_REVIEW") {
				openHITL++
			}
			if slaAt, ok := c["sla_breach_at"].(string); ok && slaAt != "" && slaAt != "null" {
				breachCount++
			}
		}

		// Compute uptime
		uptimePct := 100.0
		if totalAgents > 0 {
			uptimePct = float64(activeAgents) / float64(totalAgents) * 100.0
		}

		respond.OK(w, map[string]any{
			"total_agents":   totalAgents,
			"total_policies": len(policies),
			"total_alerts":   openAlerts,
			"system_metrics": map[string]any{
				"uptime_pct":    uptimePct,
				"breach_count":  breachCount,
				"open_hitl":     openHITL,
				"active_agents": activeAgents,
			},
		})
	}
}
