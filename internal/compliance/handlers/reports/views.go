package reports

// view_handlers.go — Handlers that query DB materialised views instead of raw joins.
//
// Analytics handlers were doing raw table joins in code (expensive, inconsistent).
// These handlers query the pre-computed DB views directly, which the DB materialises
// from the same underlying tables — results are consistent and orders of magnitude faster.
//
// Views queried:
//   vw_agent_dashboard   — per-agent stats (trust score, gate verdicts, HITL rates)
//   vw_compliance_kpis   — compliance summary metrics per tenant
//
// Circular flow:
//   Agent gate calls → core_events / qcore_verdicts
//   DB views → vw_agent_dashboard, vw_compliance_kpis (live aggregation)
//   These handlers → read views → UI dashboards

import (
	"log/slog"
	"net/http"

	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
)

// HandleGetAgentDashboard — GET /api/v1/analytics/agent-dashboard
// Reads vw_agent_dashboard (DB view) instead of doing a multi-table raw join.
// Was reading raw qcore_verdicts + platform_events + reputation tables
// separately in JS — now a single DB view query.
func HandleGetAgentDashboard(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		agentID := r.URL.Query().Get("agent_id")

		var rows []map[string]any
		var err error
		if agentID != "" {
			err = db.QueryRowsCompound(database.TblVwAgentDashboard, database.ColsVwAgentDashboard, "tenant_id", tenantID, "agent_id", agentID, &rows)
		} else {
			err = db.QueryRowsCtx(r.Context(), database.TblVwAgentDashboard, database.ColsVwAgentDashboard, "tenant_id", tenantID, &rows)
		}
		if err != nil {
			slog.Warn("view query failed — falling back to empty", "tenant", tenantID, "error", err)
			rows = []map[string]any{}
		}
		if rows == nil {
			rows = []map[string]any{}
		}
		respond.OK(w, map[string]any{
			"dashboard": rows,
			"count":     len(rows),
			"source":    "vw_agent_dashboard",
		})
	}
}

// HandleGetComplianceKPIs — GET /api/v1/analytics/compliance-kpis
// Reads vw_compliance_kpis (DB view) instead of computing metrics in Go.
// Previously the compliance page computed KPIs by fetching 3+ tables
// and aggregating in code — fragile, slow, and inconsistent with the DB view.
func HandleGetComplianceKPIs(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var rows []map[string]any
		if err := db.QueryRowsCtx(r.Context(), database.TblVwComplianceKpis, database.ColsVwComplianceKpis, "tenant_id", tenantID, &rows); err != nil {
			slog.Warn("view query failed — falling back to empty", "tenant", tenantID, "error", err)
			rows = []map[string]any{}
		}
		if rows == nil {
			rows = []map[string]any{}
		}
		// If view returns no rows, return an empty KPI scaffold so the UI doesn't break
		if len(rows) == 0 {
			// REP-01 FIX: calculate sla_breach_rate from raw hitl data when view returns nothing.
			// PostgREST cannot execute aggregate expressions like COUNT(*) FILTER (...) in select=.
			// Instead, fetch the sla_breached boolean column and count in Go.
			var hitlRows []struct {
				SLABreached *bool `json:"sla_breached"`
			}
			slaBreachRate := 0.0
			totalCases := 0
			breachedCases := 0
			if statErr := db.QueryRowsCtx(r.Context(),
				database.TblCoreHitl,
				"sla_breached",
				"tenant_id", tenantID,
				&hitlRows,
			); statErr == nil {
				totalCases = len(hitlRows)
				for _, row := range hitlRows {
					if row.SLABreached != nil && *row.SLABreached {
						breachedCases++
					}
				}
				if totalCases > 0 {
					slaBreachRate = float64(breachedCases) / float64(totalCases)
				}
			}
			rows = []map[string]any{{
				"tenant_id":            tenantID,
				"total_cases":          totalCases,
				"resolved_cases":       0,
				"escalated_cases":      breachedCases,
				"avg_resolution_hours": 0,
				"sla_breach_rate":      slaBreachRate,
				"hitl_rate":            0.0,
				"source":               "vw_compliance_kpis (fallback)",
			}}
		}
		respond.OK(w, map[string]any{
			"kpis":   rows,
			"source": "vw_compliance_kpis",
		})

	}
}
