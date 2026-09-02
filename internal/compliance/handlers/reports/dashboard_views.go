// Package admin — Consolidated dashboard view handlers.
//
// Each handler executes a SINGLE SQL view query that replaces N parallel
// frontend fetches with one consolidated JSON payload.
//
//	GET /monitor/ops-health  → v_ops_health_dashboard   (operate/health page)
//	GET /trust/dashboard     → v_trust_dashboard        (economics/trust page)
//	GET /gate/dashboard      → v_gate_dashboard         (operate/gate page)
//	GET /jury/dashboard      → v_jury_dashboard         (govern/jury page)
//	GET /jury-leaderboard    → v_jury_leaderboard       (govern/jury leaderboard tab)
//
// Views are read via PostgREST exactly like tables (QueryRows / QueryRowsCompound).
// No pagination needed — each view returns a single summary row (or ordered leaderboard).
package reports

import (
	"log/slog"
	"net/http"

	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
)

// HandleGetOpsDashboard returns a consolidated ops-health snapshot from v_ops_health_dashboard.
// GET /api/v1/monitor/ops-health
// Single query replaces:
//
//	/ops/health/services  + /ops/deployments      + /ops/circuit-breakers
//	/ops/queues           + /monitor/sla           + /monitor/audit-summary
//	/ops/resources/usage  + /monitor/performance   + /analytics/errors  (9 calls → 1)
func HandleGetOpsDashboard(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		var rows []map[string]any
		// View returns one aggregate row; no filter needed — sysadmin-level data
		if err := db.QueryViewRows("v_ops_health_dashboard", "*", "", "", &rows); err != nil {
			slog.Error("HandleGetOpsDashboard view error", "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "ops dashboard", err)
			return
		}
		snapshot := map[string]any{}
		if len(rows) > 0 {
			snapshot = rows[0]
		}
		respond.JSON(w, http.StatusOK, map[string]any{
			"dashboard": snapshot,
		})
	}
}

// HandleGetTrustDashboard returns a consolidated trust snapshot from v_trust_dashboard.
// GET /api/v1/trust/dashboard
// Single query replaces:
//
//	/trust/overview + /trust/levy + /marketplace/revenue
//	/analytics/gate-performance + /analytics/agent-risk-matrix + /ledger/entries  (6 calls → 1)
func HandleGetTrustDashboard(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		var tenantID string
		if u, uErr := auth.GetAuthUser(r.Context()); uErr == nil {
			tenantID = u.TenantID
		}

		var rows []map[string]any
		var err error
		if tenantID != "" {
			err = db.QueryViewRows("v_trust_dashboard", "*", "tenant_id", tenantID, &rows)
		} else {
			err = db.QueryViewRows("v_trust_dashboard", "*", "", "", &rows)
		}
		if err != nil {
			// Gracefully handle missing view (42P01) — return empty dashboard instead of 500
			slog.Warn("HandleGetTrustDashboard: view unavailable, returning empty snapshot", "tenant_id", tenantID, "error", err)
			respond.JSON(w, http.StatusOK, map[string]any{"dashboard": map[string]any{}})
			return
		}
		snapshot := map[string]any{}
		if len(rows) > 0 {
			snapshot = rows[0]
		}
		respond.JSON(w, http.StatusOK, map[string]any{
			"dashboard": snapshot,
		})
	}
}

// HandleGetGateDashboard returns a consolidated gate snapshot from v_gate_dashboard.
// GET /api/v1/gate/dashboard
// Single query replaces:
//
//	/esc/micropayments + /qcore/verdicts + /claims/trifactor  (3 calls → 1)
func HandleGetGateDashboard(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		var tenantID string
		if u, uErr := auth.GetAuthUser(r.Context()); uErr == nil {
			tenantID = u.TenantID
		}

		var rows []map[string]any
		var err error
		if tenantID != "" {
			err = db.QueryViewRows("v_gate_dashboard", "*", "tenant_id", tenantID, &rows)
		} else {
			err = db.QueryViewRows("v_gate_dashboard", "*", "", "", &rows)
		}
		if err != nil {
			slog.Warn("HandleGetGateDashboard: view unavailable, returning empty snapshot", "tenant_id", tenantID, "error", err)
			respond.JSON(w, http.StatusOK, map[string]any{"dashboard": map[string]any{}})
			return
		}
		snapshot := map[string]any{}
		if len(rows) > 0 {
			snapshot = rows[0]
		}
		respond.JSON(w, http.StatusOK, map[string]any{
			"dashboard": snapshot,
		})
	}
}

// HandleGetJuryDashboard returns a consolidated jury snapshot from v_jury_dashboard.
// GET /api/v1/jury/dashboard
// Single query replaces:
//
//	/hitl/cases + /gov/committee/members
//	/monitor/alerts?type=sanction + /monitor/alerts?type=violation  (4 calls → 1)
func HandleGetJuryDashboard(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		var tenantID string
		if u, uErr := auth.GetAuthUser(r.Context()); uErr == nil {
			tenantID = u.TenantID
		}

		var rows []map[string]any
		var err error
		if tenantID != "" {
			err = db.QueryViewRows("v_jury_dashboard", "*", "tenant_id", tenantID, &rows)
		} else {
			err = db.QueryViewRows("v_jury_dashboard", "*", "", "", &rows)
		}
		if err != nil {
			slog.Warn("HandleGetJuryDashboard: view unavailable, returning empty snapshot", "tenant_id", tenantID, "error", err)
			respond.JSON(w, http.StatusOK, map[string]any{"dashboard": map[string]any{}})
			return
		}
		snapshot := map[string]any{}
		if len(rows) > 0 {
			snapshot = rows[0]
		}
		respond.JSON(w, http.StatusOK, map[string]any{
			"dashboard": snapshot,
		})
	}
}

// HandleGetJuryLeaderboard returns the jury leaderboard from v_jury_leaderboard.
// GET /api/v1/jury-leaderboard
// Returns ranked list of jurors by vote count and approval rate for the caller's tenant.

// Handlers for previously unused DB views (wired 2026-07-19)

// HandleGetHITLOpenDecisions queries vw_hitl_open_decisions.
// GET /api/v1/hitl/open-decisions
// Returns all PENDING decisions for the tenant with SLA timing, vote counts,
// and agent trust score — pre-joined so the frontend makes one call instead of N.
func HandleGetHITLOpenDecisions(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var rows []map[string]any
		if err := db.QueryViewRows("vw_hitl_open_decisions", "*", "tenant_id", tenantID, &rows); err != nil {
			slog.Warn("HandleGetHITLOpenDecisions: view error", "tenant_id", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "hitl open decisions", err)
			return
		}
		respond.OK(w, map[string]any{
			"decisions": orEmpty(rows),
			"count":     len(rows),
		})
	}
}

// HandleGetHITLJuryStatus queries vw_hitl_jury_status.
// GET /api/v1/hitl/jury-status
// Returns per-decision vote tallies and consensus state for all the tenant's decisions.
func HandleGetHITLJuryStatus(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var rows []map[string]any
		if err := db.QueryViewRows("vw_hitl_jury_status", "*", "tenant_id", tenantID, &rows); err != nil {
			slog.Warn("HandleGetHITLJuryStatus: view error", "tenant_id", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "hitl jury status", err)
			return
		}
		respond.OK(w, map[string]any{
			"jury_status": orEmpty(rows),
		})
	}
}

// HandleGetCompliancePosture queries vw_compliance_posture.
// GET /api/v1/compliance/posture
// Returns compliance percentage per GRA framework for the tenant.
// Replaces individual GRA obligation queries from the compliance dashboard page.
func HandleGetCompliancePosture(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var rows []map[string]any
		if err := db.QueryViewRows("vw_compliance_posture", "*", "tenant_id", tenantID, &rows); err != nil {
			slog.Warn("HandleGetCompliancePosture: view error", "tenant_id", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "compliance posture", err)
			return
		}
		// Compute an overall score weighted across frameworks
		var totalCompliant, totalObligations int
		for _, row := range rows {
			if c, ok := row["compliant"].(float64); ok {
				totalCompliant += int(c)
			}
			if t, ok := row["total_obligations"].(float64); ok {
				totalObligations += int(t)
			}
		}
		overallPct := 0.0
		if totalObligations > 0 {
			overallPct = float64(totalCompliant) / float64(totalObligations) * 100.0
		}
		respond.OK(w, map[string]any{
			"frameworks":       orEmpty(rows),
			"overall_pct":      overallPct,
			"total_obligations": totalObligations,
		})
	}
}

// HandleGetAgentTrustSummary queries vw_agent_trust_summary.
// GET /api/v1/agents/trust-summary
// Returns per-agent trust metrics: current score, reputation, 30-day verdicts,
// allow/deny ratio, avg confidence, and trust rank within the tenant.
func HandleGetAgentTrustSummary(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var rows []map[string]any
		if err := db.QueryViewRows("vw_agent_trust_summary", "*", "tenant_id", tenantID, &rows); err != nil {
			slog.Warn("HandleGetAgentTrustSummary: view error", "tenant_id", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "agent trust summary", err)
			return
		}
		respond.OK(w, map[string]any{
			"agents": orEmpty(rows),
			"count":  len(rows),
		})
	}
}

// HandleGetPolicyVerdictDistribution queries vw_policy_verdict_distribution.
// GET /api/v1/analytics/policy-verdicts
// Returns policy-level verdict distribution (allow/deny/escalate) with avg confidence.
// No tenant filter — policy names are global; agents are tenant-scoped at query time.
func HandleGetPolicyVerdictDistribution(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		var rows []map[string]any
		if err := db.QueryViewRows("vw_policy_verdict_distribution", "*", "", "", &rows); err != nil {
			slog.Warn("HandleGetPolicyVerdictDistribution: view error", "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "policy verdict distribution", err)
			return
		}
		respond.OK(w, map[string]any{
			"policies": orEmpty(rows),
		})
	}
}

// HandleGetTrustDecayTrend queries vw_trust_decay_trend.
// GET /api/v1/trust/decay-trend
// Returns per-agent trust score change events (before/after) with reason,
// scoped to the calling tenant. Used by the trust timeline chart.
func HandleGetTrustDecayTrend(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var rows []map[string]any
		if err := db.QueryViewRows("vw_trust_decay_trend", "*", "tenant_id", tenantID, &rows); err != nil {
			slog.Warn("HandleGetTrustDecayTrend: view error", "tenant_id", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "trust decay trend", err)
			return
		}
		respond.OK(w, map[string]any{
			"trend": orEmpty(rows),
		})
	}
}

