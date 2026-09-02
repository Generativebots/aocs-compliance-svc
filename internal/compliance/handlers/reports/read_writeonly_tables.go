// Package analytics — read handlers for previously write-only analytics tables.
//
// These handlers expose data written by domain/gate layers but never surfaced
// via API routes. Each is tenant-scoped, paginated, and injection-safe.
package reports

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
)

func parseLimit(r *http.Request, def, max int) database.PageParams {
	limit := def
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= max {
		limit = n
	}
	offset := 0
	if n, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && n >= 0 {
		offset = n
	}
	return database.PageParams{Limit: limit, Offset: offset}
}

// HandleListAdaptiveThresholds — GET /api/v1/analytics/thresholds
//
// Returns per-agent adaptive threshold records written by the Tri-Factor Gate
// (gate_stages.go) whenever a policy violation triggers threshold tightening.
// These drive the Self-Heal advisor's proposals (RLHC patent claim).
func HandleListAdaptiveThresholds(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		agentID := r.URL.Query().Get("agent_id")
		metricName := r.URL.Query().Get("metric_name")
		pp := parseLimit(r, 50, 200)

		// PK is id (schema.generated.ts confirms: id, not adaptive_threshold_id).
		cols := "id,tenant_id,agent_id,metric_name,current_threshold,baseline_threshold," +
			"adjustment_factor,adaptation_factor,max_financial_action_usd," +
			"allowed_tool_categories,restricted_tool_categories,reason," +
			"last_adapted_at,last_adjusted_at,is_active,created_at,updated_at"

		var rows []map[string]any
		var err error
		switch {
		case agentID != "":
			err = db.QueryRowsCompoundLimited(database.TblAdaptiveThresholds, cols,
				"agent_id", agentID, "tenant_id", tenantID, pp, &rows)
		case metricName != "":
			err = db.QueryRowsCompoundLimited(database.TblAdaptiveThresholds, cols,
				"metric_name", metricName, "tenant_id", tenantID, pp, &rows)
		default:
			err = db.QueryRowsCursor(database.TblAdaptiveThresholds, cols, "tenant_id", tenantID, database.ParseCursorPage(r), &rows)
		}
		if err != nil {
			slog.Error("HandleListAdaptiveThresholds: db query failed", "tenant_id", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "failed to fetch thresholds", nil)
			return
		}
		respond.JSON(w, http.StatusOK, map[string]any{"thresholds": rows, "count": len(rows)})
	}
}

// HandleGetAdaptiveThreshold — GET /api/v1/analytics/thresholds/{id}
func HandleGetAdaptiveThreshold(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		id := mux.Vars(r)["id"]
		if id == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "id is required")
			return
		}
		var rows []map[string]any
		// core_adaptive_thresholds PK is id (not threshold_id or adaptive_threshold_id).
		if err := db.QueryRowsCompound(database.TblAdaptiveThresholds,
			"id,tenant_id,agent_id,metric_name,current_threshold,baseline_threshold,"+
				"adjustment_factor,adaptation_factor,max_financial_action_usd,reason,"+
				"last_adapted_at,last_adjusted_at,is_active,created_at,updated_at",
			"id", id, "tenant_id", tenantID, &rows); err != nil || len(rows) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "threshold not found")
			return
		}
		respond.JSON(w, http.StatusOK, rows[0])
	}
}

// HandleListAgentTrustHistory — GET /api/v1/agents/{agent_id}/trust-history
//
// Returns time-series trust score history for an agent. Written by the decay
// flusher (worker_decay_flusher.go) and federation trust ledger. Critical for
// CIP-3 federation trust analytics.
func HandleListAgentTrustHistory(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		agentID := mux.Vars(r)["agent_id"]
		if agentID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "agent_id is required")
			return
		}
		pp := parseLimit(r, 100, 500)
		var rows []map[string]any
		if err := db.QueryRowsCompoundLimited(
			database.TblTrustScoreTimeline,
			"trust_score_timeline_id,tenant_id,agent_id,score,change_type,change_delta,source,occurred_at",
			"agent_id", agentID, "tenant_id", tenantID, pp, &rows); err != nil {
			slog.Error("HandleListAgentTrustHistory: db query failed — returning empty history",
				"agent_id", agentID, "tenant_id", tenantID, "error", err)
			// Graceful degradation: don't 500 — trust history is read-only analytics.
			// Return empty rather than crashing the client dashboard.
			rows = nil
		}
		if rows == nil {
			rows = []map[string]any{}
		}
		respond.JSON(w, http.StatusOK, map[string]any{
			"agent_id": agentID, "history": rows, "count": len(rows),
		})
	}
}

// HandleListGuardianVerdicts — GET /api/v1/guardian/verdicts
//
// Returns Guardian AI verdicts (Gemini evaluation written by gate_stage_events.go).
// These represent AI-layer decisions on agent actions — critical for CIP patent
// claim 9 (AI governance layer auditability).
func HandleListGuardianVerdicts(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		agentID := r.URL.Query().Get("agent_id")
		// SCOPE FIX: department_id=slug from ScopeBar → filter verdicts to that dept's agents
		deptID := r.URL.Query().Get("department_id")
		// verdict_type does not exist as a column — it's stored in metadata JSONB.
		// We fetch all records and let the client filter by metadata.verdict_type if needed.
		pp := parseLimit(r, 50, 200)

		// Actual aocs_guardian_verdicts columns: verdict_id, tenant_id, agent_id, confidence, metadata, created_at
		// guardian_verdict_id, verdict_type, decision, reason, evidence, appealed — do NOT exist.
		cols := "verdict_id,tenant_id,agent_id,confidence,metadata,created_at"
		var rows []map[string]any
		var err error
		if agentID != "" {
			err = db.QueryRowsCompoundLimited(database.TblGuardianVerdicts, cols,
				"agent_id", agentID, "tenant_id", tenantID, pp, &rows)
		} else {
			err = db.QueryRowsCursor(database.TblGuardianVerdicts, cols, "tenant_id", tenantID, database.ParseCursorPage(r), &rows)
		}
		if err != nil {
			slog.Error("HandleListGuardianVerdicts: db query failed", "tenant_id", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "failed to fetch guardian verdicts", nil)
			return
		}
		if rows == nil {
			rows = []map[string]any{}
		}
		// Post-filter by department: resolve agent_id → department_id (slug) via agents table
		if deptID != "" && agentID == "" {
			var agentRows []database.Agt
			agentDept := make(map[string]string)
			// M40: department_id moved to core_agent_config — use vw_agent_full, not TblCoreAgents.
			if dbErr := db.QueryRowsCtx(r.Context(), database.TblAgentFullView, "agent_id,department_id",
				"tenant_id", tenantID, &agentRows); dbErr == nil {
				for _, a := range agentRows {
					agentDept[a.AgentID] = a.DepartmentID // slug e.g. "claims"
				}
			}
			filtered := rows[:0]
			for _, row := range rows {
				if aid, ok := row["agent_id"].(string); ok && agentDept[aid] == deptID {
					filtered = append(filtered, row)
				}
			}
			rows = filtered
		}
		respond.JSON(w, http.StatusOK, map[string]any{"verdicts": rows, "count": len(rows)})
	}
}

// HandleGetGuardianVerdict — GET /api/v1/guardian/verdicts/{id}
func HandleGetGuardianVerdict(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		id := mux.Vars(r)["id"]
		if id == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "id is required")
			return
		}
		var rows []map[string]any
		// aocs_guardian_verdicts columns: verdict_id, tenant_id, agent_id, confidence, metadata, created_at.
		// No guardian_verdict_id, decision, verdict_type, reason, evidence, or appealed columns.
		if err := db.QueryRowsCompound(database.TblGuardianVerdicts,
			"verdict_id,tenant_id,agent_id,confidence,metadata,created_at",
			"verdict_id", id, "tenant_id", tenantID, &rows); err != nil || len(rows) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "guardian verdict not found")
			return
		}
		respond.JSON(w, http.StatusOK, rows[0])
	}
}
