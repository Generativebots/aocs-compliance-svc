// Package analytics — observability handlers for agent telemetry, config, and copilot logs.
//
// P3 handlers: these three tables existed in Go models and Supabase but had no
// HTTP API exposure. Added 2026-08-07 as part of the database sync audit.
//
// Routes (register in routes_intel.go):
//
//	GET /api/v1/agents/{agent_id}/telemetry    → HandleListAgentTelemetry
//	GET /api/v1/agents/{agent_id}/config       → HandleGetAgentConfig
//	GET /api/v1/copilot/interaction-log        → HandleListCopilotInteractionLog
package reports

import (
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
)

// HandleListAgentTelemetry — GET /api/v1/agents/{agent_id}/telemetry
//
// Returns per-agent telemetry records (latency, throughput, error rates) written
// by gate/hub monitoring goroutines. Paginated and tenant-scoped.
// Supports ?limit=N&offset=N&agent_id=<id> query params.
func HandleListAgentTelemetry(db database.DB) http.HandlerFunc {
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
			agentID = r.URL.Query().Get("agent_id")
		}
		pp := parseLimit(r, 100, 500)

		cols := "*"
		var rows []map[string]any
		var err error

		if agentID != "" {
			err = db.QueryRowsCompound(database.TblCoreAgentTelemetry, cols,
				"tenant_id", tenantID, "agent_id", agentID, &rows)
		} else {
			err = db.QueryRowsLimited(database.TblCoreAgentTelemetry, cols,
				"tenant_id", tenantID, pp, &rows)
		}
		if err != nil {
			slog.Error("HandleListAgentTelemetry: query failed",
				"tenant_id", tenantID, "agent_id", agentID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "telemetry query failed", err)
			return
		}
		if rows == nil {
			rows = []map[string]any{}
		}
		respond.OK(w, map[string]any{
			"telemetry": rows,
			"agent_id":  agentID,
			"count":     len(rows),
		})
	}
}

// HandleGetAgentConfig — GET /api/v1/agents/{agent_id}/config
//
// Returns runtime configuration entries for a specific agent within the tenant.
// Config is written by the agent provisioning flow (aocs-hub) and surfaced here.
func HandleGetAgentConfig(db database.DB) http.HandlerFunc {
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
			agentID = r.URL.Query().Get("agent_id")
		}
		if agentID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "agent_id is required")
			return
		}

		var rows []map[string]any
		if err := db.QueryRowsCompound(database.TblCoreAgentConfig, database.ColsAgentConfig,
			"tenant_id", tenantID, "agent_id", agentID, &rows); err != nil {
			slog.Error("HandleGetAgentConfig: query failed",
				"tenant_id", tenantID, "agent_id", agentID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "agent config query failed", err)
			return
		}
		if rows == nil {
			rows = []map[string]any{}
		}
		respond.OK(w, map[string]any{
			"config":   rows,
			"agent_id": agentID,
		})
	}
}

// HandleListCopilotInteractionLog — GET /api/v1/copilot/interaction-log
//
// Returns the copilot interaction log for the tenant — per-message metadata
// including intent classification, latency, token usage, and feedback scores.
// This is the RLHF training data source. Supports ?session_id=<id>&limit=N.
func HandleListCopilotInteractionLog(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		sessionID := r.URL.Query().Get("session_id")
		pp := parseLimit(r, 50, 200)

		var rows []map[string]any
		var err error

		if sessionID != "" {
			err = db.QueryRowsCompound(database.TblCopilotInteractionLog, database.ColsCopilotInteractionLog,
				"tenant_id", tenantID, "session_id", sessionID, &rows)
		} else {
			err = db.QueryRowsLimited(database.TblCopilotInteractionLog, database.ColsCopilotInteractionLog,
				"tenant_id", tenantID, pp, &rows)
		}
		if err != nil {
			slog.Error("HandleListCopilotInteractionLog: query failed",
				"tenant_id", tenantID, "session_id", sessionID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "interaction log query failed", err)
			return
		}
		if rows == nil {
			rows = []map[string]any{}
		}
		respond.OK(w, map[string]any{
			"interactions": rows,
			"session_id":   sessionID,
			"count":        len(rows),
		})
	}
}
