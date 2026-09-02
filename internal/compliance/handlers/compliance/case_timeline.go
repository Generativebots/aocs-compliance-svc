// case_timeline.go — Case timeseries / audit trail handler
//
// GET  /api/v1/hitl/cases/{case_id}/timeline
// GET  /api/v1/hitl/decisions/{decision_id}/timeline
//
// Returns the full ordered sequence of events for a case:
// CREATED → ASSIGNED → STATUS_CHANGED → ESCALATED → RESOLVED/CLOSED
// Sourced from aocs_case_events (migration 055).
//
// Events are immutable — inserted by DB triggers on status changes.
// Useful for compliance audit UIs showing "what happened and when."
package compliance

import (
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
)

const tblCaseEvents = "aocs_case_events"

const colsCaseEvents = `event_id, case_id, case_type, tenant_id,
	event_type, from_status, to_status,
	actor_id, actor_type, notes, metadata, occurred_at`

// HandleGetCaseTimeline returns the full timeseries of events for a compliance case.
// GET /api/v1/hitl/cases/{case_id}/timeline
func HandleGetCaseTimeline(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		caseID := mux.Vars(r)["case_id"]
		if caseID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "case_id required")
			return
		}

		var events []map[string]any
		if err := db.QueryRowsCompound(
			tblCaseEvents,
			colsCaseEvents,
			"case_id", caseID,
			"tenant_id", tenantID,
			&events,
		); err != nil {
			slog.Error("HandleGetCaseTimeline: DB query failed",
				"case_id", caseID, "tenant_id", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "failed to fetch timeline", nil)
			return
		}
		if events == nil {
			events = []map[string]any{}
		}
		respond.OK(w, map[string]any{
			"case_id": caseID,
			"count":   len(events),
			"events":  events,
		})
	}
}

// HandleGetDecisionTimeline returns the full timeseries of events for a HITL decision.
// GET /api/v1/hitl/decisions/{decision_id}/timeline
func HandleGetDecisionTimeline(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		decisionID := mux.Vars(r)["decision_id"]
		if decisionID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "decision_id required")
			return
		}

		var events []map[string]any
		if err := db.QueryRowsCompound(
			tblCaseEvents,
			colsCaseEvents,
			"case_id", decisionID,
			"tenant_id", tenantID,
			&events,
		); err != nil {
			slog.Error("HandleGetDecisionTimeline: DB query failed",
				"decision_id", decisionID, "tenant_id", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "failed to fetch timeline", nil)
			return
		}
		if events == nil {
			events = []map[string]any{}
		}
		respond.OK(w, map[string]any{
			"decision_id": decisionID,
			"count":       len(events),
			"events":      events,
		})
	}
}
