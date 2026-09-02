package reports

// bulk_escalation_actions.go — Bulk assign and acknowledge for escalation chains.
//
// POST /analytics/escalation-chains/bulk/assign      { ids: [...], assignee_id: "user-uuid" }
// POST /analytics/escalation-chains/bulk/acknowledge { ids: [...] }
//
// The frontend /governance/escalations page calls these when the reviewer
// clicks "Assign All" or "Acknowledge All" on selected escalation chains.
// Without these routes the UI bulk actions silently fail (404).

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/concurrent"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/serviceclient"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

// ── Shared types ──────────────────────────────────────────────────────────────

type bulkEscalationResult struct {
	ID      string `json:"id"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// ── HandleBulkEscalationAssign — POST /analytics/escalation-chains/bulk/assign ──
//
// Body: { ids: ["chain-uuid-1", ...], assignee_id: "user-uuid" }
// Sets assigned_to on each escalation chain config, with tenant isolation.

func HandleBulkEscalationAssign(db database.DB, coreClient *serviceclient.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var req struct {
			IDs        []string `json:"ids"`
			AssigneeID string   `json:"assignee_id"`
		}
		respond.LimitBody(r)
		if !validate.Bind(w, r, &req) {
			return
		}
		if len(req.IDs) == 0 {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "ids must be a non-empty array")
			return
		}
		if len(req.IDs) > 100 {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "maximum 100 ids per request")
			return
		}

		results := make([]bulkEscalationResult, 0, len(req.IDs))
		successCount := 0
		now := time.Now().UTC().Format(time.RFC3339)
		// AU-02 FIX: actor from JWT context, not from X-User-ID header (forgeable)
		actorID := auth.GetUserID(r.Context())

		for _, id := range req.IDs {
			if id == "" {
				results = append(results, bulkEscalationResult{ID: id, Success: false, Error: "empty id"})
				continue
			}
			if err := db.UpdateRowCompound(database.TblGovernanceDeliberations,
				"escalation_config_id", id,
				"tenant_id", tenantID,
				map[string]any{
					"assigned_to": req.AssigneeID,
					"updated_at":  now,
				}); err != nil {
				slog.Error("bulk escalation assign: update failed",
					"id", id, "tenant", tenantID, "error", err)
				results = append(results, bulkEscalationResult{ID: id, Success: false, Error: err.Error()})
				continue
			}
			// AU-01 FIX: write audit trail for every successful bulk assignment via ocx-core-svc API.
			if coreClient != nil {
				evtPayload := map[string]any{
					"tenant_id":   tenantID,
					"event_type":  "escalation_chain.assigned",
					"entity_id":   id,
					"entity_type": "escalation_config",
					"actor_id":    actorID,
					"metadata": map[string]any{
						"assignee_id": req.AssigneeID,
						"bulk":        true,
					},
				}
				concurrent.Go("bulk-escalate-assign-event", func() { _ = coreClient.PostEvent(context.Background(), evtPayload) })
			} else if _wErr := db.InsertRow(database.TblCoreEvents, map[string]any{
				"tenant_id":   tenantID,
				"event_type":  "escalation_chain.assigned",
				"entity_id":   id,
				"entity_type": "escalation_config",
				"actor_id":    actorID,
				"metadata": map[string]any{
					"assignee_id": req.AssigneeID,
					"bulk":        true,
				},
			}); _wErr != nil {
				slog.Error("SILENT_DROP_FIXED: InsertRow",
					"table", "tenant_id", "file", "aocs-intel/handlers/analytics/bulk_escalation_actions.go", "err", _wErr)
			}
			results = append(results, bulkEscalationResult{ID: id, Success: true})
			successCount++
		}

		slog.Info("bulk escalation assign", "tenant", tenantID,
			"total", len(req.IDs), "success", successCount, "actor", actorID)
		respond.OK(w, map[string]any{
			"action":        "assign",
			"assignee_id":   req.AssigneeID,
			"total":         len(req.IDs),
			"success_count": successCount,
			"results":       results,
		})
	}
}

// ── HandleBulkEscalationAcknowledge — POST /analytics/escalation-chains/bulk/acknowledge ──
//
// Body: { ids: [...] }
// Marks each escalation chain config as acknowledged (acknowledged_at = now).

func HandleBulkEscalationAcknowledge(db database.DB, coreClient *serviceclient.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var req struct {
			IDs []string `json:"ids"`
		}
		respond.LimitBody(r)
		if !validate.Bind(w, r, &req) {
			return
		}
		if len(req.IDs) == 0 {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "ids must be a non-empty array")
			return
		}
		if len(req.IDs) > 100 {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "maximum 100 ids per request")
			return
		}

		results := make([]bulkEscalationResult, 0, len(req.IDs))
		successCount := 0
		now := time.Now().UTC().Format(time.RFC3339)
		// AU-02 FIX: actor from JWT context, not from X-User-ID header (forgeable)
		actorID := auth.GetUserID(r.Context())

		for _, id := range req.IDs {
			if id == "" {
				results = append(results, bulkEscalationResult{ID: id, Success: false, Error: "empty id"})
				continue
			}
			if err := db.UpdateRowCompound(database.TblGovernanceDeliberations,
				"escalation_config_id", id,
				"tenant_id", tenantID,
				map[string]any{
					"acknowledged_at": now,
					"updated_at":      now,
				}); err != nil {
				slog.Error("bulk escalation acknowledge: update failed",
					"id", id, "tenant", tenantID, "error", err)
				results = append(results, bulkEscalationResult{ID: id, Success: false, Error: err.Error()})
				continue
			}
			// AU-01 FIX: write audit trail for every successful bulk acknowledgement via ocx-core-svc API.
			if coreClient != nil {
				evtPayload := map[string]any{
					"tenant_id":   tenantID,
					"event_type":  "escalation_chain.acknowledged",
					"entity_id":   id,
					"entity_type": "escalation_config",
					"actor_id":    actorID,
					"metadata":    map[string]any{"bulk": true},
				}
				concurrent.Go("bulk-escalate-ack-event", func() { _ = coreClient.PostEvent(context.Background(), evtPayload) })
			} else if _wErr := db.InsertRow(database.TblCoreEvents, map[string]any{
				"tenant_id":   tenantID,
				"event_type":  "escalation_chain.acknowledged",
				"entity_id":   id,
				"entity_type": "escalation_config",
				"actor_id":    actorID,
				"metadata":    map[string]any{"bulk": true},
			}); _wErr != nil {
				slog.Error("SILENT_DROP_FIXED: InsertRow",
					"table", "tenant_id", "file", "aocs-intel/handlers/analytics/bulk_escalation_actions.go", "err", _wErr)
			}
			results = append(results, bulkEscalationResult{ID: id, Success: true})
			successCount++
		}

		slog.Info("bulk escalation acknowledge", "tenant", tenantID,
			"total", len(req.IDs), "success", successCount, "actor", actorID)
		respond.OK(w, map[string]any{
			"action":        "acknowledge",
			"total":         len(req.IDs),
			"success_count": successCount,
			"results":       results,
		})
	}
}
