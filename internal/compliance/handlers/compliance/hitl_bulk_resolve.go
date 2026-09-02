// Package compliance — Bulk HITL resolution handler.
//
// POST /api/v1/hitl/ops/resolve
//
// Bulk-resolves HITL decisions. Accepts an array of decision IDs + verdict.
// Used by the HITL Operations panel to approve/reject multiple cases at once.
// Updates aocs_hitl_decisions status and records the reviewer's verdict.
package compliance

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/serviceclient"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

// bulkHITLResolveRequest is the JSON body for POST /hitl/ops/resolve.
type bulkHITLResolveRequest struct {
	DecisionIDs []string `json:"decision_ids"` // required, max 50
	Verdict     string   `json:"verdict"`      // APPROVED | REJECTED | ESCALATED
	Reason      string   `json:"reason" validate:"required"` // human-readable rationale
}

// HandleResolveBulkHITL handles POST /api/v1/hitl/ops/resolve
// Accepts up to 50 decision IDs and a verdict, updates each row in aocs_hitl_decisions.
// Returns per-decision success/failure breakdown in the response.
func HandleResolveBulkHITL(db database.DB, coreClients ...*serviceclient.Client) http.HandlerFunc {
	var coreClient *serviceclient.Client
	if len(coreClients) > 0 {
		coreClient = coreClients[0]
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		respond.LimitBody(r)

		var req bulkHITLResolveRequest
		if !validate.Bind(w, r, &req) {
			return
		}
		if len(req.DecisionIDs) == 0 {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "decision_ids required")
			return
		}
		if len(req.DecisionIDs) > 50 {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "max 50 decision_ids per request")
			return
		}
		if req.Verdict != "APPROVED" && req.Verdict != "REJECTED" && req.Verdict != "ESCALATED" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest,
				"verdict must be APPROVED, REJECTED, or ESCALATED")
			return
		}

		// Extract reviewer identity from the JWT — this is what gets written to the
		// audit log so the "by —" field is populated with a real actor.
		reviewerID := auth.GetUserID(r.Context())
		if reviewerID == "" {
			reviewerID = "system:bulk-resolve"
		}
		now := time.Now().UTC().Format(time.RFC3339)

		results := make([]map[string]any, 0, len(req.DecisionIDs))
		for _, decisionID := range req.DecisionIDs {
			result := map[string]any{"decision_id": decisionID, "verdict": req.Verdict}
			if coreClient != nil {
				// SVC-BOUNDARY: update aocs_hitl_decisions via ocx-core-svc API
				if _rErr := coreClient.PatchHITLCase(r.Context(), tenantID, decisionID, map[string]any{
					"status":            req.Verdict,
					"reviewer_id":       reviewerID,
					"resolution_reason": req.Reason,
					"resolved_at":       now,
					"updated_at":        now,
				}); _rErr != nil {
					slog.Error("HandleResolveBulkHITL: coreClient update failed", "decision_id", decisionID, "error", _rErr)
					result["error"] = "update failed"
					result["ok"] = false
				} else {
					result["ok"] = true
					// Audit event via ocx-core-svc API (best-effort)
					if _sErr := coreClient.PostEvent(r.Context(), map[string]any{
						"event_id":   uuid.NewString(),
						"tenant_id":  tenantID,
						"event_type": "HITL_DECISION_" + req.Verdict,
						"actor_id":   reviewerID,
						"user_id":    reviewerID,
						"target_id":  decisionID,
						"action":     req.Verdict,
						"severity":   "INFO",
						"new_value":  `{"reason":"` + req.Reason + `"}`,
					}); _sErr != nil {
						slog.Error("PostEvent failed (best-effort)", "decision_id", decisionID, "error", _sErr)
					}
				}
			} else {
				// Fallback: direct DB when coreClient is not wired
				err := db.UpdateRowCompound(
					database.TblHITLDecisions,
					"decision_id", decisionID,
					"tenant_id", tenantID,
					map[string]any{
						"status":            req.Verdict,
						"reviewer_id":       reviewerID,
						"resolution_reason": req.Reason,
						"resolved_at":       now,
						"updated_at":        now,
					},
				)
				if err != nil {
					slog.Error("HandleResolveBulkHITL: update failed", "decision_id", decisionID, "error", err)
					result["error"] = "update failed"
					result["ok"] = false
				} else {
					result["ok"] = true
					if _sErr := db.InsertPlatformEvent(database.PlatformEvent{
						EventID:   uuid.NewString(),
						TenantID:  tenantID,
						EventType: "HITL_DECISION_" + req.Verdict,
						ActorID:   reviewerID,
						UserID:    reviewerID,
						TargetID:  decisionID,
						Action:    req.Verdict,
						Severity:  "INFO",
						NewValue:  []byte(`{"reason":"` + req.Reason + `"}`),
					}); _sErr != nil {
						slog.Error("InsertPlatformEvent failed", "decision_id", decisionID, "error", _sErr)
					}
				}
			}
			results = append(results, result)
		}

		succeeded := 0
		for _, r := range results {
			if r["ok"] == true {
				succeeded++
			}
		}

		respond.JSON(w, http.StatusOK, map[string]any{
			"resolved":    succeeded,
			"failed":      len(results) - succeeded,
			"total":       len(results),
			"resolved_at": now,
			"results":     results,
		})
	}
}
