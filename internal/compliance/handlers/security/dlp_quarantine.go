package security

// dlp_quarantine.go — POST /dlp/quarantine
//
// Records a quarantine enforcement action against an entity (agent, document,
// or data asset) suspected of policy violation.
//
// The quarantine is persisted in core_enforcement_actions with
// action_type = 'dlp_quarantine' and creates a corresponding DLP finding
// for audit trail purposes.
//
// POST /api/v1/dlp/quarantine
// Body: { "entity_id": "...", "entity_type": "agent|document|data", "reason": "..." }
// Response: { "quarantine_id": "...", "entity_id": "...", "status": "QUARANTINED" }

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

type quarantineRequest struct {
	EntityID   string `json:"entity_id"`
	EntityType string `json:"entity_type"` // agent | document | data | tool
	Reason	string	`json:"reason" validate:"required"`
	Severity   string `json:"severity"` // LOW | MEDIUM | HIGH | CRITICAL
}

type quarantineResponse struct {
	QuarantineID string    `json:"quarantine_id"`
	EntityID     string    `json:"entity_id"`
	EntityType   string    `json:"entity_type"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
}

// HandleDLPQuarantine — POST /dlp/quarantine
//
// Quarantines an entity by recording an enforcement action.
// Does NOT terminate running agents — that requires /esc/kill-switch.
// Use this for data/document quarantine and policy-hold states.
func HandleDLPQuarantine(store *DLPStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if store == nil || respond.RequireDB(w, store.db) {
			return
		}
		respond.LimitBody(r)

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var req quarantineRequest
		if !validate.Bind(w, r, &req) {
			return
		}
		if req.EntityID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "entity_id is required")
			return
		}
		if req.EntityType == "" {
			req.EntityType = "agent"
		}
		if req.Severity == "" {
			req.Severity = "HIGH"
		}
		if req.Reason == "" {
			req.Reason = "DLP policy violation — manual quarantine"
		}

		quarantineID := generatePlatformID()
		now := time.Now().UTC()

		// Persist as an enforcement action for audit trail.
		meta, _ := json.Marshal(map[string]any{
			"entity_type":    req.EntityType,
			"reason":         req.Reason,
			"severity":       req.Severity,
			"quarantine_id":  quarantineID,
			"quarantined_at": now,
		})

		ea := database.EnforcementAction{
			TenantID:    tenantID,
			ActionType:  "dlp_quarantine",
			Scope:       database.EnforcementScopeAgent,
			SubjectID:   req.EntityID,
			SubjectType: req.EntityType,
			Reason:      req.Reason,
			Severity:    req.Severity,
			Metadata:    json.RawMessage(meta),
		}
		if err := store.db.InsertRow(database.TblCoreEnforcementActions, ea); err != nil {
			slog.Error("dlp/quarantine: enforcement action insert failed",
				"entity_id", req.EntityID, "err", err)
			respond.InternalError(w, http.StatusInternalServerError, "failed to record quarantine", nil)
			return
		}

		slog.Info("dlp/quarantine: entity quarantined",
			"tenant_id", tenantID, "entity_id", req.EntityID,
			"entity_type", req.EntityType, "quarantine_id", quarantineID)

		respond.Created(w, quarantineResponse{
			QuarantineID: quarantineID,
			EntityID:     req.EntityID,
			EntityType:   req.EntityType,
			Status:       "QUARANTINED",
			CreatedAt:    now,
		})
	}
}
