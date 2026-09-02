package security

import (
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/security"
	"github.com/ocx/shared/infra/serviceclient"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

// HandleListAttackEvents returns an overview of recent attack mitigation act.
// GET /api/v1/security/attacks?tenant_id=...
func HandleListAttackEvents(sybil *security.SybilDetector, nonce *security.NonceStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		respond.OK(w, map[string]any{
			"tenant_id": tenantID,
			"status":    "MONITORING",
		})
	}
}

// HandleCheckSybil checks if an agt shows Sybil attack patterns.
// GET /api/v1/security/sybil/check/{agentId}?tenant_id=...&ip=...
func HandleCheckSybil(sybil *security.SybilDetector, db database.DB, coreClients ...*serviceclient.Client) http.HandlerFunc {
	var coreClient *serviceclient.Client
	if len(coreClients) > 0 {
		coreClient = coreClients[0]
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		agentID := mux.Vars(r)["agentId"]
		if agentID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: agentId")
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		ipAddress := r.URL.Query().Get("ip")
		if ipAddress == "" {
			ipAddress = r.RemoteAddr
		}

		err := sybil.ValidateAgent(r.Context(), agentID, ipAddress)
		allowed := err == nil
		reason := ""
		if err != nil {
			reason = err.Error()
		}

		action := "VALIDATED"
		if !allowed {
			action = "BLOCKED"
		}
		severity := "INFO"
		if !allowed {
			severity = "WARN"
		}

		if coreClient != nil {
			// Preferred path: route audit event via ocx-core-svc API.
			evtPayload := map[string]any{
				"event_type":  database.PlatformEventSybilDetected,
				"tenant_id":   tenantID,
				"agent_id":    agentID,
				"allowed":     allowed,
				"ip_address":  ipAddress,
				"action":      action,
				"severity":    severity,
				"intent_id":   r.URL.Query().Get("intent_id"),
				"activity_id": r.URL.Query().Get("activity_id"),
				"execution_id": r.URL.Query().Get("execution_id"),
				"process_id":  r.URL.Query().Get("process_id"),
			}
			if postErr := coreClient.PostEvent(r.Context(), evtPayload); postErr != nil {
				slog.Error("Failed to persist sybil event via coreClient", "agent_id", agentID, "error", postErr)
			}
		} else if db != nil {
			// Fallback: direct DB (no coreClient wired).
			allowedBool := allowed
			evt := database.PlatformEvent{
				EventType: database.PlatformEventSybilDetected,
				TenantID:  tenantID,
				AgentID:   agentID,
				Allowed:   &allowedBool,
				IPAddress: ipAddress,
				Action:    action,
				Severity:  severity,
				IntentID:    r.URL.Query().Get("intent_id"),
				ActivityID:  r.URL.Query().Get("activity_id"),
				ExecutionID: r.URL.Query().Get("execution_id"),
				ProcessID:   r.URL.Query().Get("process_id"),
			}
			if dbErr := db.InsertRow(database.TblPlatformEvents, evt); dbErr != nil {
				slog.Error("Failed to persist sybil event", "agent_id", agentID, "error", dbErr)
				respond.InternalError(w, http.StatusInternalServerError, "failed to record sybil event", nil)
				return
			}
		}

		respond.OK(w, map[string]any{
			"agent_id":  agentID,
			"tenant_id": tenantID,
			"allowed":   allowed,
			"reason":    reason,
		})
	}
}

// HandleValidateNonce validates a nonce for replay protection.
// POST /api/v1/security/nonce/validate
func HandleValidateNonce(nonce *security.NonceStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		respond.LimitBody(r)
		var req NonceValidateRequest
		respond.LimitBody(r)
		if !validate.Bind(w, r, &req) {
			return
		}
		// JWT only — body tenant_id ignored
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		req.TenantID = tenantID
		if req.Nonce == "" || req.AgentID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "nonce and agent_id are required")
			return
		}

		err := nonce.ValidateNonce(req.Nonce, req.AgentID)
		valid := err == nil
		reason := ""
		if err != nil {
			reason = err.Error()
		}

		respond.OK(w, map[string]any{
			"nonce":     req.Nonce,
			"tenant_id": req.TenantID,
			"valid":     valid,
			"reason":    reason,
		})
	}
}
