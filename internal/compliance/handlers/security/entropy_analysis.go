package security

import (
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"
	contracts "github.com/ocx/shared/contracts"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/pagination"
	"github.com/ocx/shared/infra/serviceclient"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

// HandleGetEntropyStatus returns entropy monitor configuration and overall status.
// GET /api/v1/entropy/status
func HandleGetEntropyStatus(entropy contracts.EntropyMonitor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		respond.OK(w, map[string]any{
			"status": "ACTIVE",
			"mode":   "shannon_entropy",
		})
	}
}

// HandleScanEntropy performs an entropy analysis on a submitted payload.
// POST /api/v1/entropy/scan/{agentId}
func HandleScanEntropy(entropy contracts.EntropyMonitor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agentID := mux.Vars(r)["agentId"]
		if agentID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: agentId")
			return
		}

		var req struct {
			Payload  string `json:"payload"`
			TenantID string `json:"tenant_id"`
		}
		respond.LimitBody(r)
		if !validate.Bind(w, r, &req) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		req.TenantID = tenantID

		result := entropy.Analyze([]byte(req.Payload), req.TenantID)

		respond.OK(w, map[string]any{
			"agent_id":      agentID,
			"entropy_score": result.EntropyScore,
			"verdict":       result.Verdict,
			"confidence":    result.Confidence,
		})
	}
}

// HandleGetEntropyEvents returns recent entropy detection events.
// GET /api/v1/entropy/events
func HandleGetEntropyEvents(db database.DB, coreClients ...*serviceclient.Client) http.HandlerFunc {
	var coreClient *serviceclient.Client
	if len(coreClients) > 0 {
		coreClient = coreClients[0]
	}
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := tenantFromRequest(w, r)
		if !ok {
			return
		}

		if coreClient != nil {
			evts, err := coreClient.ListPlatformEventsByType(r.Context(), tenantID, database.PlatformEventEntropyBreach, 200)
			if err != nil {
				slog.Error("GetEntropyEvents coreClient failed", "tenant", tenantID, "error", err)
				respond.InternalError(w, http.StatusInternalServerError, "failed to list entropy events", err)
				return
			}
			pagination.RespondPageTyped(w, r, evts, "event_id")
			return
		}
		// Fallback: direct DB (local dev / no coreClient)
		if respond.RequireDB(w, db) {
			return
		}
		var rows []database.PlatformEvent
		if err := db.QueryRowsWithin90DaysCompound(database.TblCoreEvents, database.ColsPlatformEvent,
			tenantID, "event_type", database.PlatformEventEntropyBreach, &rows); err != nil {
			slog.Error("GetEntropyEvents failed", "tenant", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "failed to list entropy events", err)
			return
		}
		if rows == nil {
			rows = []database.PlatformEvent{}
		}
		// Cursor pagination — was returning all entropy breach events unbounded.
		pagination.RespondPageTyped(w, r, rows, "id")
	}
}

// HandleGetEntropyEvent returns a single entropy event.
// GET /api/v1/entropy/events/{id}
func HandleGetEntropyEvent(db database.DB, coreClients ...*serviceclient.Client) http.HandlerFunc {
	var coreClient *serviceclient.Client
	if len(coreClients) > 0 {
		coreClient = coreClients[0]
	}
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := tenantFromRequest(w, r)
		if !ok {
			return
		}
		eventID := mux.Vars(r)["id"]
		if eventID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}

		if coreClient != nil {
			evt, err := coreClient.GetPlatformEventByEntityAndType(r.Context(), tenantID, eventID, database.PlatformEventEntropyBreach)
			if err != nil || evt == nil {
				respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "entropy event not found")
				return
			}
			respond.OK(w, evt)
			return
		}
		// Fallback: direct DB
		if respond.RequireDB(w, db) {
			return
		}
		var rows []database.PlatformEvent
		if err := db.QueryRowsCompound(database.TblCoreEvents, database.ColsPlatformEvent,
			"log_id", eventID, "tenant_id", tenantID, &rows); err != nil || len(rows) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "entropy event not found")
			return
		}
		respond.OK(w, rows[0])
	}
}

// HandleCreateEntropyEvent creates a new entropy event.
// POST /api/v1/entropy/events
func HandleCreateEntropyEvent(db database.DB, coreClients ...*serviceclient.Client) http.HandlerFunc {
	var coreClient *serviceclient.Client
	if len(coreClients) > 0 {
		coreClient = coreClients[0]
	}
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := tenantFromRequest(w, r)
		if !ok {
			return
		}
		respond.LimitBody(r)

		var req CreateEntropyEventRequest
		if !validate.Bind(w, r, &req) {
			return
		}

		evtPayload := map[string]any{
			"event_type":    database.PlatformEventEntropyBreach,
			"tenant_id":     tenantID,
			"agent_id":      req.AgentID,
			"intent_id":     req.IntentID,
			"activity_id":   req.ActivityID,
			"execution_id":  req.ExecutionID,
			"process_id":    req.ProcessID,
			"entropy_score": req.VarianceScore,
			"analysis_type": "SIGNAL",
			"action":        "entropy_recorded",
			"severity":      "WARN",
		}

		if coreClient != nil {
			if err := coreClient.PostEvent(r.Context(), evtPayload); err != nil {
				slog.Error("CreateEntropyEvent coreClient failed", "tenant", tenantID, "error", err)
				respond.InternalError(w, http.StatusInternalServerError, "failed to create entropy event", err)
				return
			}
			respond.JSON(w, http.StatusCreated, map[string]string{"status": "created"})
			return
		}
		// Fallback: direct DB
		if respond.RequireDB(w, db) {
			return
		}
		evt := database.PlatformEvent{
			EventType:    database.PlatformEventEntropyBreach,
			TenantID:     tenantID,
			AgentID:      req.AgentID,
			IntentID:     req.IntentID,
			ActivityID:   req.ActivityID,
			ExecutionID:  req.ExecutionID,
			ProcessID:    req.ProcessID,
			EntropyScore: req.VarianceScore,
			AnalysisType: "SIGNAL",
			Action:       "entropy_recorded",
			Severity:     "WARN",
		}
		if err := db.InsertRow(database.TblCoreEvents, evt); err != nil {
			slog.Error("CreateEntropyEvent failed", "tenant", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "failed to create entropy event", err)
			return
		}
		respond.JSON(w, http.StatusCreated, map[string]string{"status": "created"})
	}
}

// HandleUpdateEntropyEvent updates an entropy event's score.
// PUT /api/v1/entropy/events/{id}
func HandleUpdateEntropyEvent(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := tenantFromRequest(w, r)
		if !ok {
			return
		}
		eventID := mux.Vars(r)["id"]
		if eventID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}
		respond.LimitBody(r)

		var req struct {
			VarianceScore float64 `json:"varianceScore"`
		}
		respond.LimitBody(r)
		if !validate.Bind(w, r, &req) {
			return
		}

		if err := db.UpdatePlatformEventEntropyScore(eventID, tenantID, req.VarianceScore); err != nil {
			slog.Error("UpdateEntropyEvent failed", "id", eventID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "failed to update entropy event", err)
			return
		}
		respond.OK(w, map[string]string{"status": "updated"})
	}
}

// HandleDeleteEntropyEvent deletes an entropy event.
// DELETE /api/v1/entropy/events/{id}
func HandleDeleteEntropyEvent(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := tenantFromRequest(w, r)
		if !ok {
			return
		}
		eventID := mux.Vars(r)["id"]
		if eventID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}

		if err := db.DeletePlatformEvent(eventID, tenantID); err != nil {
			slog.Error("DeleteEntropyEvent failed", "id", eventID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "failed to delete entropy event", err)
			return
		}
		respond.OK(w, map[string]string{"status": "deleted"})
	}
}
