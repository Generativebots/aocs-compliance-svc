// retrain_events.go — NULL retrain completed_at FIX
//
// Provides two endpoints for the ML training lifecycle:
//
//   GET  /analytics/retrain-events
//     Lists all platform events with trigger_source=HUMAN_ARBITRATION (RLHC retrain queue).
//     Returns events with pending_count and training status.
//
//   PATCH /analytics/retrain-events/{id}/complete
//     Called by the Python Vertex AI worker when a training job finishes.
//     Writes completed_at + model_version to the core_events row.
//     This fixes the always-NULL completed_at field on retrain records.
//
// Previously: completed_at was always NULL because no endpoint existed for
// the Python ML worker to signal completion. Training jobs completed silently
// with no record update.
package reports

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/serviceclient"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

// HandleListRetrainEvents lists RLHC retrain events from core_events.
// GET /analytics/retrain-events
func HandleListRetrainEvents(db database.DB, coreClients ...*serviceclient.Client) http.HandlerFunc {
	var coreClient *serviceclient.Client
	if len(coreClients) > 0 {
		coreClient = coreClients[0]
	}
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		type RetrainEvent struct {
			ID            string  `json:"id"`
			TenantID      string  `json:"tenant_id"`
			CaseID        string  `json:"case_id"`
			TriggerSource string  `json:"trigger_source"`
			Verdict       string  `json:"verdict"`
			ReasonHash    string  `json:"reason_hash"`
			ModelVersion  string  `json:"model_version"`
			Status        string  `json:"status"`
			CreatedAt     string  `json:"created_at"`
			CompletedAt   *string `json:"completed_at"`
		}

		pending := 0

		if coreClient != nil {
			// Preferred: fetch via ocx-core-svc API, filtering by trigger_source.
			evts, err := coreClient.ListPlatformEventsByType(r.Context(), tenantID, "HUMAN_ARBITRATION", 500)
			if err != nil {
				slog.Error("HandleListRetrainEvents coreClient failed", "tenant_id", tenantID, "error", err)
				evts = nil
			}
			// Map PlatformEvent → RetrainEvent shape.
			out := make([]RetrainEvent, 0, len(evts))
			for _, e := range evts {
				item := RetrainEvent{
					TenantID:      e.TenantID,
					TriggerSource: "HUMAN_ARBITRATION",
					CreatedAt:     e.CreatedAt,
				}
				if item.Status == "PENDING_RETRAIN" {
					pending++
				}
				out = append(out, item)
			}
			respond.JSON(w, http.StatusOK, map[string]any{
				"events":        out,
				"total":         len(out),
				"pending_count": pending,
			})
			return
		}

		// Fallback: direct DB.
		if respond.RequireDB(w, db) {
			return
		}
		// CQ-05 FIX: Previously loaded ALL platform events for the tenant then filtered
		// in Go — OOM at scale (core_events is written for every gate call).
		// Now uses QueryRowsCompound to push trigger_source filter to the DB.
		var events []RetrainEvent
		cols := "id,tenant_id,case_id,trigger_source,verdict,reason_hash,model_version,status,created_at,completed_at"
		if err := db.QueryRowsCompound(database.TblPlatformEvents, cols,
			"tenant_id", tenantID,
			"trigger_source", "HUMAN_ARBITRATION",
			&events); err != nil {
			slog.Error("HandleListRetrainEvents: query failed", "tenant_id", tenantID, "error", err)
			events = []RetrainEvent{}
		}

		for _, e := range events {
			if e.Status == "PENDING_RETRAIN" {
				pending++
			}
		}

		respond.JSON(w, http.StatusOK, map[string]any{
			"events":        events,
			"total":         len(events),
			"pending_count": pending,
		})
	}
}

// HandleCompleteRetrainEvent marks a retrain event as completed.
// PATCH /analytics/retrain-events/{id}/complete
//
// Called by the Python Vertex AI training worker on job completion.
// Body: { "model_version": "v1.3.0", "metrics": { ... } }
//
// This is the missing webhook — without it, completed_at was always NULL.
func HandleCompleteRetrainEvent(db database.DB, coreClients ...*serviceclient.Client) http.HandlerFunc {
	var coreClient *serviceclient.Client
	if len(coreClients) > 0 {
		coreClient = coreClients[0]
	}
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		eventID := mux.Vars(r)["id"]
		if eventID == "" {
			http.Error(w, "id is required", http.StatusBadRequest)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // B6 FIX: 1MB limit
		var req struct {
			ModelVersion string                 `json:"model_version"`
			Metrics      map[string]interface{} `json:"metrics"`
		}
		if !validate.BindOptional(w, r, &req) {
			return
		}

		now := time.Now().UTC().Format(time.RFC3339)
		modelVersion := req.ModelVersion
		if modelVersion == "" {
			modelVersion = "unknown"
		}

		metricsJSON := "{}"
		if req.Metrics != nil {
			if b, jsonErr := json.Marshal(req.Metrics); jsonErr == nil {
				metricsJSON = string(b)
			}
		}

		updates := map[string]any{
			"status":        "RETRAIN_COMPLETE",
			"completed_at":  now,
			"model_version": modelVersion,
			"metadata":      metricsJSON,
		}

		if coreClient != nil {
			// Preferred path: update via ocx-core-svc API.
			if err := coreClient.UpdatePlatformEvent(r.Context(), eventID, updates); err != nil {
				slog.Error("HandleCompleteRetrainEvent: coreClient update failed",
					"event_id", eventID, "tenant_id", tenantID, "error", err)
				respond.InternalError(w, http.StatusInternalServerError, "update_retrain_event_failed", err)
				return
			}
		} else {
			// Fallback: direct DB.
			if respond.RequireDB(w, db) {
				return
			}
			// tenant could update another tenant's retrain event by guessing the UUID.
			// Fixed: use UpdateRowCompound which adds AND tenant_id=$2 to the WHERE clause.
			if err := db.UpdateRowCompound(database.TblPlatformEvents,
				"id", eventID,
				"tenant_id", tenantID,
				updates); err != nil {
				slog.Error("HandleCompleteRetrainEvent: failed to update retrain event",
					"event_id", eventID, "tenant_id", tenantID, "error", err)
				respond.InternalError(w, http.StatusInternalServerError, "update_retrain_event_failed", err)
				return
			}
		}

		slog.Info("NULL retrain completed_at FIXED: event marked complete",
			"event_id", eventID, "model_version", modelVersion,
			"tenant_id", tenantID, "completed_at", now)

		respond.JSON(w, http.StatusOK, map[string]any{
			"event_id":      eventID,
			"status":        "RETRAIN_COMPLETE",
			"model_version": modelVersion,
			"completed_at":  now,
		})
	}
}
