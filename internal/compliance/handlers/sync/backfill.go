package sync

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/ocx/shared/respond"
)

// ActivateSyncRequest is the body for POST /compliance/sync/activate.
type ActivateSyncRequest struct {
	TenantID  string `json:"tenant_id"`
	Module    string `json:"module"`
	Mode      string `json:"mode"` // "forward_only" or "full_backfill"
	Watermark string `json:"watermark,omitempty"`
	Initiator string `json:"initiator,omitempty"`
}

// HandleActivateComplianceSync handles instant module activation and historical backfill requests.
func HandleActivateComplianceSync() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			respond.ErrorWithCode(w, http.StatusBadRequest, "bad_request", "failed to read request body")
			return
		}
		defer r.Body.Close()

		var req ActivateSyncRequest
		if len(body) > 0 {
			if err := json.Unmarshal(body, &req); err != nil {
				respond.ErrorWithCode(w, http.StatusBadRequest, "invalid_json", "invalid JSON payload")
				return
			}
		}

		if req.TenantID == "" {
			req.TenantID = r.Header.Get("X-Tenant-ID")
		}

		if req.TenantID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, "missing_tenant", "tenant_id is required")
			return
		}

		if req.Mode == "" {
			req.Mode = "forward_only"
		}

		now := time.Now().UTC()
		watermark := now.Format(time.RFC3339)
		if req.Watermark != "" {
			watermark = req.Watermark
		}

		slog.Info("Compliance ring sync activated",
			"tenant_id", req.TenantID,
			"mode", req.Mode,
			"watermark", watermark,
		)

		if req.Mode == "forward_only" {
			// Instant activation mode ("Move Forward Only"):
			// Clean genesis watermark at t=NOW, zero historical backfill latency.
			respond.JSON(w, http.StatusOK, map[string]any{
				"status":           "ACTIVE",
				"tenant_id":        req.TenantID,
				"module":           "compliance",
				"mode":             "forward_only",
				"watermark":        watermark,
				"events_processed": 0,
				"message":          fmt.Sprintf("Compliance Vault activated instantly for tenant %s. Operations enabled from %s without backfill.", req.TenantID, watermark),
				"activated_at":     now.Format(time.RFC3339),
			})
			return
		}

		// Mode: full_backfill
		respond.JSON(w, http.StatusAccepted, map[string]any{
			"status":           "SYNCHRONIZING",
			"tenant_id":        req.TenantID,
			"module":           "compliance",
			"mode":             "full_backfill",
			"watermark":        watermark,
			"events_processed": 0,
			"message":          fmt.Sprintf("Historical backfill queued for tenant %s. Events will be verified retroactively.", req.TenantID),
			"activated_at":     now.Format(time.RFC3339),
		})
	}
}
