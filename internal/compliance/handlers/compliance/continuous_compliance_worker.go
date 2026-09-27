package compliance

import (
	"context"
	"log/slog"
	"time"

	"github.com/ocx/shared/infra/concurrent"
	"github.com/ocx/shared/infra/database"
)

const continuousComplianceInterval = 5 * time.Minute

// StartContinuousComplianceWorker periodically scans for active policy violations
// and synchronizes linked compliance obligation statuses so the dashboard posture
// is continuously updated rather than only updated on-demand (GAP-GRC1).
func StartContinuousComplianceWorker(ctx context.Context, db database.DB) {
	if db == nil {
		slog.Warn("ContinuousComplianceWorker: db is nil — worker not started")
		return
	}

	concurrent.GoUnbounded("aocs-compliance/continuous_compliance_worker", func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("ContinuousComplianceWorker recovered from panic", "error", r)
			}
		}()

		slog.Info("ContinuousComplianceWorker started", "interval", continuousComplianceInterval)

		// Run sweep on startup
		evaluateContinuousCompliance(ctx, db)

		ticker := time.NewTicker(continuousComplianceInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				slog.Info("ContinuousComplianceWorker shutting down")
				return
			case <-ticker.C:
				evaluateContinuousCompliance(ctx, db)
			}
		}
	})
}

func evaluateContinuousCompliance(ctx context.Context, db database.DB) {
	// Query active open violations across all tenants
	var openViolations []map[string]any
	err := db.QueryRowsCtx(ctx, database.TblComplPolicyViolations, "violation_id,tenant_id,policy_id,status", "status", "OPEN", &openViolations)
	if err != nil {
		slog.Debug("ContinuousComplianceWorker: error querying open violations", "error", err)
		return
	}

	nowStr := time.Now().UTC().Format(time.RFC3339)
	tenantViolations := make(map[string]int)
	for _, v := range openViolations {
		tid, _ := v["tenant_id"].(string)
		if tid != "" {
			tenantViolations[tid]++
		}
	}

	// For tenants with active violations, ensure obligations reflect this
	for tenantID, count := range tenantViolations {
		if count > 0 {
			var obRows []map[string]any
			if qErr := db.QueryRowsCtx(ctx, database.TblComplObligations, "control_id,status,last_assessed_at", "tenant_id", tenantID, &obRows); qErr == nil {
				for _, ob := range obRows {
					cid, _ := ob["control_id"].(string)
					curStatus, _ := ob["status"].(string)
					if curStatus == "COMPLIANT" {
						// Flip to IN_PROGRESS to reflect active violation under review
						_ = db.UpdateRowCompound(database.TblComplObligations, "control_id", cid, "tenant_id", tenantID, map[string]any{
							"status":           "IN_PROGRESS",
							"last_assessed_at": nowStr,
						})
						slog.Info("ContinuousComplianceWorker: obligation flipped to IN_PROGRESS due to open violation",
							"tenant_id", tenantID, "control_id", cid)
					}
				}
			}
		}
	}
}
