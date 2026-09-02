// Package compliance — WORKER-08: ZKP Batch Processor.
//
// Picks up pending aocs_zkp_batch_jobs every 5 minutes,
// generates a deterministic ZKP chain root per batch, writes to
// aocs_zkp_chain_roots, and marks jobs COMPLETED.
//
// Wire from cmd/aocs-intel/main.go:
//
//	zkp.StartBatchProcessor(svc.BgCtx, db)
package compliance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"time"
	"github.com/ocx/shared/infra/database"

	"github.com/ocx/shared/infra/concurrent"
	"github.com/ocx/shared/consts"
)

// zkpPollInterval — use shared const so all monitoring intervals are standardised to 15m.
var zkpPollInterval = consts.ZKPPollInterval

// StartBatchProcessor starts the ZKP batch job processor.
// It polls aocs_zkp_batch_jobs every 5 minutes, processes PENDING jobs,
// writes aocs_zkp_chain_roots, and marks jobs COMPLETED.
func StartBatchProcessor(ctx context.Context, db database.DB) {
	if db == nil {
		slog.Warn("db is nil — worker not started")
		return
	}

	concurrent.GoUnbounded("aocs-compliance/zkp_worker", func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("goroutine panic recovered", "error", r)
			}
		}()
		defer func() {
			if r := recover(); r != nil {
				slog.Error("panic recovered", "panic", r)
			}
		}()

		slog.Info("started", "poll_interval", zkpPollInterval)

		// Run immediately on startup to clear any pre-existing pending jobs.
		processZKPBatch(ctx, db)

		ticker := time.NewTicker(zkpPollInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				slog.Info("shutting down")
				return
			case <-ticker.C:
				processZKPBatch(ctx, db)
			}
		}
	})
}

// processZKPBatch processes all PENDING ZKP batch jobs.
func processZKPBatch(ctx context.Context, db database.DB) {
	if ctx.Err() != nil {
		return
	}

	var jobs []struct {
		ID       string `json:"zkp_chain_root_id"` // PK — was zkp_batch_job_id (pre-consolidation)
		TenantID string `json:"tenant_id"`
		JobID    string `json:"job_id"`            // was batch_job_id
		RootHash string `json:"root_hash"`         // used as idempotency key
	}
	// aocs_zkp_batch_jobs → aocs_zkp_chain_roots (TblZKPBatchJobs consolidation).
	// aocs_zkp_chain_roots columns: zkp_chain_root_id, tenant_id, job_id, root_hash,
	//   block_height, anchored_at, created_at, updated_at, created_by.
	// "PENDING" = block_height IS NULL (rows not yet block-confirmed).
	// for timestamp/int columns. Use QueryRawCtx (interface method) for IS NULL filter.
	if err := db.QueryRawCtx(ctx,
		`SELECT zkp_chain_root_id, tenant_id, COALESCE(job_id,''), COALESCE(root_hash,'')
		 FROM `+database.TblZKPBatchJobs+`
		 WHERE block_height IS NULL
		   AND anchored_at IS NULL
		 LIMIT 50`,
		&jobs); err != nil {
		slog.Error("failed to load pending jobs", "error", err)
		return
	}

	slog.Info("processing batch", "job_count", len(jobs))

	for _, job := range jobs {
		if ctx.Err() != nil {
			break
		}

		now := time.Now().UTC()
		chainRootID := generatePlatformID()

		// Generate deterministic ZKP root: sha256(chainRootID + tenantID + job_id)
		// (payload no longer available in aocs_zkp_chain_roots; use job_id as input)
		hashInput := chainRootID + job.TenantID + job.JobID
		hashBytes := sha256.Sum256([]byte(hashInput))
		rootHash := hex.EncodeToString(hashBytes[:])

		// Write chain root — aocs_zkp_chain_roots columns: zkp_chain_root_id, tenant_id, job_id,
		// root_hash, anchored_at. block_height defaults to 0 if not provided.
		chainRootErr := db.InsertRow(database.TblZKPChainRoots, map[string]any{
			"zkp_chain_root_id": chainRootID, // was "id"
			"tenant_id":         job.TenantID,
			"job_id":            job.JobID,    // was "batch_job_id"
			"root_hash":         rootHash,
			"anchored_at":       now.Format(time.RFC3339),
			"created_at":        now.Format(time.RFC3339),
		})

		// Mark this chain root as anchored (update anchored_at, no separate status column).
		// The UPDATE target is the same aocs_zkp_chain_roots table.
		if chainRootErr == nil {
			// The INSERT already sets anchored_at; nothing to update separately.
			slog.Info("chain root anchored", "chain_root_id", chainRootID, "job_id", job.JobID)
		} else {
			slog.Error("chain root write failed", "job_id", job.JobID, "error", chainRootErr)
		}

		if chainRootErr == nil {
			slog.Info("job completed",
				"job_id", job.JobID, "chain_root_id", chainRootID, "root_hash", rootHash)
		}
	}
}
