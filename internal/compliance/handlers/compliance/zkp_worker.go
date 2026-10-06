// Package compliance — WORKER-08: ZKP Batch Processor.
//
// Picks up pending core_evidence every 5 minutes,
// generates a deterministic ZKP chain root per batch, writes to
// core_evidence, and marks jobs COMPLETED.
//
// Wire from cmd/aocs-intel/main.go:
//
//	zkp.StartBatchProcessor(svc.BgCtx, db)
package compliance

import (
	"github.com/ocx/shared/consts"
)

// zkpPollInterval — use shared const so all monitoring intervals are standardised to 15m.
var zkpPollInterval = consts.ZKPPollInterval
