// Package propagation — ring_consumers.go
//
// Layer 2 Pub/Sub consumers for Ring 3 (aocs-compliance-svc).
//
// Palantir 3-layer pattern for each consumer:
//  1. Check compliance.idempotency_log (message_id) → skip if already processed.
//  2. UPSERT the target table (ON CONFLICT DO UPDATE) — safe on redelivery.
//  3. Write compliance.idempotency_log after success.
//  4. ACK.
//
// Triggers handled:
//   - TENANT_PROVISIONED (Ring 0) → UPSERT compliance.tenant_baselines
//   - TENANT_DELETED    (Ring 0) → UPDATE compliance.tenant_baselines + compliance_cases
//   - AGENT_REGISTERED  (Ring 2) → UPSERT compliance.agent_evidence_vault

package propagation

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"cloud.google.com/go/pubsub"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/eventbus"
)

// StartCompliancePropagationConsumers starts all cross-ring consumers for Ring 3.
// Must be called in goroutines. All consumers run until ctx is cancelled.
func StartCompliancePropagationConsumers(ctx context.Context, db database.DB, projectID string) {
	go startConsumer(ctx, db, projectID,
		eventbus.TopicTenantProvisioned(),
		"aocs-compliance-tenant-provisioned-sub",
		handleComplianceTenantProvisioned,
	)
	go startConsumer(ctx, db, projectID,
		eventbus.TopicTenantDeleted(),
		"aocs-compliance-tenant-deleted-sub",
		handleComplianceTenantDeleted,
	)
	go startConsumer(ctx, db, projectID,
		eventbus.TopicAgentRegistered(),
		"aocs-compliance-agent-registered-sub",
		handleComplianceAgentRegistered,
	)
}

// ─────────────────────────────────────────────────────────────────────────────
// TENANT_PROVISIONED → UPSERT compliance.tenant_baselines
// ─────────────────────────────────────────────────────────────────────────────

func handleComplianceTenantProvisioned(ctx context.Context, db database.DB, messageID string, payload map[string]any) error {
	tenantID, _ := payload["tenant_id"].(string)
	if tenantID == "" {
		return nil
	}

	if messageID != "" && isProcessed(ctx, db, messageID) {
		return nil
	}

	now := time.Now().UTC().Format(time.RFC3339)
	row := map[string]any{
		"tenant_id":        tenantID,
		"enforcement_mode": "OBSERVE", // safe default — log-only until admin promotes to ENFORCE
		"seeded_at":        now,
		"updated_at":       now,
	}
	// UPSERT on (tenant_id) — ON CONFLICT DO UPDATE enforces idempotency.
	// If Ring 0 sends twice, second delivery updates enforcement_mode to OBSERVE
	// (same value) — safe no-op in practice.
	if err := db.InsertRowIdempotent(database.TblComplianceTenantBaselines, row, "tenant_id"); err != nil {
		slog.Error("compliance/propagation: failed to upsert tenant_baselines",
			"tenant_id", tenantID, "error", err)
		return err
	}

	markProcessed(ctx, db, messageID, eventbus.TopicTenantProvisioned(), tenantID, "", "tenant_provisioned")
	slog.Info("compliance/propagation: tenant_baselines seeded (OBSERVE mode)", "tenant_id", tenantID)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// TENANT_DELETED → UPDATE compliance.tenant_baselines + compliance_cases
// ─────────────────────────────────────────────────────────────────────────────

func handleComplianceTenantDeleted(ctx context.Context, db database.DB, messageID string, payload map[string]any) error {
	tenantID, _ := payload["tenant_id"].(string)
	if tenantID == "" {
		return nil
	}

	if messageID != "" && isProcessed(ctx, db, messageID) {
		return nil
	}

	now := time.Now().UTC().Format(time.RFC3339)

	// UPDATE tenant_baselines — soft tombstone. Never hard-delete (audit trail required).
	if err := db.UpdateRow(database.TblComplianceTenantBaselines, "tenant_id", tenantID, map[string]any{
		"enforcement_mode": "AUDIT", // tenant deleted → AUDIT-only (no new enforcement)
		"updated_at":       now,
	}); err != nil {
		slog.Warn("compliance/propagation: failed to tombstone tenant_baselines (non-fatal)",
			"tenant_id", tenantID, "error", err)
	}

	// UPDATE compliance_cases — close any open cases for this tenant.
	// Idempotent: setting CLOSED → CLOSED is a safe DB no-op.
	if err := db.UpdateRow(database.TblComplianceComplianceCases, "tenant_id", tenantID, map[string]any{
		"status":     "CLOSED",
		"updated_at": now,
	}); err != nil {
		slog.Warn("compliance/propagation: failed to close compliance_cases (non-fatal)",
			"tenant_id", tenantID, "error", err)
	}

	// UPDATE agent_evidence_vault — freeze all vaults for this tenant.
	if err := db.UpdateRow(database.TblComplianceAgentVault, "tenant_id", tenantID, map[string]any{
		"vault_status": "RETIRED",
		"updated_at":   now,
	}); err != nil {
		slog.Warn("compliance/propagation: failed to retire agent_evidence_vault entries (non-fatal)",
			"tenant_id", tenantID, "error", err)
	}

	markProcessed(ctx, db, messageID, eventbus.TopicTenantDeleted(), tenantID, "", "tenant_deleted")
	slog.Info("compliance/propagation: tenant compliance records tombstoned", "tenant_id", tenantID)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// AGENT_REGISTERED → UPSERT compliance.agent_evidence_vault
// ─────────────────────────────────────────────────────────────────────────────

func handleComplianceAgentRegistered(ctx context.Context, db database.DB, messageID string, payload map[string]any) error {
	agentID, _ := payload["agent_id"].(string)
	tenantID, _ := payload["tenant_id"].(string)
	agentName, _ := payload["agent_name"].(string)

	if agentID == "" || tenantID == "" {
		return nil
	}

	if messageID != "" && isProcessed(ctx, db, messageID) {
		return nil
	}

	now := time.Now().UTC().Format(time.RFC3339)
	row := map[string]any{
		"tenant_id":    tenantID,
		"agent_id":     agentID,
		"agent_name":   agentName,
		"vault_status": "ACTIVE",
		"seeded_at":    now,
		"updated_at":   now,
	}
	// UPSERT on (agent_id, tenant_id) — idempotent on redelivery.
	if err := db.InsertRowIdempotent(database.TblComplianceAgentVault, row, "agent_id,tenant_id"); err != nil {
		slog.Error("compliance/propagation: failed to upsert agent_evidence_vault",
			"agent_id", agentID, "tenant_id", tenantID, "error", err)
		return err
	}

	markProcessed(ctx, db, messageID, eventbus.TopicAgentRegistered(), tenantID, agentID, "agent_registered")
	slog.Info("compliance/propagation: agent_evidence_vault seeded",
		"agent_id", agentID, "tenant_id", tenantID)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Generic consumer bootstrap + idempotency helpers
// ─────────────────────────────────────────────────────────────────────────────

type msgHandler func(ctx context.Context, db database.DB, messageID string, payload map[string]any) error

func startConsumer(ctx context.Context, db database.DB, projectID, topic, subID string, handler msgHandler) {
	if projectID != "" && topic != "" {
		broker, err := eventbus.NewPubSubBroker(projectID)
		if err != nil {
			slog.Error("compliance/propagation: failed to init broker", "topic", topic, "error", err)
		} else {
			slog.Info("compliance/propagation: starting consumer", "topic", topic, "sub", subID)
			if err := broker.SubscribeExactlyOnce(ctx, topic, subID, func(ctx context.Context, msg *pubsub.Message) {
				var payload map[string]any
				if err := json.Unmarshal(msg.Data, &payload); err != nil {
					msg.Nack()
					return
				}
				if err := handler(ctx, db, msg.ID, payload); err != nil {
					msg.Nack()
					return
				}
				msg.Ack()
			}); err != nil && ctx.Err() == nil {
				slog.Error("compliance/propagation: consumer exited", "topic", topic, "error", err)
			}
			return
		}
	}
	// Local dev: LocalEventBus.
	slog.Info("compliance/propagation: LocalEventBus fallback", "topic", topic)
	eventbus.GlobalBus().Subscribe(eventbus.EventType(topic), func(ctx context.Context, e *eventbus.Event) error {
		return handler(ctx, db, "", e.Payload)
	})
	<-ctx.Done()
}

func isProcessed(ctx context.Context, db database.DB, messageID string) bool {
	var rows []map[string]any
	_ = db.QueryRowsCtx(ctx, "compliance.idempotency_log",
		"message_id", "message_id", messageID, &rows)
	return len(rows) > 0
}

func markProcessed(ctx context.Context, db database.DB, messageID, topic, tenantID, agentID, handler string) {
	if messageID == "" {
		return
	}
	row := map[string]any{
		"message_id":   messageID,
		"topic":        topic,
		"tenant_id":    tenantID,
		"agent_id":     agentID,
		"handler":      handler,
		"result":       "OK",
		"processed_at": time.Now().UTC().Format(time.RFC3339),
	}
	_ = db.InsertRowIdempotent("compliance.idempotency_log", row, "message_id")
}
