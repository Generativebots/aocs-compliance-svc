// Package propagation — ring0_compliance_consumer.go
//
// Ring-0 Outbox Consumer for aocs-compliance-svc.
//
// Polls syst_outbox_events (Ring-0 DB) for tenant and agent lifecycle events
// and seeds compliance-owned tables via the existing handler functions.
//
// # Why this exists
//
// Ring-0 (aocs-system-svc) writes events to syst_outbox_events — NOT to GCP
// Pub/Sub. The existing StartCompliancePropagationConsumers relies on GCP
// Pub/Sub / LocalEventBus and therefore NEVER fires in production.
// Ring0ComplianceConsumer fixes this by polling the outbox directly.
//
// # Consumed events
//
//   - "tenant.provisioned"    → UPSERT compl_tenant_baselines (OBSERVE mode).
//   - "tenant.deleted"        → soft-tombstone compl_tenant_baselines + close cases.
//   - "agent.created"         → UPSERT compl_agent_evidence_vault.
//   - "agent.seed_requested"  → UPSERT compl_agent_evidence_vault (same handler).
//   - "AGENT_RETIRED"         → no compliance action (vault stays ACTIVE for audit).
//
// # DB wiring
//
//   READ  (syst_outbox_events):       PLATFORM_DATABASE_URL → Ring-0 Supabase DB.
//   WRITE (compl_tenant_baselines,    svc.DB / db arg      → Compliance Supabase DB
//          compl_agent_evidence_vault,                        (DATABASE_URL for compliance).
//          compl_idempotency_log):
//
// # Idempotency
//
// All handlers use the compl_idempotency_log to deduplicate on message_id.
// For Ring-0 outbox events, evt.EventID is used as the message_id.
// The outbox poller is at-least-once — idempotency log prevents double-writes.
//
// # Wiring (cmd/aocs-compliance/main.go)
//
//	if ring0Pool != nil {
//	    ring0Consumer := propagation.NewRing0ComplianceConsumer(ring0Pool.Pool(), db)
//	    ring0Consumer.Start(svc.BgCtx)
//	}
package propagation

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/eventbus"
)

// Ring0ComplianceConsumer polls Ring-0's syst_outbox_events and seeds compliance tables.
type Ring0ComplianceConsumer struct {
	poller *eventbus.Ring0OutboxPoller
	db     database.DB
}

// NewRing0ComplianceConsumer creates the consumer.
//
//   - pool: pgx pool pointing at Ring-0 DB (PLATFORM_DATABASE_URL) — for outbox reads.
//   - db:   compliance SupabaseClient (DATABASE_URL) — for compl_* writes.
func NewRing0ComplianceConsumer(pool *pgxpool.Pool, db database.DB) *Ring0ComplianceConsumer {
	c := &Ring0ComplianceConsumer{db: db}
	c.poller = eventbus.NewRing0OutboxPoller(pool, c.dispatch, "")
	return c
}

// Start begins polling syst_outbox_events in a supervised goroutine.
func (c *Ring0ComplianceConsumer) Start(ctx context.Context) {
	slog.Info("ring0-compliance-consumer: starting",
		"table", eventbus.Ring0OutboxTable,
		"events", []string{
			"tenant.provisioned",
			"tenant.deleted",
			"agent.created",
			"agent.seed_requested",
		},
	)
	c.poller.Start(ctx)
}

// dispatch routes incoming outbox events to the appropriate compliance handler.
// Returns nil for unknown events — other consumers may handle them.
func (c *Ring0ComplianceConsumer) dispatch(ctx context.Context, evt eventbus.Ring0OutboxEvent) error {
	// Merge aggregate_id / tenant_id / agent_id into payload so existing handlers
	// can extract them with their standard payload["tenant_id"].(string) pattern.
	payload := mergeEventFields(evt)

	switch evt.EventType {
	case "tenant.provisioned":
		// evt.EventID used as messageID for idempotency log dedup.
		return handleComplianceTenantProvisioned(ctx, c.db, evt.EventID, payload)

	case "tenant.deleted":
		return handleComplianceTenantDeleted(ctx, c.db, evt.EventID, payload)

	case "agent.created", "agent.seed_requested":
		// Both events carry agent_id + tenant_id — same vault seeding logic.
		return handleComplianceAgentRegistered(ctx, c.db, evt.EventID, payload)

	case "AGENT_RETIRED":
		// Compliance keeps the vault ACTIVE for audit trail purposes.
		// Retiring an agent does not seal its evidence vault.
		slog.Info("ring0-compliance-consumer: AGENT_RETIRED — vault kept ACTIVE for audit trail",
			"agent_id", evt.AggregateID, "tenant_id", evt.TenantID)
		return nil

	default:
		// Silently skip — this consumer only handles compliance-relevant events.
		return nil
	}
}

// mergeEventFields produces a payload map enriched with the outbox event's
// top-level fields (tenant_id, agent_id / aggregate_id, agent_name).
// This lets existing handlers use their standard payload["tenant_id"].(string) pattern
// without needing to be aware of the Ring0OutboxEvent struct.
func mergeEventFields(evt eventbus.Ring0OutboxEvent) map[string]any {
	payload := make(map[string]any, len(evt.Payload)+4)
	for k, v := range evt.Payload {
		payload[k] = v
	}
	// Prefer payload values already set; only fill in from event fields if absent.
	if _, ok := payload["tenant_id"]; !ok && evt.TenantID != "" {
		payload["tenant_id"] = evt.TenantID
	}
	if _, ok := payload["agent_id"]; !ok && evt.AggregateID != "" {
		payload["agent_id"] = evt.AggregateID
	}
	if _, ok := payload["agent_name"]; !ok {
		if name, ok2 := evt.Payload["name"].(string); ok2 {
			payload["agent_name"] = name
		}
	}
	return payload
}
