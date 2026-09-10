// Package propagation — system_compliance_consumer.go
//
// System Outbox Consumer for aocs-compliance-svc.
//
// Polls syst_outbox_events (System DB) for tenant and agent lifecycle events
// and seeds compliance-owned tables via the existing handler functions.
//
// # Why this exists
//
// System foundation writes events to syst_outbox_events.
// SystemComplianceConsumer polls the outbox directly.
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
//   READ  (syst_outbox_events):       PLATFORM_DATABASE_URL or SYSTEM_DATABASE_URL → System Supabase DB.
//   WRITE (compl_tenant_baselines,    svc.DB / db arg                              → Compliance Supabase DB
//          compl_agent_evidence_vault,                                                (DATABASE_URL for compliance).
//          compl_idempotency_log):
//
// # Idempotency
//
// All handlers use the compl_idempotency_log to deduplicate on message_id.
// For system outbox events, evt.EventID is used as the message_id.
// The outbox poller is at-least-once — idempotency log prevents double-writes.
//
// # Wiring (cmd/aocs-compliance/main.go)
//
//	if systemPool != nil {
//	    consumer := propagation.NewSystemComplianceConsumer(systemPool.Pool(), db)
//	    consumer.Start(svc.BgCtx)
//	}
package propagation

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/eventbus"
)

// SystemComplianceConsumer polls system syst_outbox_events and seeds compliance tables.
type SystemComplianceConsumer struct {
	poller *eventbus.SystemOutboxPoller
	db     database.DB
}

// NewSystemComplianceConsumer creates the consumer.
//
//   - pool: pgx pool pointing at System DB — for outbox reads.
//   - db:   compliance SupabaseClient (DATABASE_URL) — for compl_* writes.
func NewSystemComplianceConsumer(pool *pgxpool.Pool, db database.DB) *SystemComplianceConsumer {
	c := &SystemComplianceConsumer{db: db}
	c.poller = eventbus.NewSystemOutboxPoller(pool, c.dispatch, "")
	return c
}

// Start begins polling syst_outbox_events in a supervised goroutine.
func (c *SystemComplianceConsumer) Start(ctx context.Context) {
	slog.Info("system-compliance-consumer: starting",
		"table", eventbus.SystemOutboxTable,
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
func (c *SystemComplianceConsumer) dispatch(ctx context.Context, evt eventbus.SystemOutboxEvent) error {
	payload := mergeEventFields(evt)

	switch evt.EventType {
	case "tenant.provisioned":
		return handleComplianceTenantProvisioned(ctx, c.db, evt.EventID, payload)

	case "tenant.deleted":
		return handleComplianceTenantDeleted(ctx, c.db, evt.EventID, payload)

	case "agent.created", "agent.seed_requested":
		return handleComplianceAgentRegistered(ctx, c.db, evt.EventID, payload)

	case "AGENT_RETIRED":
		slog.Info("system-compliance-consumer: AGENT_RETIRED — vault kept ACTIVE for audit trail",
			"agent_id", evt.AggregateID, "tenant_id", evt.TenantID)
		return nil

	default:
		return nil
	}
}

// mergeEventFields produces a payload map enriched with the outbox event's
// top-level fields (tenant_id, agent_id / aggregate_id, agent_name).
func mergeEventFields(evt eventbus.SystemOutboxEvent) map[string]any {
	payload := make(map[string]any, len(evt.Payload)+4)
	for k, v := range evt.Payload {
		payload[k] = v
	}
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
