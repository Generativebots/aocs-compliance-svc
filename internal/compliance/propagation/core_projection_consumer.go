// Package propagation — core_projection_consumer.go
//
// Row 9 (CM-01): compliance's read model of core data. ocx-core-svc publishes every
// core_hitl / core_policies / core_agents change as eventbus.ComplianceProjection on the
// compliance topic; this consumer upserts it into compl_core_projection so compliance
// handlers never SQL-read core_* tables.
//
// Idempotent and order-safe: a message only applies when its source_ts is not older than the
// stored row, so Pub/Sub redelivery and reordering are harmless (no idempotency-log row needed).
package propagation

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"cloud.google.com/go/pubsub"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/eventbus"
)

const projectionSubID = "aocs-compliance-projection-sub"

const projectionUpsertSQL = `
	INSERT INTO compl_core_projection (tenant_id, kind, entity_id, payload, source_ts, updated_at)
	VALUES ($1, $2, $3, $4::jsonb, $5, NOW())
	ON CONFLICT (tenant_id, kind, entity_id) DO UPDATE
	   SET payload = EXCLUDED.payload, source_ts = EXCLUDED.source_ts, updated_at = NOW()
	 WHERE compl_core_projection.source_ts <= EXCLUDED.source_ts`

const projectionDeleteSQL = `
	DELETE FROM compl_core_projection
	 WHERE tenant_id = $1 AND kind = $2 AND entity_id = $3 AND source_ts <= $4`

// StartCoreProjectionConsumer subscribes to the compliance topic and applies projections.
// Blocks until ctx is cancelled; run it in a goroutine.
func StartCoreProjectionConsumer(ctx context.Context, pool *database.PGXPool, projectID string) {
	if pool == nil {
		slog.Warn("compliance/projection: no DB pool — core read model disabled")
		return
	}
	topic := eventbus.TopicComplianceEvent()
	if projectID == "" || topic == "" {
		slog.Warn("compliance/projection: GCP_PROJECT_ID or compliance topic unset — core read model disabled")
		return
	}
	broker, err := eventbus.NewPubSubBroker(projectID)
	if err != nil {
		slog.Error("compliance/projection: failed to init broker", "error", err)
		return
	}
	slog.Info("compliance/projection: starting consumer", "topic", topic, "sub", projectionSubID)
	if err := broker.SubscribeExactlyOnce(ctx, topic, projectionSubID, func(ctx context.Context, msg *pubsub.Message) {
		if err := applyProjectionMessage(ctx, pool, msg.Data); err != nil {
			slog.Error("compliance/projection: apply failed — nacking", "message_id", msg.ID, "error", err)
			msg.Nack()
			return
		}
		msg.Ack()
	}); err != nil && ctx.Err() == nil {
		slog.Error("compliance/projection: consumer exited", "error", err)
	}
}

// applyProjectionMessage decodes one message and applies it. Messages that are not projections
// (compliance.event traffic on the shared topic) and permanently invalid ones are acked (nil).
func applyProjectionMessage(ctx context.Context, pool *database.PGXPool, data []byte) error {
	var m eventbus.ComplianceProjection
	if err := json.Unmarshal(data, &m); err != nil || m.EventType != eventbus.EventComplianceProjection {
		return nil
	}
	if m.TenantID == "" || m.EntityID == "" || !eventbus.ValidProjectionKind(m.Kind) {
		slog.Warn("compliance/projection: dropping invalid projection", "kind", m.Kind, "entity_id", m.EntityID)
		return nil
	}
	ts, err := time.Parse(time.RFC3339Nano, m.SourceTS)
	if err != nil {
		ts = time.Now().UTC()
	}
	body, err := json.Marshal(m.Payload)
	if err != nil || m.Payload == nil {
		body = []byte("{}")
	}

	tx, err := pool.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Consumer is a system actor: no per-tenant session, so lift RLS for this tx only.
	if _, err := tx.Exec(ctx, `SELECT set_config('app.is_super_admin','true',true)`); err != nil {
		return err
	}
	if m.Deleted {
		_, err = tx.Exec(ctx, projectionDeleteSQL, m.TenantID, m.Kind, m.EntityID, ts)
	} else {
		_, err = tx.Exec(ctx, projectionUpsertSQL, m.TenantID, m.Kind, m.EntityID, string(body), ts)
	}
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" { // tenant not (yet) in syst_tenants
			slog.Warn("compliance/projection: unknown tenant — dropping", "tenant_id", m.TenantID, "kind", m.Kind)
			return nil
		}
		return err
	}
	return tx.Commit(ctx)
}

