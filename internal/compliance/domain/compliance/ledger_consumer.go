// Package compliance — Pub/Sub consumer for AOCS Ledger.
//
// This consumer subscribes to "aocs.ledger.write" and streams evidence payloads
// asynchronously into the core_evidence_records table, preventing the core REST API
// from blocking during high-throughput orchestration cycles.
package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"cloud.google.com/go/pubsub"
	"github.com/ocx/shared/consts"
	"github.com/ocx/shared/infra/config"
	"github.com/ocx/shared/infra/database"
)

// LedgerConsumer subscribes to Pub/Sub and streams evidence payloads to the database.
type LedgerConsumer struct {
	pgx     *database.PGXPool
	project string
	subName string
}

// NewLedgerConsumer creates a consumer that writes to pgx.
func NewLedgerConsumer(pgx *database.PGXPool, project, subName string) *LedgerConsumer {
	if project == "" {
		project = config.Get().Services.GCPProject
	}
	if subName == "" {
		subName = "aocs-ledger-consumer-sub"
	}
	return &LedgerConsumer{
		pgx:     pgx,
		project: project,
		subName: subName,
	}
}

// Start launches the consumer natively in the background.
func (c *LedgerConsumer) Start(ctx context.Context) {
	go c.run(ctx)
}

func (c *LedgerConsumer) run(ctx context.Context) {
	if c.pgx == nil {
		slog.Warn("PGX Pool is nil — ledger recording disabled")
		return
	}

	slog.Info("Starting Pub/Sub consumer",
		"project", c.project,
		"subscription", c.subName)

	client, err := pubsub.NewClient(ctx, c.project)
	if err != nil {
		slog.Error("Failed to create Pub/Sub client", "error", err)
		return
	}
	defer client.Close()

	if os.Getenv("PUBSUB_EMULATOR_HOST") != "" {
		c.ensureTopicAndSub(ctx, client)
	}

	sub := client.Subscription(c.subName)
	// Optimize for high-throughput
	sub.ReceiveSettings.MaxOutstandingMessages = 100
	sub.ReceiveSettings.NumGoroutines = 4

	slog.Info("Listening for ledger stream events", "subscription", c.subName)

	if err := sub.Receive(ctx, func(ctx context.Context, msg *pubsub.Message) {
		c.handleMessage(ctx, msg)
	}); err != nil && ctx.Err() == nil {
		slog.Error("Pub/Sub Receive error", "error", err)
	}

	slog.Info("Consumer stopped")
}

func (c *LedgerConsumer) handleMessage(ctx context.Context, msg *pubsub.Message) {
	var e database.QCoreEvidenceRecord
	if err := json.Unmarshal(msg.Data, &e); err != nil {
		slog.Error("Malformed evidence message — nacking",
			"error", err,
			"message_id", msg.ID)
		msg.Nack()
		return
	}

	// Basic validation
	if e.TenantID == "" || e.Hash == "" {
		slog.Warn("Dropping evidence missing tenant_id or cryptohash",
			"message_id", msg.ID)
		msg.Ack()
		return
	}

	// Insert into DB using pgx
	err := c.insertEvidence(ctx, e)
	if err != nil {
		slog.Error("DB Insert failed — nacking", "error", err)
		deadLetterLogLedger(e, err)
		msg.Nack()
		return
	}

	slog.Debug("Recorded evidence", "id", e.ID, "hash", e.Hash)
	msg.Ack()
}

func (c *LedgerConsumer) insertEvidence(ctx context.Context, e database.QCoreEvidenceRecord) error {
	// SLA-GUARANTEE: Supply both `timestamp` (composite PK partner) and `created_at` explicitly
	// from the same instant. The frontend reads `created_at` for all time-window filtering;
	// `timestamp` is the legacy PK field for ON CONFLICT resolution.
	// Using the same `now` value ensures the two columns are always identical and deterministic.
	now := time.Now().UTC()
	// Fix-8: created_by stamps the originating agent (or "ledger.consumer" for system events).
	createdBy := e.AgentID
	if createdBy == "" {
		createdBy = "ledger.consumer"
	}
	query := `
		INSERT INTO core_evidence_records (
			id, type, transaction_id, tenant_id, agent_id,
			hash, payload, timestamp, created_at, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8, $9)
		ON CONFLICT (id, timestamp) DO UPDATE SET
			hash       = EXCLUDED.hash,
			payload    = EXCLUDED.payload,
			created_at = EXCLUDED.created_at,
			created_by = EXCLUDED.created_by
	`
	_, err := c.pgx.Pool().Exec(ctx, query,
		e.ID,
		e.Type,
		e.TransactionID,
		e.TenantID,
		nullIfEmpty(e.AgentID),
		e.Hash,
		string(e.Payload),
		now,
		createdBy,
	)
	return err
}

func nullIfEmpty(val string) interface{} {
	if val == "" {
		return nil
	}
	return val
}

func (c *LedgerConsumer) ensureTopicAndSub(ctx context.Context, client *pubsub.Client) {
	topicName := config.Get().Topics.LedgerWrite
	topic := client.Topic(topicName)
	if ok, _ := topic.Exists(ctx); !ok {
		if _, err := client.CreateTopic(ctx, topicName); err != nil {
			slog.Warn("Could not create emulator topic", "error", err)
		}
	}
	sub := client.Subscription(c.subName)
	if ok, _ := sub.Exists(ctx); !ok {
		if _, err := client.CreateSubscription(ctx, c.subName, pubsub.SubscriptionConfig{
			Topic:       topic,
			AckDeadline: consts.PubSubAckDeadlineDefault,
		}); err != nil {
			slog.Warn("Could not create emulator subscription", "error", err)
		}
	}
}

func deadLetterLogLedger(payload database.QCoreEvidenceRecord, cause error) {
	entry := map[string]any{
		"severity":  "CRITICAL",
		"component": "ledger-consumer-dlq",
		"tenant_id": payload.TenantID,
		"agent_id":  payload.AgentID,
		"hash":      payload.Hash,
		"error":     fmt.Sprintf("%v", cause),
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	b, marshalErr := json.Marshal(entry)
	if marshalErr != nil {
		slog.Error("json.Marshal failed", "err", marshalErr)
		return
	}
	slog.Error("DEAD-LETTER", "json", string(b))
}
