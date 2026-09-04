// Package jry — Pub/Sub consumer for AOCS Jury escalations.
//
// This consumer subscribes to "aocs.cases.escalated" and forwards each
// escalation event to the Python Jury gRPC service.  It is the Go-side
// bridge that feeds the Python human-review workflow.
//
// When aocs-platform raises a HOLD verdict from the Tri-Factor Gate, it publishes
// to this topic.  The consumer picks it up and calls EscalateCase on the Python
// Jury service, which assigns the case to the next available juror and persists
// it in the core_compliance table.
//
// Resilience:
//   - Circuit breaker wraps every EscalateCase gRPC call.
//   - Nack-on-failure allows the Pub/Sub retry policy to redeliver.
//   - Dead-letter logging (same pattern as led-consumer) for observability.
package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"cloud.google.com/go/pubsub"
	"github.com/ocx/shared/infra/circuitbreaker"
	"github.com/ocx/shared/infra/config"
	"github.com/ocx/shared/consts"
)

// EscalationMessage is the canonical shape published on "aocs.cases.escalated".
// aocs-platform publishes this when the Tri-Factor Gate returns HOLD+HITL.
type EscalationMessage struct {
	DecisionID string `json:"decision_id"`
	GateID     string `json:"gate_id"`
	TenantID   string `json:"tenant_id"`
	AgentID    string `json:"agent_id"`
	Reason     string `json:"reason"`
	ContextData string `json:"context_data"` // JSON-encoded gate decision context
	Timestamp  string `json:"timestamp"`    // RFC3339
}

// EscalateFunc is the function signature used to escalate a case.
// In production this calls the Python Jury gRPC service.
// In tests a mock is injected.
type EscalateFunc func(ctx context.Context, msg EscalationMessage) error

// JuryConsumer subscribes to Pub/Sub and forwards escalations to the Jury service.
// 2 + PATENT-GAP-3 FIX: the gRPC JuryClient is held as a struct field and
// dialed exactly once — per-message dials were (a) expensive and (b) reset the
// CircuitBreaker's failure window on every new connection, defeating its purpose.
type JuryConsumer struct {
	escalate EscalateFunc
	cb       *circuitbreaker.CircuitBreaker
	project  string
	subName  string
	juryAddr string        // stored so Start() can dial once
	client   *JuryClient   // long-lived gRPC connection; nil until Start()
}

// NewJuryConsumer creates a production consumer that dials the Python Jury at juryAddr.
// juryAddr: gRPC address of the unified aocs-py-svc Jury gRPC port (e.g. "aocs-jury.ocx-system.svc.cluster.local:50090")
// project:  GCP project ID (falls back to GOOGLE_CLOUD_PROJECT env var)
// subName:  Pub/Sub subscription name (defaults to "aocs-jury-escalated-sub")
func NewJuryConsumer(juryAddr, project, subName string) *JuryConsumer {
	if project == "" {
		project = config.Get().Services.GCPProject
	}
	if subName == "" {
		subName = "aocs-jury-escalated-sub"
	}
	if juryAddr == "" {
		juryAddr = os.Getenv("JURY_GRPC_ADDR") // canonical env var (AOCS_JURY_ADDR deprecated)
	}
	if juryAddr == "" {
		// P0-fix: no localhost fallback — in Cloud Run, localhost:50090 is unreachable.
		// If JURY_GRPC_ADDR is unset, the NewJuryClient call will error and the
		// circuit breaker will open, fail-open for cases. Log at startup for observability.
		slog.Error("JURY_GRPC_ADDR not configured — jury forwarding will fail-open")
	}

	cb := circuitbreaker.New(circuitbreaker.Config{
		Name:             "jry-pubsub-consumer",
		FailureThreshold: 3, // Faster trip — Jury HOLD is time-sensitive
		ResetTimeout:     consts.PubSubResetTimeout,
	})

	// Store juryAddr; actual dial is deferred to Start() so that
	// a single connection is reused across all messages processed by this consumer.
	return &JuryConsumer{
		cb:       cb,
		project:  project,
		subName:  subName,
		juryAddr: juryAddr,
	}
}

// NewJuryConsumerWithFunc creates a consumer with a custom escalate function (for testing).
func NewJuryConsumerWithFunc(fn EscalateFunc, project, subName string) *JuryConsumer {
	if project == "" {
		project = config.Get().Services.GCPProject
	}
	if subName == "" {
		subName = "aocs-jury-escalated-sub"
	}
	return &JuryConsumer{
		escalate: fn,
		cb:       circuitbreaker.New(circuitbreaker.Config{Name: "jry-consumer-test", FailureThreshold: 3}),
		project:  project,
		subName:  subName,
	}
}

// Start launches the Pub/Sub listener as a background goroutine.
// The gRPC JuryClient is dialed once here and stored on the
// struct. All message handlers share this connection for the lifetime of the consumer.
func (c *JuryConsumer) Start(ctx context.Context) {
	if c.escalate == nil && c.juryAddr != "" {
		// Dial the persistent gRPC connection and wire the escalate func
		juryClient, err := NewJuryClient(c.juryAddr)
		if err != nil {
			slog.Error("Failed to dial Jury service — escalations will not be processed",
				"addr", c.juryAddr, "error", err)
			return
		}
		c.client = juryClient
		// Wire escalate func to the persistent client
		c.escalate = buildEscalateFuncFromClient(juryClient)
	}
	go c.run(ctx)
}

func (c *JuryConsumer) run(ctx context.Context) {
	slog.Info("Starting Pub/Sub consumer",
		"project", c.project,
		"subscription", c.subName)

	// Close the persistent gRPC connection when the consumer exits
	if c.client != nil {
		defer func() {
			if err := c.client.Close(); err != nil {
				slog.Error("Error closing jury client", "error", err)
			}
		}()
	}

	client, err := pubsub.NewClient(ctx, c.project)
	if err != nil {
		slog.Error("Failed to create Pub/Sub client — escalations will not be processed",
			"error", err)
		return
	}
	defer client.Close()

	if os.Getenv("PUBSUB_EMULATOR_HOST") != "" {
		c.ensureTopicAndSub(ctx, client)
	}

	sub := client.Subscription(c.subName)
	sub.ReceiveSettings.MaxOutstandingMessages = 20
	sub.ReceiveSettings.NumGoroutines = 2

	slog.Info("Listening for escalation events", "subscription", c.subName)

	if err := sub.Receive(ctx, func(ctx context.Context, msg *pubsub.Message) {
		c.handleMessage(ctx, msg)
	}); err != nil && ctx.Err() == nil {
		slog.Error("Pub/Sub Receive error", "error", err)
	}

	slog.Info("Consumer stopped")
}

func (c *JuryConsumer) handleMessage(ctx context.Context, msg *pubsub.Message) {
	// 1. Parse
	var payload EscalationMessage
	if err := json.Unmarshal(msg.Data, &payload); err != nil {
		slog.Error("Malformed escalation message — nacking",
			"error", err,
			"message_id", msg.ID)
		msg.Nack()
		return
	}

	// 2. Validate
	if payload.TenantID == "" || payload.AgentID == "" {
		slog.Error("Dropping escalation with missing tenant_id or agent_id",
			"message_id", msg.ID)
		msg.Ack()
		return
	}

	// 3. Forward to Python Jury via circuit breaker
	cbErr := c.cb.Execute(ctx, func(ctx context.Context) error {
		if err := c.escalate(ctx, payload); err != nil {
			return fmt.Errorf("jury escalate failed: %w", err)
		}
		slog.Info("Escalation forwarded to Jury service",
			"decision_id", payload.DecisionID,
			"gate_id", payload.GateID,
			"tenant_id", payload.TenantID,
			"agent_id", payload.AgentID)
		return nil
	})

	if cbErr != nil {
		slog.Error("CB blocked jury escalation — nacking",
			"error", cbErr,
			"decision_id", payload.DecisionID)
		deadLetterLogJury(payload, cbErr)
		msg.Nack()
		return
	}

	msg.Ack()
}

func (c *JuryConsumer) ensureTopicAndSub(ctx context.Context, client *pubsub.Client) {
	topicName  := config.Get().Topics.CasesEscalated
	dlqTopicID := config.Get().Topics.CasesEscalatedDLQ

	// Provision primary topic
	topic := client.Topic(topicName)
	if ok, err := topic.Exists(ctx); err == nil && !ok {
		if _, err := client.CreateTopic(ctx, topicName); err != nil {
			slog.Warn("Could not create emulator topic", "error", err)
		}
	}

	// Provision dead-letter topic
	dlqTopic := client.Topic(dlqTopicID)
	if ok, err := dlqTopic.Exists(ctx); err == nil && !ok {
		if _, err := client.CreateTopic(ctx, dlqTopicID); err != nil {
			slog.Warn("Could not create DLQ topic", "error", err)
			dlqTopic = nil // DLQ unavailable — fall back to log-only
		}
	}

	sub := client.Subscription(c.subName)
	if ok, err := sub.Exists(ctx); err == nil && !ok {
		cfg := pubsub.SubscriptionConfig{
			Topic:       topic,
			AckDeadline: consts.PubSubAckDeadlineLong,
		}
		// Wire DLQ policy when available
		if dlqTopic != nil {
			cfg.DeadLetterPolicy = &pubsub.DeadLetterPolicy{
				DeadLetterTopic:     dlqTopic.String(),
				MaxDeliveryAttempts: 5,
			}
		}
		if _, err := client.CreateSubscription(ctx, c.subName, cfg); err != nil {
			slog.Warn("Could not create emulator subscription", "error", err)
		}
	}
}

// buildEscalateFunc returns a production EscalateFunc that dials a NEW JuryClient
// per call. Only used by NewJuryConsumerWithFunc / test paths.
// PRODUCTION path uses buildEscalateFuncFromClient which reuses one connection.
// buildEscalateFuncFromClient builds the escalate func from a pre-dialed client.
// This is the production path — connection is shared and
// the CircuitBreaker state persists across all message dispatches.
func buildEscalateFuncFromClient(client *JuryClient) EscalateFunc {
	return func(ctx context.Context, msg EscalationMessage) error {
		resp, err := client.AuditIntent(
			ctx,
			msg.TenantID,
			msg.DecisionID,
			msg.AgentID,
			"escalate_case",
			"", // intentID — not available on escalation path
			"", // departmentID — not available on escalation path
			map[string]any{
				"reason":       msg.Reason,
				"gate_id":      msg.GateID,
				"tenant_id":    msg.TenantID,
				"context_data": msg.ContextData,
			},
		)
		if err != nil {
			return err
		}

		slog.Info("Jury accepted escalation",
			"decision_id", msg.DecisionID,
			"verdict", resp.Verdict,
			"reason", resp.Reason)
		return nil
	}
}

func deadLetterLogJury(payload EscalationMessage, cause error) {
	entry := map[string]any{
		"severity":    "CRITICAL",
		"component":   "jry-consumer-dead-letter",
		"tenant_id":   payload.TenantID,
		"agent_id":    payload.AgentID,
		"decision_id": payload.DecisionID,
		"gate_id":     payload.GateID,
		"error":       fmt.Sprintf("%v", cause),
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
	}
	b, marshalErr := json.Marshal(entry)
	if marshalErr != nil {
		slog.Error("json.Marshal failed", "err", marshalErr)
		return
	}
	slog.Error("DEAD-LETTER", "json", string(b))
}
