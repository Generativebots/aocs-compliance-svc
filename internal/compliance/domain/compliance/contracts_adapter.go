// Package compliance provides gRPC clients for the Python Jury Auditor (JuryClient)
// and the ENT hallucination detection service (EntClient).
// This file adds thin contracts adapters so that these types implement the
// contracts.IntentAuditor and contracts.HallucinationDetector interfaces,
// enabling the gate handler layer to depend on abstractions.
//
// Design notes:
//   - Both adapters validate their wrapped client at construction time (nil guard).
//   - Both adapters are intentionally thin — observability (latency, error-rate
//     metrics) belongs in the underlying client or a decorator wrapper, not here.
//   - AuditIntent / DetectHallucination take positional string args because the
//     interfaces are defined in contracts.go and shared across the codebase.
//     Argument-order bugs are mitigated by the compile-time interface assertion.
//   - Response structs contain only primitive value types (string, float64, bool).
//     No shared mutable state — field copies are safe.
package compliance

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/ocx/shared/contracts"
)

// JuryClient → contracts.IntentAuditor

// Compile-time assertion: *JuryClientAdapter must implement contracts.IntentAuditor.
var _ contracts.IntentAuditor = (*JuryClientAdapter)(nil)

// JuryClientAdapter wraps *JuryClient and implements contracts.IntentAuditor.
type JuryClientAdapter struct {
	client *JuryClient
}

// NewJuryClientAdapter wraps client so it satisfies contracts.IntentAuditor.
//
// Returns an error if client is nil — a nil JuryClient would cause a nil-pointer
// panic on the first AuditIntent call, and such a misconfiguration is better
// caught at startup than silently at request time.
func NewJuryClientAdapter(client *JuryClient) (*JuryClientAdapter, error) {
	if client == nil {
		return nil, errors.New("compliance: NewJuryClientAdapter: JuryClient must not be nil")
	}
	return &JuryClientAdapter{client: client}, nil
}

// AuditIntent implements contracts.IntentAuditor.
//
// Parameter order: tenantID, txID, agentID, toolName, params.
// This order is fixed by the IntentAuditor interface (contracts/contracts.go).
// Callers must verify argument order at the call site.
func (a *JuryClientAdapter) AuditIntent(
	ctx context.Context,
	tenantID, txID, agentID, toolName string,
	params map[string]any,
) (*contracts.IntentAuditResponse, error) {
	start := time.Now()
	resp, err := a.client.AuditIntent(ctx, tenantID, txID, agentID, toolName, params)
	latency := time.Since(start)

	if err != nil {
		slog.Warn("compliance.JuryClientAdapter: AuditIntent error",
			"tenant_id", tenantID,
			"tx_id", txID,
			"agent_id", agentID,
			"latency_ms", latency.Milliseconds(),
			"error", err,
		)
		return nil, fmt.Errorf("compliance.AuditIntent: %w", err)
	}
	if resp == nil {
		slog.Warn("compliance.JuryClientAdapter: AuditIntent returned nil (Jury unavailable)",
			"tenant_id", tenantID, "tx_id", txID, "agent_id", agentID)
		return nil, nil
	}

	slog.Debug("compliance.JuryClientAdapter: AuditIntent ok",
		"tenant_id", tenantID, "tx_id", txID, "verdict", resp.Verdict,
		"confidence", resp.Confidence, "latency_ms", latency.Milliseconds(),
	)

	// Shallow copy is safe: IntentAuditResponse contains only primitive value
	// types (string, float64, bool) — no slices, maps, or pointer fields.
	return &contracts.IntentAuditResponse{
		TransactionID:  resp.TransactionID,
		Verdict:        resp.Verdict,
		Confidence:     resp.Confidence,
		Reason:         resp.Reason,
		AuditTime:      resp.AuditTime,
		CognitiveScore: resp.CognitiveScore,
		IsFallback:     resp.IsFallback,
	}, nil
}

// EntClient → contracts.HallucinationDetector

// Compile-time assertion: *EntClientAdapter must implement contracts.HallucinationDetector.
var _ contracts.HallucinationDetector = (*EntClientAdapter)(nil)

// EntClientAdapter wraps *EntClient and implements contracts.HallucinationDetector.
type EntClientAdapter struct {
	client *EntClient
}

// NewEntClientAdapter wraps client so it satisfies contracts.HallucinationDetector.
//
// Returns an error if client is nil — same nil-guard rationale as NewJuryClientAdapter.
func NewEntClientAdapter(client *EntClient) (*EntClientAdapter, error) {
	if client == nil {
		return nil, errors.New("compliance: NewEntClientAdapter: EntClient must not be nil")
	}
	return &EntClientAdapter{client: client}, nil
}

// DetectHallucination implements contracts.HallucinationDetector.
//
// Parameter order: llmOutput, contextText, agentID, tenantID.
// This order is fixed by the HallucinationDetector interface (contracts/contracts.go).
func (a *EntClientAdapter) DetectHallucination(
	ctx context.Context,
	llmOutput, contextText, agentID, tenantID string,
) (*contracts.HallucinationResponse, error) {
	start := time.Now()
	resp, err := a.client.DetectHallucination(ctx, llmOutput, contextText, agentID, tenantID)
	latency := time.Since(start)

	if err != nil {
		slog.Warn("compliance.EntClientAdapter: DetectHallucination error",
			"tenant_id", tenantID,
			"agent_id", agentID,
			"latency_ms", latency.Milliseconds(),
			"error", err,
		)
		return nil, fmt.Errorf("compliance.DetectHallucination: %w", err)
	}
	if resp == nil {
		slog.Warn("compliance.EntClientAdapter: DetectHallucination returned nil (ENT unavailable)",
			"tenant_id", tenantID, "agent_id", agentID)
		return nil, nil
	}

	slog.Debug("compliance.EntClientAdapter: DetectHallucination ok",
		"tenant_id", tenantID, "agent_id", agentID,
		"detected", resp.HallucinationDetected, "risk", resp.RiskLevel,
		"latency_ms", latency.Milliseconds(),
	)

	// Shallow copy is safe: HallucinationResponse contains only primitive value
	// types (string, float64, bool) — no slices, maps, or pointer fields.
	return &contracts.HallucinationResponse{
		HallucinationDetected: resp.HallucinationDetected,
		Confidence:            resp.Confidence,
		RiskLevel:             resp.RiskLevel,
		Entropy:               resp.Entropy,
		ContextSimilarity:     resp.ContextSimilarity,
		Explanation:           resp.Explanation,
		ModelVersion:          resp.ModelVersion,
		IsFallback:            resp.IsFallback,
	}, nil
}
