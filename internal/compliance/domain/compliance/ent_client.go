// Package compliance provides the Go gRPC client for the Python ENT
// (Embedding-based Narrative Trust) service.
//
// ENT powers Phase 1A: hallucination detection (Shannon entropy + cosine
// similarity) and intent validation (cosine similarity + keyword contradiction).
//
// ENT_GRPC_ADDR must be set to the Python pod's internal address.
// Fail-open: if ENT is unreachable, DetectHallucination returns
// hallucination_detected=false (LOW risk) so the gate does not block
// legitimate traffic during a Python pod restart.
package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/ocx/shared/infra/security"
	"github.com/ocx/shared/types"
	"google.golang.org/grpc"
)

// ── Request / Response wire types (match aocs_ent.proto) ─────────────────────

// EntHallucinationRequest maps to the proto EntHallucinationRequest message.
type EntHallucinationRequest struct {
	LLMOutput string `json:"llm_output"`
	Context   string `json:"context"`
	AgentID	string	`json:"agent_id" validate:"required"`
	TenantID	string	`json:"tenant_id" validate:"required"`
}

// EntHallucinationResponse maps to the proto EntHallucinationResponse message.
type EntHallucinationResponse struct {
	HallucinationDetected bool    `json:"hallucination_detected"`
	Confidence            float64 `json:"confidence"`
	RiskLevel             string  `json:"risk_level"` // LOW | MEDIUM | HIGH
	Entropy               float64 `json:"entropy"`
	ContextSimilarity     float64 `json:"context_similarity"`
	Explanation           string  `json:"explanation"`
	ModelVersion          string  `json:"model_version"`
	IsFallback            bool    `json:"is_fallback,omitempty"`
}

// EntIntentRequest maps to the proto EntIntentRequest message.
type EntIntentRequest struct {
	StatedIntent string `json:"stated_intent"`
	ActualAction string `json:"actual_action"`
	AgentID	string	`json:"agent_id" validate:"required"`
	TenantID	string	`json:"tenant_id" validate:"required"`
}

// EntIntentResponse maps to the proto EntIntentResponse message.
type EntIntentResponse struct {
	IsValid               bool    `json:"is_valid"`
	Similarity            float64 `json:"similarity"`
	ContradictionDetected bool    `json:"contradiction_detected"`
	Threshold             float64 `json:"threshold"`
	Explanation           string  `json:"explanation"`
	IsFallback            bool    `json:"is_fallback,omitempty"`
}

// EntClient wraps a gRPC connection to the Python ENT service.
type EntClient struct {
	conn   *grpc.ClientConn
	addr   string
	logger *slog.Logger
}

// NewEntClient dials the ENT gRPC service at addr.
// Returns an error if addr is empty — callers must configure ENT_GRPC_ADDR.
// Uses security.Dial for OTEL instrumentation + keepalive + retry policy
// (matches cvic, escrow, and traffic client pattern — WIRE-GAP-09).
func NewEntClient(addr string) (*EntClient, error) {
	if addr == "" {
		return nil, fmt.Errorf("ENT gRPC address not configured — set ENT_GRPC_ADDR env var")
	}

	conn, err := security.Dial(addr)
	if err != nil {
		return nil, fmt.Errorf("ENT gRPC client creation failed (%s): %w", addr, err)
	}

	return &EntClient{
		conn:   conn,
		addr:   addr,
		logger: slog.Default().With("component", "ent-client"),
	}, nil
}

// Close shuts down the gRPC connection.
func (e *EntClient) Close() error {
	if e.conn != nil {
		return e.conn.Close()
	}
	return nil
}

// DetectHallucination calls the ENT DetectHallucination RPC (Phase 1A).
// On failure, returns a safe fallback (hallucination_detected=false, LOW risk)
// so the gate does not block traffic during ENT pod restarts.
func (e *EntClient) DetectHallucination(
	ctx context.Context,
	llmOutput, contextText, agentID, tenantID string,
) (*EntHallucinationResponse, error) {
	req := &EntHallucinationRequest{
		LLMOutput: llmOutput,
		Context:   contextText,
		AgentID:   agentID,
		TenantID:  tenantID,
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ENT DetectHallucination request: %w", err)
	}

	var respBytes []byte
	err = e.conn.Invoke(ctx, "/aocs.ent.EntService/DetectHallucination", reqBytes, &respBytes)
	if err != nil {
		// FIX-HALL-01: Previously fail-open returned hallucination_detected=false/LOW regardless
		// of content, making the stage entirely useless when ENT is down (common in dev/staging).
		// Now: run the local rule-based scorer as a fallback so obvious patterns are caught
		// even without the ML service. IsFallback=true signals the audit dashboard that the
		// score came from the local scorer, not the full ML pipeline.
		e.logger.Warn("ENT DetectHallucination RPC failed — using local rule-based fallback scorer",
			"error", err, "addr", e.addr, "agent_id", agentID)
		return localHallucinationScore(llmOutput, contextText, agentID), nil
	}

	var resp EntHallucinationResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ENT DetectHallucination response: %w", err)
	}

	e.logger.Info("ENT hallucination check complete",
		"agent_id", agentID,
		"detected", resp.HallucinationDetected,
		"risk_level", resp.RiskLevel,
		"confidence", resp.Confidence,
	)

	return &resp, nil
}

// ValidateIntent calls the ENT ValidateIntent RPC.
// On failure, returns a safe fallback (is_valid=true) — fail-open.
func (e *EntClient) ValidateIntent(
	ctx context.Context,
	statedIntent, actualAction, agentID, tenantID string,
) (*EntIntentResponse, error) {
	req := &EntIntentRequest{
		StatedIntent: statedIntent,
		ActualAction: actualAction,
		AgentID:      agentID,
		TenantID:     tenantID,
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ENT ValidateIntent request: %w", err)
	}

	var respBytes []byte
	err = e.conn.Invoke(ctx, "/aocs.ent.EntService/ValidateIntent", reqBytes, &respBytes)
	if err != nil {
		e.logger.Warn("ENT ValidateIntent RPC failed — fail-open (intent valid)",
			"error", err, "addr", e.addr, "agent_id", agentID)
		return &EntIntentResponse{
			IsValid:    true,
			IsFallback: true,
		}, nil
	}

	var resp EntIntentResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ENT ValidateIntent response: %w", err)
	}

	e.logger.Info("ENT intent validation complete",
		"agent_id", agentID,
		"is_valid", resp.IsValid,
		"similarity", resp.Similarity,
		"contradiction", resp.ContradictionDetected,
	)

	return &resp, nil
}

// ── APE Extraction (Model Gateway) ───────────────────────────────────────────
// All Gemini / LLM calls go through the Python ENT service.
// Go never calls Gemini directly — this enables model switching, cost
// tracking, and prompt versioning without rebuilding Go binaries.

// Type aliases — re-exported from aocs-shared/types so *EntClient satisfies
// types.APEExtractor without a cross-domain import in callers.
type EntExtractIntentsRequest = types.APEExtractRequest
type EntExtractedIntent = types.APEExtractedIntent
type EntExtractedPolicy = types.APEExtractedPolicy
type EntExtractedGoal = types.APEExtractedGoal
type EntExtractedConflict = types.APEExtractedConflict
type EntExtractIntentsResponse = types.APEExtractResponse

// Compile-time check: *EntClient must satisfy types.APEExtractor.
var _ types.APEExtractor = (*EntClient)(nil)

// ExtractIntents calls the Python ENT service to run Gemini-powered APE
// extraction on the given document content.
// On failure, returns an empty (fallback) result — fail-open so the wizard
// still functions when the Python pod is restarting.
func (e *EntClient) ExtractIntents(
	ctx context.Context,
	req *EntExtractIntentsRequest,
) (*EntExtractIntentsResponse, error) {
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ENT ExtractIntents request: %w", err)
	}

	var respBytes []byte
	err = e.conn.Invoke(ctx, "/aocs.ent.EntService/ExtractIntents", reqBytes, &respBytes)
	if err != nil {
		e.logger.Warn("ENT ExtractIntents RPC failed — fail-open (empty extraction)",
			"error", err, "addr", e.addr)
		return &EntExtractIntentsResponse{
			Summary:    "",
			Intents:    []EntExtractedIntent{},
			Policies:   []EntExtractedPolicy{},
			Goals:      []EntExtractedGoal{},
			Conflicts:  []EntExtractedConflict{},
			IsFallback: true,
		}, nil
	}

	var resp EntExtractIntentsResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ENT ExtractIntents response: %w", err)
	}

	e.logger.Info("ENT APE extraction complete",
		"intents", len(resp.Intents),
		"policies", len(resp.Policies),
		"conflicts", len(resp.Conflicts),
		"model", resp.ModelVersion,
	)
	return &resp, nil
}
