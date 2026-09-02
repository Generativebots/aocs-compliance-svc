// Package jury provides a Go gRPC client for the Python Jury Auditor service.
// The Jury performs cognitive auditing of agt intents against policy.
package compliance

// AuditRequest mirrors proto/jury_pb2.AuditRequest.
// Uses JSON wire format matching the Python hand-written proto stubs.
type AuditRequest struct {
	TransactionID string         `json:"transaction_id"`
	AgentID	string	`json:"agent_id" validate:"required"`
	ToolName      string         `json:"tool_name"`
	Parameters    map[string]any `json:"parameters"`
	Context       map[string]any `json:"context"`
	RawPayload    string         `json:"raw_payload,omitempty"`
}

// AuditResponse mirrors proto/jury_pb2.AuditResponse.
type AuditResponse struct {
	TransactionID  string  `json:"transaction_id"`
	Verdict        string  `json:"verdict"`         // ALLOW, DENY (UNKNOWN is deprecated — mapped to DENY fail-closed)
	Confidence     float64 `json:"confidence"`      // 0.0–1.0
	Reason         string  `json:"reason"`
	AuditTime      float64 `json:"audit_time"`      // seconds
	// fall back to gc.TrustScore. Now the Jury Assess gRPC response (0-1 scale, fixed in assess.py)
	// is propagated into gate context for CEL rule evaluation and audit records.
	CognitiveScore float64 `json:"cognitive_score"` // 0.0–1.0 normalized from Python assess.py
	// IsFallback is true when the verdict was produced locally due to Jury unavailability.
	// Callers can use this to emit alerts / increment fallback counters.
	IsFallback     bool    `json:"is_fallback,omitempty"`
}
