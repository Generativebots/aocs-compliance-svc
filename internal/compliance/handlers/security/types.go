// Package security — named request and row types.
// Note: DLPScanRequest and related DLP types are declared in dlp_types.go.
// This file contains additional security-specific request/row types.
package security

// ThreatMitigationRequest is the body for POST /security/threats/:id/mitigate.
type ThreatMitigationRequest struct {
	Action	string	`json:"action" validate:"required"`	// BLOCK | QUARANTINE | ALERT | DISMISS
	Reason	string	`json:"reason" validate:"required"`
}

// EntropyAnalysisRow is the DB projection for entropy analysis reads.
type EntropyAnalysisRow struct {
	ID           string  `json:"id"`
	TenantID     string  `json:"tenant_id"`
	AgentID      string  `json:"agent_id"`
	EntropyScore float64 `json:"entropy_score"`
	RiskLevel    string  `json:"risk_level"` // LOW | MEDIUM | HIGH | CRITICAL
	AnalyzedAt   string  `json:"analyzed_at"`
}

// CreateEntropyEventRequest is the request body for HandleCreateEntropyEvent. (6 fields)
type CreateEntropyEventRequest struct {
	AgentID	string	`json:"agentId" validate:"required"`
	VarianceScore float64 `json:"varianceScore"`
	// Actor chain FKs
	IntentID    string `json:"intent_id,omitempty"`
	ActivityID  string `json:"activity_id,omitempty"`
	ExecutionID string `json:"execution_id,omitempty"`
	ProcessID   string `json:"process_id,omitempty"`
}

// NonceValidateRequest is the request body for HandleValidateNonce. (3 fields)
type NonceValidateRequest struct {
	Nonce    string `json:"nonce"`
	AgentID	string	`json:"agent_id" validate:"required"`
	TenantID	string	`json:"tenant_id" validate:"required"`
}
