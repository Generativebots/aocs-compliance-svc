// Package evaluation — named request and row types.
package evaluation

import "encoding/json"

// EvidenceCreateRequest is the body for POST /evaluation/evidence.
type EvidenceCreateRequest struct {
	AgentID	string	`json:"agent_id" validate:"required"`
	ExecutionID	string	`json:"execution_id" validate:"required"`
	EvidenceType string          `json:"evidence_type"` // output | audit | compliance
	Content      json.RawMessage `json:"content"`
	HashAlgo     string          `json:"hash_algo,omitempty"` // sha256 (default)
}

// VaultRow is the DB projection for evidence vault reads.
type VaultRow struct {
	ID           string `json:"id"`
	TenantID     string `json:"tenant_id"`
	AgentID      string `json:"agent_id"`
	ExecutionID  string `json:"execution_id"`
	EvidenceType string `json:"evidence_type"`
	ContentHash  string `json:"content_hash"`
	StoredAt     string `json:"stored_at"`
}

// CreateEvidenceRequest is the request body for HandleCreateEvidence. (10 fields)
type CreateEvidenceRequest struct {
	Type	string	`json:"type" validate:"required"`	// NOT NULL
	ActionClass string         `json:"action_class,omitempty"`
	ToolID      string         `json:"tool_id,omitempty"`
	TransID     string         `json:"transaction_id,omitempty"`
	Timestamp   string         `json:"timestamp,omitempty"`
	PayloadData map[string]any `json:"payload_data,omitempty"`
	// Governance actor chain FKs — UI sends from localStorage
	AgentID     string `json:"agent_id,omitempty"`
	IntentID    string `json:"intent_id,omitempty"`
	ActivityID  string `json:"activity_id,omitempty"`
	ExecutionID string `json:"execution_id,omitempty"`
}
