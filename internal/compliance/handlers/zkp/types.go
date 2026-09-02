// Package zkp — named request and row types (Zero-Knowledge Proofs).
package zkp

// ZKPProofRequest is the body for POST /zkp/prove.
type ZKPProofRequest struct {
	AgentID	string	`json:"agent_id" validate:"required"`
	ClaimType string `json:"claim_type"` // trust_score | policy_compliance | identity
	Period    string `json:"period,omitempty"`
}

// ZKPVerifyRequest is the body for POST /zkp/verify.
type ZKPVerifyRequest struct {
	ProofID    string `json:"proof_id"`
	VerifierID string `json:"verifier_id"`
}

// ZKPBatchRow is the DB projection for ZKP batch operation reads.
type ZKPBatchRow struct {
	ID         string `json:"id"`
	TenantID   string `json:"tenant_id"`
	AgentID    string `json:"agent_id"`
	ClaimType  string `json:"claim_type"`
	ProofHash  string `json:"proof_hash"`
	IsVerified bool   `json:"is_verified"`
	CreatedAt  string `json:"created_at"`
}

// GenerateZKPProofRequest is the request body for HandleGenerateZKPProof. (8 fields)
type GenerateZKPProofRequest struct {
	ProofType string         `json:"proof_type"`
	AgentID	string	`json:"agent_id" validate:"required"`
	ClaimData map[string]any `json:"claim_data"`
	Expiry    string         `json:"expiry,omitempty"`
	ReportID string `json:"report_id,omitempty"`
	// Actor chain FKs
	IntentID    string `json:"intent_id,omitempty"`
	ActivityID  string `json:"activity_id,omitempty"`
	ExecutionID string `json:"execution_id,omitempty"`

	// One of PrivateKey or SchnorrProof must be provided:
	//   - PrivateKey: agent's P-256 secret scalar (hex). Server generates Schnorr proof.
	//     MUST be sent over mTLS only. Never persisted.
	//   - SchnorrProof: pre-generated Schnorr proof (client-side generation preferred).
	//     Server verifies the proof before persisting.
	PrivateKey   string        `json:"private_key,omitempty"`   // secret — mTLS only, never stored
	SchnorrProof *SchnorrProof `json:"schnorr_proof,omitempty"` // pre-generated client-side
}

// VerifyZKPRequest is the request body for HandleVerifyZKP. (9 fields)
type VerifyZKPRequest struct {
	AgentID	string	`json:"agent_id" validate:"required"`
	ProofType   string   `json:"proof_type"`
	Commitment  string   `json:"commitment"`
	ProofBytes  string   `json:"proof_bytes"`
	ChallengeID string   `json:"challenge_id"`
	Properties  []string `json:"properties"`
	// Actor chain FKs
	IntentID    string `json:"intent_id,omitempty"`
	ActivityID  string `json:"activity_id,omitempty"`
	ExecutionID string `json:"execution_id,omitempty"`
}
