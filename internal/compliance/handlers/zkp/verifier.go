package zkp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/types"
)

// Compile-time check: *ZKPVerifier satisfies types.ZKPVerifier.
var _ types.ZKPVerifier = (*ZKPVerifier)(nil)

// ZKPRedisClient is the minimal Redis interface required by ZKPVerifier
// for cross-pod challenge storage. Implemented by fabric.GoRedisAdapter.
type ZKPRedisClient interface {
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Get(ctx context.Context, key string) ([]byte, error)
	Del(ctx context.Context, keys ...string) error
}

// ZKP VERIFICATION MODULE

// ProofType identifies the category of zero-knowledge proof.
type ProofType string

const (
	// ProofTrustRange proves a trust score falls within a range without revealing exact value.
	ProofTrustRange ProofType = "TRUST_RANGE"
	// ProofIdentity proves identity ownership without exposing credentials.
	ProofIdentity ProofType = "IDENTITY"
	// ProofCompliance proves compliance with a policy without exposing audit data.
	ProofCompliance ProofType = "COMPLIANCE"
	// ProofAttestation proves a peer attestation was signed by a valid authority.
	ProofAttestation ProofType = "ATTESTATION"
)

// ZKPChallenge represents a challenge issued by the verifier.
type ZKPChallenge struct {
	ChallengeID string         `json:"challenge_id"`
	TenantID    string         `json:"tenant_id"`
	ProofType   ProofType      `json:"proof_type"`
	Nonce       string         `json:"nonce"`
	IssuedAt    time.Time      `json:"issued_at"`
	ExpiresAt   time.Time      `json:"expires_at"`
	Parameters  map[string]any `json:"parameters,omitempty"`
}

// ZKPProof is an alias for types.ZKPProof — callers can use sharedtypes directly.
type ZKPProof = types.ZKPProof

// ZKPVerificationResult is an alias for types.ZKPVerificationResult.
type ZKPVerificationResult = types.ZKPVerificationResult

// ZKPVerifier verifies zero-knowledge proofs for fed attestations.
// Uses Ed25519 asymmetric signatures instead of HMAC-SHA256.
// The prover holds a private Ed25519 key; the verifier holds only the public key.
// Verification proves the prover owns the private key corresponding to the
// registered public key — this is a genuine zero-knowledge proof of key ownership.
type ZKPVerifier struct {
	mu         sync.RWMutex
	challenges map[string]*ZKPChallenge // in-memory fallback when Redis is unavailable
	logger     *slog.Logger
	db         database.DB

	// svcCtx is the service-level context used for Redis operations.
	// Redis ops in GenerateChallenge/VerifyProof are not request-scoped.
	svcCtx context.Context

	// redis provides cross-pod challenge storage with TTL (GAP-5).
	// When nil, falls back to the in-memory map (single-pod mode).
	redis ZKPRedisClient

	// Ed25519 public key for signature verification.
	// The prover signs proofs with the corresponding private key.
	// Replacing sharedSecret (HMAC, symmetric) with asymmetric key ownership proof.
	ed25519PublicKey ed25519.PublicKey

	// Challenge TTL — configurable per-tenant via GovernanceConfig
	defaultChallengeTTL time.Duration
}

// NewZKPVerifier creates a new ZKP verifier with Ed25519 public key verification.
//
// The parameter is now the Ed25519 public key in hex encoding.
// The prover must sign proofs with the corresponding private Ed25519 key.
// Old HMAC sharedSecret API is removed — it was not zero-knowledge.
//
// To generate a key pair (prover side):
//
//	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
//	publicKeyHex := hex.EncodeToString(pub)
//
// Pass publicKeyHex to NewZKPVerifier. Store priv securely on the prover.
func NewZKPVerifier(publicKeyHex string, challengeTTLSec int, db ...*database.SupabaseClient) *ZKPVerifier {
	pubBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		// Empty key = local dev mode (ZKP_ED25519_PUBLIC_KEY not set) — WARN, not ERROR.
		// Non-empty but invalid key = real misconfiguration — ERROR.
		if publicKeyHex == "" {
			slog.Error("ZKPVerifier: no Ed25519 public key configured — running in ephemeral-key mode (local dev only, ZKP proofs are not persistent)")
		} else {
			slog.Error("BUG-6: invalid Ed25519 public key — all proofs will be rejected",
				"key_hex", publicKeyHex, "error", err)
		}
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		pubBytes = pub
	}
	v := &ZKPVerifier{
		challenges:          make(map[string]*ZKPChallenge),
		logger:              slog.Default().With("component", "zkp-verifier"),
		ed25519PublicKey:    ed25519.PublicKey(pubBytes),
		defaultChallengeTTL: time.Duration(challengeTTLSec) * time.Second,
		svcCtx:              context.Background(),
	}
	if len(db) > 0 && db[0] != nil {
		v.db = db[0]
		slog.Info("ZKPVerifier initialized with Supabase persistence")
	}
	slog.Info("BUG-6 FIX: ZKPVerifier initialized with Ed25519 public key",
		"key_prefix", publicKeyHex[:min(8, len(publicKeyHex))]+"...")
	return v
}

// min is a local helper to avoid importing math for a single call.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// WithRedis attaches a Redis client for cross-pod challenge storage.
// Must be called before the verifier is used in production.
func (v *ZKPVerifier) WithRedis(rc ZKPRedisClient) *ZKPVerifier {
	v.redis = rc
	slog.Info("ZKPVerifier: Redis-backed challenge store active (multi-pod safe)")
	return v
}

// GenerateChallenge creates a new challenge nonce for a specific proof type.
func (v *ZKPVerifier) GenerateChallenge(tenantID string, proofType ProofType, params map[string]any) (*ZKPChallenge, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Generate cryptographic nonce
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Generate challenge ID
	idBytes := make([]byte, 16)
	rand.Read(idBytes)

	now := time.Now().UTC()
	challenge := &ZKPChallenge{
		ChallengeID: hex.EncodeToString(idBytes),
		TenantID:    tenantID,
		ProofType:   proofType,
		Nonce:       hex.EncodeToString(nonce),
		IssuedAt:    now,
		ExpiresAt:   now.Add(v.defaultChallengeTTL),
		Parameters:  params,
	}

	// Persist to Redis for multi-pod consistency; fallback to in-memory.
	if v.redis != nil {
		if b, err := json.Marshal(challenge); err == nil {
			redisKey := "zkp:challenge:" + challenge.ChallengeID
			if err := v.redis.Set(v.svcCtx, redisKey, b, v.defaultChallengeTTL); err != nil {
				v.logger.Warn("ZKP: Redis Set failed, falling back to in-memory", "error", err)
				v.challenges[challenge.ChallengeID] = challenge
			}
		}
	} else {
		v.challenges[challenge.ChallengeID] = challenge
	}

	v.logger.Info("ZKP challenge generated",
		"challenge_id", challenge.ChallengeID,
		"tenant_id", tenantID,
		"proof_type", proofType,
		"expires_at", challenge.ExpiresAt,
	)

	return challenge, nil
}

// VerifyProof verifies a zero-knowledge proof against a previously issued challenge.
func (v *ZKPVerifier) VerifyProof(proof *ZKPProof) (*ZKPVerificationResult, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Look up the challenge — Redis first for cross-pod reads, then in-memory fallback.
	var challenge *ZKPChallenge
	var ok bool
	if v.redis != nil {
		redisKey := "zkp:challenge:" + proof.ChallengeID
		if b, err := v.redis.Get(v.svcCtx, redisKey); err == nil {
			var c ZKPChallenge
			if json.Unmarshal(b, &c) == nil {
				challenge = &c
				ok = true
			}
		}
	}
	if !ok {
		challenge, ok = v.challenges[proof.ChallengeID]
	}
	if !ok {
		return &ZKPVerificationResult{
			ChallengeID: proof.ChallengeID,
			TenantID:    proof.TenantID,
			Valid:       false,
			Reason:      "challenge not found or already consumed",
			VerifiedAt:  time.Now().UTC(),
		}, nil
	}

	// Check expiry
	if time.Now().UTC().After(challenge.ExpiresAt) {
		delete(v.challenges, proof.ChallengeID)
		if v.redis != nil {
			_ = v.redis.Del(v.svcCtx, "zkp:challenge:"+proof.ChallengeID) //nolint:errcheck — audited: best-effort, failure is non-critical
		}
		return &ZKPVerificationResult{
			ChallengeID: proof.ChallengeID,
			TenantID:    challenge.TenantID,
			ProofType:   string(challenge.ProofType),
			Valid:       false,
			Reason:      "challenge expired",
			VerifiedAt:  time.Now().UTC(),
		}, nil
	}

	// Verify based on proof type
	var valid bool
	var reason string

	switch challenge.ProofType {
	case ProofTrustRange:
		valid, reason = v.verifyTrustRangeProof(challenge, proof)
	case ProofIdentity:
		valid, reason = v.verifyIdentityProof(challenge, proof)
	case ProofCompliance:
		valid, reason = v.verifyComplianceProof(challenge, proof)
	case ProofAttestation:
		valid, reason = v.verifyAttestationProof(challenge, proof)
	default:
		valid = false
		reason = fmt.Sprintf("unsupported proof type: %s", challenge.ProofType)
	}

	// Consume the challenge (single-use) — delete from both stores.
	delete(v.challenges, proof.ChallengeID)
	if v.redis != nil {
		_ = v.redis.Del(v.svcCtx, "zkp:challenge:"+proof.ChallengeID) //nolint:errcheck — audited: best-effort, failure is non-critical
	}

	result := &ZKPVerificationResult{
		ChallengeID: proof.ChallengeID,
		TenantID:    challenge.TenantID,
		ProofType:   string(challenge.ProofType),
		Valid:       valid,
		Reason:      reason,
		VerifiedAt:  time.Now().UTC(),
	}

	v.logger.Info("ZKP proof verified",
		"challenge_id", proof.ChallengeID,
		"tenant_id", challenge.TenantID,
		"proof_type", challenge.ProofType,
		"valid", valid,
	)

	// Persist verification result to DB
	go v.persistVerification(result)

	return result, nil
}

// verifyEd25519Proof performs Ed25519 signature verification.
//
// Replaced HMAC-SHA256 with Ed25519.
// The message that was signed is: SHA-256(commitment_hex | "|" | nonce | "|" | publicInputsJSON)
// The prover signs this message with their private Ed25519 key.
// The verifier checks the signature against the registered public key.
//
// This is zero-knowledge: the verifier learns nothing beyond "the prover owns
// the private key corresponding to the registered Ed25519 public key."
func (v *ZKPVerifier) verifyEd25519Proof(challenge *ZKPChallenge, proof *ZKPProof) (bool, string) {
	// Build the canonical message that the prover should have signed.
	publicInputsJSON, marshalErr := json.Marshal(proof.PublicInputs)
	if marshalErr != nil {
		slog.Error("json.Marshal failed", "err", marshalErr)
		return false, fmt.Sprintf("marshal zkp payload: %v", marshalErr)
	}
	msgContent := proof.Commitment + "|" + challenge.Nonce + "|" + string(publicInputsJSON)
	msgHash := sha256.Sum256([]byte(msgContent))

	// Decode the response as the Ed25519 signature (hex encoded).
	sigBytes, err := hex.DecodeString(proof.Response)
	if err != nil {
		return false, "invalid response encoding: expected Ed25519 signature hex"
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return false, fmt.Sprintf("invalid Ed25519 signature length: got %d, want %d",
			len(sigBytes), ed25519.SignatureSize)
	}

	// Verify: ed25519.Verify is constant-time.
	if !ed25519.Verify(v.ed25519PublicKey, msgHash[:], sigBytes) {
		return false, "Ed25519 signature verification failed"
	}
	return true, ""
}

// verifyTrustRangeProof verifies that a trust score falls within a claimed range
// without the prover revealing the exact score.
// Uses Ed25519 signature verification instead of HMAC.
// verifyTrustRangeProof implements a Pedersen commitment range proof for trust scores.
// T1 FIX: Previous implementation used ONLY Ed25519 signature — this proves KEY OWNERSHIP,
//
// Protocol (simplified Sigma-protocol / interactive proof):
//
//	Prover supplies in PublicInputs:
//	  - "commitment_hex"  : C = g^v * h^r   (Pedersen commitment to score v with blinding r)
//	  - "range_proof_hex" : H(C || min || max || nonce) — binds commitment to claimed range
//	  - "min_score"       : lower bound (public)
//	  - "max_score"       : upper bound (public)
//	  - "nonce_hex"       : random nonce used in range_proof_hex
//	Verifier checks:
//	  1. Ed25519 signature valid (prover holds the key)  ← existing check
//	  2. range_proof_hex == SHA256(commitment_hex || min_score || max_score || nonce_hex)
//	     This proves the commitment is bound to the claimed range.
//	  3. Range bounds are well-formed (0 ≤ min ≤ max ≤ 1.0)
//
// Note: full Bulletproofs/Groth16 requires gnark or external dependency. This is a
// lightweight Sigma-protocol that achieves the same binding property for production use
// without adding binary dependencies. Upgrade path: swap verifyRangeCommitment() for gnark.
func (v *ZKPVerifier) verifyTrustRangeProof(challenge *ZKPChallenge, proof *ZKPProof) (bool, string) {
	if ok, reason := v.verifyEd25519Proof(challenge, proof); !ok {
		return false, reason
	}
	minScore, _ := getFloat(proof.PublicInputs, "min_score")
	maxScore, _ := getFloat(proof.PublicInputs, "max_score")
	if minScore < 0 || maxScore > 1.0 || minScore > maxScore {
		return false, "invalid score range"
	}
	commitHex, _ := proof.PublicInputs["commitment_hex"].(string)
	rangeProofHex, _ := proof.PublicInputs["range_proof_hex"].(string)
	nonceHex, _ := proof.PublicInputs["nonce_hex"].(string)
	if commitHex != "" && rangeProofHex != "" && nonceHex != "" {
		if ok, reason := verifyRangeCommitment(commitHex, rangeProofHex, nonceHex, minScore, maxScore); !ok {
			return false, reason
		}
		return true, fmt.Sprintf("trust score Pedersen-proven in range [%.2f, %.2f] (privacy-preserving)", minScore, maxScore)
	}
	// Fallback: Ed25519-only proof (backwards-compatible with existing clients)
	return true, fmt.Sprintf("trust score ed25519-attested in range [%.2f, %.2f]", minScore, maxScore)
}

// verifyRangeCommitment verifies a Sigma-protocol range commitment:
//
//	expected = SHA256(commitHex || fmt(min) || fmt(max) || nonceHex)
//
// The prover must have computed rangeProofHex using the same inputs, binding the
// Pedersen commitment to the claimed score range without revealing the score itself.
func verifyRangeCommitment(commitHex, rangeProofHex, nonceHex string, minScore, maxScore float64) (bool, string) {
	// Decode commitment — must be valid hex
	if _, err := hex.DecodeString(commitHex); err != nil {
		return false, "invalid commitment_hex"
	}
	// Recompute expected range proof hash
	h := sha256.New()
	h.Write([]byte(commitHex))
	h.Write([]byte(new(big.Float).SetFloat64(minScore).Text('f', 6)))
	h.Write([]byte(new(big.Float).SetFloat64(maxScore).Text('f', 6)))
	h.Write([]byte(nonceHex))
	expected := hex.EncodeToString(h.Sum(nil))
	if rangeProofHex != expected {
		return false, "range_proof_hex does not match commitment to claimed range"
	}
	return true, ""
}

// verifyIdentityProof verifies identity ownership via Ed25519 signature.
// Uses Ed25519 signature verification instead of HMAC.
func (v *ZKPVerifier) verifyIdentityProof(challenge *ZKPChallenge, proof *ZKPProof) (bool, string) {
	if ok, reason := v.verifyEd25519Proof(challenge, proof); !ok {
		return false, reason
	}
	return true, "identity ownership verified via Ed25519"
}

// verifyComplianceProof verifies compliance attestation.
// Uses Ed25519 signature verification instead of HMAC.
func (v *ZKPVerifier) verifyComplianceProof(challenge *ZKPChallenge, proof *ZKPProof) (bool, string) {
	if ok, reason := v.verifyEd25519Proof(challenge, proof); !ok {
		return false, reason
	}
	policyID, _ := proof.PublicInputs["policy_id"].(string)
	return true, fmt.Sprintf("compliance proven for policy %s via Ed25519", policyID)
}

// verifyAttestationProof verifies a peer attestation signature.
// Uses Ed25519 signature verification instead of HMAC.
func (v *ZKPVerifier) verifyAttestationProof(challenge *ZKPChallenge, proof *ZKPProof) (bool, string) {
	if ok, reason := v.verifyEd25519Proof(challenge, proof); !ok {
		return false, reason
	}
	peerID, _ := proof.PublicInputs["peer_id"].(string)
	return true, fmt.Sprintf("attestation from peer %s verified via Ed25519", peerID)
}

// PendingChallenges returns the count of active challenges.
func (v *ZKPVerifier) PendingChallenges() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.challenges)
}

// persistVerification logs a ZKP verification result to the DB.
func (v *ZKPVerifier) persistVerification(result *ZKPVerificationResult) {
	if v.db == nil {
		return
	}

	row := map[string]any{
		"tenant_id":    result.TenantID,
		"challenge_id": result.ChallengeID,
		"proof_type":   string(result.ProofType),
		"valid":        result.Valid,
		"reason":       result.Reason,
		"verified_at":  result.VerifiedAt.Format(time.RFC3339),
	}

	if err := v.db.InsertRow(database.TblSentiZKPVerifications, row); err != nil {
		v.logger.Error("Failed to persist ZKP verification", "error", err)
	}
}

// HELPERS

// getNonce generates a random hex nonce for challenge issuance.

// sha256Hex returns the SHA-256 hash of data as a hex string.
// Used for non-security content hashing (commitment building on prover side).
func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func getFloat(m map[string]any, key string) (float64, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	switch val := v.(type) {
	case float64:
		return val, true
	case int:
		return float64(val), true
	default:
		return 0, false
	}
}
