// Package handlers — ZKP (Zero-Knowledge Proof) verification endpoints.
//
// Provides read-only access to ZKP verification records stored in the
// zkp_verifications table. Supports listing, getting by ID, and stats.
// HandleVerifyZKP now accepts an optional *fed.ZKPVerifier for real
// cryptographic proof validation with Redis-backed multi-pod safe storage.
package zkp

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/config"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
	"github.com/ocx/shared/types"
)

// POST /api/v1/zkp/proofs
//
// When verifier is non-nil, uses real ZKPVerifier domain logic with
// Redis-backed multi-pod-safe challenge storage.
// When verifier is nil (degraded/local), falls back to structural validation.
func HandleVerifyZKP(db database.DB, verifier types.ZKPVerifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if tenantID == "" {
			if config.Get().IsDevelopment() {
				// if the JWT claim is missing. Guard explicitly so dev ZKP proofs
				// cannot be stored against an empty tenant (cross-tenant data leak).
				tenantID, _ = auth.GetTenantID(r.Context())
				if tenantID == "" {
					slog.Warn("ZKP proof rejected: empty tenant_id in dev mode — check JWT claims")
					respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized, "missing tenant_id")
					return
				}
			} else {
				respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized, "missing tenant_id")
				return
			}
		}

		var req VerifyZKPRequest
		respond.LimitBody(r)
		if !validate.Bind(w, r, &req) {
			return
		}
		if req.AgentID == "" || req.Commitment == "" || req.ProofBytes == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "agent_id, commitment, and proof_bytes are required")
			return
		}

		verificationID := fmt.Sprintf("zkp-%d", time.Now().UnixNano())
		isValid := false
		detail := "structural-only"

		if verifier != nil && req.ChallengeID != "" {
			// Real cryptographic path — uses Redis-backed challenge store (multi-pod safe).
			result, err := verifier.VerifyProof(&types.ZKPProof{
				ChallengeID:  req.ChallengeID,
				TenantID:     tenantID,
				Commitment:   req.Commitment,
				Response:     req.ProofBytes,
				PublicInputs: map[string]any{"agent_id": req.AgentID, "proof_type": req.ProofType},
			})
			if err != nil {
				slog.Error("ZKP domain verification error", "err", err, "agent", req.AgentID)
				// Fall through to structural check — do not hard-fail the request.
				isValid = len(req.ProofBytes) > 10 && req.Commitment != ""
				detail = "structural-only (domain error: " + err.Error() + ")"
			} else {
				isValid = result.Valid
				detail = result.Reason
				verificationID = fmt.Sprintf("zkp-%s", result.ChallengeID)
			}
		} else {
			// Degraded path — structural validation only (no challenge presented or verifier unavailable).
			isValid = len(req.ProofBytes) > 10 && req.Commitment != ""
			if verifier == nil {
				detail = "structural-only (verifier not initialised)"
			} else {
				detail = "structural-only (no challenge_id provided)"
			}
		}

		slog.Info("ZKP Verification", "id", verificationID, "agent", req.AgentID, "type", req.ProofType, "valid", isValid, "detail", detail)

		// Map proof_type to schema CHECK values
		proofType := req.ProofType
		switch proofType {
		case "TRUST_RANGE", "IDENTITY", "COMPLIANCE", "ATTESTATION":
			// valid
		default:
			proofType = "COMPLIANCE"
		}

		challengeID := req.ChallengeID
		if challengeID == "" {
			challengeID = verificationID // structural-only path: use generated ID
		}

		record := database.SentiZKPVerification{
			TenantID:    tenantID,
			AgentID:     &req.AgentID,
			ProofType:   proofType,
			Valid:       isValid,
			ChallengeID: challengeID,
			Reason:      &detail,
			PublicInputs: map[string]any{
				"agent_id":   req.AgentID,
				"commitment": req.Commitment,
				"properties": req.Properties,
			},
			IssuedAt:   time.Now().UTC().Format(time.RFC3339),
			VerifiedAt: time.Now().UTC().Format(time.RFC3339),
		}
		if req.IntentID != "" {
			record.IntentID = &req.IntentID
		}
		if req.ActivityID != "" {
			record.ActivityID = &req.ActivityID
		}
		if req.ExecutionID != "" {
			record.ExecutionID = &req.ExecutionID
		}

		// challenge_id is the natural idempotency key: each challenge is single-use.
		// If a record for (tenant_id, challenge_id) already exists, return 409 Conflict
		// to prevent a replayed proof from being recorded as a second valid verification.
		if challengeID != "" && challengeID != verificationID {
			var existing []database.SentiZKPVerification
			if err := db.QueryRowsCompound(database.TblSentiZKPVerifications, database.Meta[database.TblSentiZKPVerifications],
				"tenant_id", tenantID, "challenge_id", challengeID, &existing); err == nil && len(existing) > 0 {
				slog.Warn("ZKP replay blocked — challenge_id already consumed",
					"challenge_id", challengeID, "tenant_id", tenantID, "agent_id", req.AgentID)
				respond.ErrorWithCode(w, http.StatusConflict, respond.ErrCodeConflict,
					"proof already submitted for this challenge_id — each challenge is single-use")
				return
			}
		}

		if err := db.InsertRow(database.TblSentiZKPVerifications, record); err != nil {
			slog.Error("Failed to persist ZKP verification", "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "persist zkp verification", err)
			return
		}

		// so the compliance UI can render a precise hash diff instead of a generic message.
		resp := map[string]any{
			"verification_id": verificationID,
			"valid":           isValid,
			"reason":          detail,
			"public_inputs":   req.Commitment,
		}
		if !isValid {
			// expected_hash = the commitment the client declared (what the proof should cover)
			// got_hash = the proof_bytes the client submitted (what was actually received)
			// Together these let a compliance officer diff what was expected vs what arrived.
			if req.Commitment != "" {
				resp["expected_hash"] = req.Commitment
			}
			if req.ProofBytes != "" {
				resp["got_hash"] = req.ProofBytes
			}
		}
		respond.JSON(w, http.StatusOK, resp)
	}
}

// LIST ZKP VERIFICATIONS

// HandleListZKPVerifications returns all ZKP verifications for the tenant.
// GET /api/v1/zkp/verifications
// No ?limit — 90-day window is the boundary; frontend paginates in-memory.
// Optional semantic filters: ?proof_type=TRUST_RANGE, ?valid=true|false
// Extend history: ?from=RFC3339&to=RFC3339 (refine search)
func HandleListZKPVerifications(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if tenantID == "" {
			if config.Get().IsDevelopment() {
				tenantID, _ = auth.GetTenantID(r.Context())
				if tenantID == "" {
					slog.Warn("ZKP list rejected: empty tenant_id in dev mode — check JWT claims")
					respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized, "missing tenant_id")
					return
				}
			} else {
				respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized, "missing tenant_id")
				return
			}
		}

		// Semantic filters (not pagination) — narrow by proof type or validity
		proofType := r.URL.Query().Get("proof_type")
		validOnly := r.URL.Query().Get("valid")
		from := r.URL.Query().Get("from")
		to := r.URL.Query().Get("to")

		var rawRows []database.SentiZKPVerification
		if from != "" || to != "" {
			if _dbErr := db.QueryRowsWithWindow(database.TblSentiZKPVerifications, database.ColsSentiZkpVerifications, tenantID, from, to, &rawRows); _dbErr != nil {
				slog.Error("db operation failed", "method", "QueryRowsWithWindow", "error", _dbErr)
			}
		} else {
			if _dbErr := db.QueryRowsWithin90Days(database.TblSentiZKPVerifications, database.ColsSentiZkpVerifications, tenantID, &rawRows); _dbErr != nil {
				slog.Error("db operation failed", "method", "QueryRowsWithin90Days", "error", _dbErr)
			}
		}

		out := make([]database.SentiZKPVerification, 0, len(rawRows))
		for _, row := range rawRows {
			if proofType != "" && row.ProofType != proofType {
				continue
			}
			if validOnly == "true" && !row.Valid {
				continue
			} else if validOnly == "false" && row.Valid {
				continue
			}
			out = append(out, row)
		}

		respond.JSON(w, http.StatusOK, map[string]any{
			"verifications": out,
			"count":         len(out),
		})
	}
}

// GET SINGLE ZKP VERIFICATION

// HandleGetZKPVerification returns a single ZKP verification by ID.
// GET /api/v1/zkp/verifications/{id}
func HandleGetZKPVerification(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if tenantID == "" {
			if config.Get().IsDevelopment() {
				tenantID, _ = auth.GetTenantID(r.Context())
				if tenantID == "" {
					slog.Warn("ZKP get rejected: empty tenant_id in dev mode — check JWT claims")
					respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized, "missing tenant_id")
					return
				}
			} else {
				respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized, "missing tenant_id")
				return
			}
		}

		id := mux.Vars(r)["id"]
		if id == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "Verification ID required")
			return
		}

		var rows []database.SentiZKPVerification
		err := db.QueryRowsCompound(database.TblSentiZKPVerifications, database.ColsSentiZkpVerifications, database.Meta[database.TblSentiZKPVerifications], id, "tenant_id", tenantID, &rows)
		if err != nil || len(rows) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "ZKP verification not found")
			return
		}

		respond.JSON(w, http.StatusOK, rows[0])
	}
}

// GET /api/v1/zkp/stats

// HandleGetZKPStats returns aggregate statistics for ZKP verifications.
func HandleGetZKPStats(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var rows []database.SentiZKPVerification
		if _dbErr := db.QueryRowsWithin90Days(database.TblSentiZKPVerifications, database.ColsSentiZkpVerifications, tenantID, &rows); _dbErr != nil {
			slog.Error("db operation failed", "method", "QueryRowsWithin90Days", "error", _dbErr)
		}

		type TypeStat struct{ Total, Valid, Invalid int }
		byType := map[string]*TypeStat{}
		totalValid, totalInvalid := 0, 0
		for _, row := range rows {
			pt := row.ProofType
			if byType[pt] == nil {
				byType[pt] = &TypeStat{}
			}
			byType[pt].Total++
			if row.Valid {
				byType[pt].Valid++
				totalValid++
			} else {
				byType[pt].Invalid++
				totalInvalid++
			}
		}
		byTypeOut := make([]map[string]any, 0, len(byType))
		for pt, s := range byType {
			byTypeOut = append(byTypeOut, map[string]any{"proof_type": pt, "total": s.Total, "valid": s.Valid, "invalid": s.Invalid})
		}
		respond.JSON(w, http.StatusOK, map[string]any{
			"total": len(rows), "valid": totalValid, "invalid": totalInvalid,
			"by_type": byTypeOut, "tenant_id": tenantID,
		})
	}
}
