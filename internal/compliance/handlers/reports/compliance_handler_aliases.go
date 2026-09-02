// Package analytics — cross-package handler aliases for test compatibility.
//
// These forwarding functions re-export handlers from their canonical packages
// (evaluation, zkp) into the analytics package scope, so integration tests
// in package analytics can call them without import path changes.
//
// This is the ONLY alias file permitted. See handler_aliases.go deletion note.
package reports

import (
	"net/http"

	"github.com/ocx/compliance/internal/compliance/handlers/zkp"
	"github.com/ocx/compliance/internal/compliance/handlers/evidence"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/types"
)

// ── Evidence (canonical: handlers/evaluation) ────────────────────────────────

func HandleListEvidence(db database.DB) http.HandlerFunc {
	return evaluation.HandleListEvidence(db)
}

func HandleCreateEvidence(db database.DB) http.HandlerFunc {
	return evaluation.HandleCreateEvidence(db)
}

func HandleGetEvidence(db database.DB) http.HandlerFunc {
	return evaluation.HandleGetEvidence(db)
}

func HandleAttestEvidence(db database.DB) http.HandlerFunc {
	return evaluation.HandleAttestEvidence(db)
}

func HandleListEvidenceAttestations(db database.DB) http.HandlerFunc {
	return evaluation.HandleListEvidenceAttestations(db)
}

func HandleGetEvidenceChainByID(db database.DB) http.HandlerFunc {
	return evaluation.HandleGetEvidenceChainByID(db)
}

// ── ZKP (canonical: handlers/zkp) ────────────────────────────────────────────

func HandleListZKPVerifications(db database.DB) http.HandlerFunc {
	return zkp.HandleListZKPVerifications(db)
}

func HandleGetZKPStats(db database.DB) http.HandlerFunc {
	return zkp.HandleGetZKPStats(db)
}

func HandleGenerateZKPProof(db database.DB) http.HandlerFunc {
	return zkp.HandleGenerateZKPProof(db)
}

// HandleVerifyZKP forwards to the canonical zkp package verifier.
// verifier may be nil — the zkp handler accepts nil and uses DB-backed verification.
func HandleVerifyZKP(db database.DB, verifier types.ZKPVerifier) http.HandlerFunc {
	return zkp.HandleVerifyZKP(db, verifier)
}
