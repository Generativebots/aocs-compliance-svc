package evaluation

// evidence_token_analytics.go — Handlers for evlt vault, token broker,
// and analytics endpoints. These back the frontend API clients that previously
// hit non-existent routes. Uses SupabaseClient's public QueryRows/InsertRow API.

import (
	"github.com/ocx/shared/idgen"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

// generatePlatformID generates a platform-standard ID: YYYYMM + 8 UPPERCASE alphanumeric chars.
// Matches the PostgreSQL gen_id() function in V013__functions.sql
func generatePlatformID() string { return idgen.GenID() }

func HandleListEvidence(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "tenant_id required")
			return
		}

		var records []database.QCoreEvidenceRecord
		if err := db.QueryRowsCtx(r.Context(), database.TblQCoreEvidenceRecords, database.ColsQCoreEvidenceRecord, "tenant_id", tenantID, &records); err != nil {
			slog.Error("ListEvidence DB query failed", "error", err, "tenant_id", tenantID)
			respond.InternalError(w, http.StatusInternalServerError, "failed to list evidence records", nil)
			return
		}

		// Optional type filter
		typeFilter := r.URL.Query().Get("type")
		if typeFilter != "" {
			var filtered []database.QCoreEvidenceRecord
			for _, rec := range records {
				if strings.EqualFold(rec.Type, typeFilter) {
					filtered = append(filtered, rec)
				}
			}
			records = filtered
		}

		if records == nil {
			records = []database.QCoreEvidenceRecord{}
		}
		respond.OK(w, records)
	}
}

// HandleCreateEvidence — POST /api/v1/evlt
func HandleCreateEvidence(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "tenant_id required")
			return
		}

		// Typed struct — explicit field contract prevents opaque map passthrough
		var req CreateEvidenceRequest
		respond.LimitBody(r)
		if !validate.Bind(w, r, &req) {
			return
		}

		// type is NOT NULL with no DEFAULT — must be set by caller
		if req.Type == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "type is required")
			return
		}
		// PKs/FKs mandatory — UI must carry agent_id and intent_id from localStorage
		if req.AgentID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "agent_id is required")
			return
		}
		if req.IntentID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "intent_id is required")
			return
		}

		ts := req.Timestamp
		if ts == "" {
			ts = time.Now().UTC().Format(time.RFC3339)
		}

		var payloadBytes []byte
		if req.PayloadData != nil {
			payloadBytes, _ = json.Marshal(req.PayloadData)
		} else {
			payloadBytes = []byte("{}")
		}

		record := database.QCoreEvidenceRecord{
			ID:            generatePlatformID(),
			TenantID:      tenantID,
			Type:          req.Type,
			ActionClass:   req.ActionClass,
			ToolID:        req.ToolID,
			TransactionID: req.TransID,
			Payload:       payloadBytes,
			AgentID:       req.AgentID,
			IntentID:      req.IntentID,
			ActivityID:    req.ActivityID,
			ExecutionID:   req.ExecutionID,
		}

		// Cryptographic hash chain — link to previous record
		// discarded and the raw table string bypassed T.* registry.
		// QueryRows with tenant filter ensures the previous hash belongs to the same tenant.
		var prevRows []struct {
			Hash string `json:"hash"`
		}
		if err := db.QueryRowsCtx(r.Context(), database.TblQCoreEvidenceRecords, "hash", "tenant_id", tenantID, &prevRows); err != nil {
			slog.Error("CreateEvidence: failed to fetch previous hash for chain link", "tenant_id", tenantID, "error", err)
		}

		var prevHash string
		if len(prevRows) > 0 {
			prevHash = prevRows[0].Hash
		}
		record.PreviousHash = prevHash

		// Serialize the struct to establish canonical JSON for hashing
		structuredBytes, marshalErr := json.Marshal(record)
		if marshalErr != nil {
			slog.Error("json.Marshal failed", "err", marshalErr)
			return
		}
		hashInput := string(structuredBytes) + prevHash
		hashBytes := sha256.Sum256([]byte(hashInput))

		record.Hash = hex.EncodeToString(hashBytes[:])

		if err := db.InsertRow(database.TblQCoreEvidenceRecords, record); err != nil {
			slog.Error("CreateEvidence failed", "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "failed to create evlt", nil)
			return
		}
		// L-NEW-4 + H-NEW-4 FIX: Audit log for evidence creation.
		// Evidence IS the audit system — but its own creation must still be attributed.
		// EU AI Act Art.13 requires all AI decision records to be traceable to their creator.
		slog.Info("audit: evidence created",
			"action", "CREATE_EVIDENCE",
			"evidence_id", record.ID,
			"tenant_id", tenantID,
			"actor", r.Header.Get("X-User-ID"),
			"evidence_type", record.Type,
			"hash", record.Hash,
			"at", time.Now().UTC().Format(time.RFC3339),
		)
		// Return actor chain FKs so UI can persist for governance traceability
		respond.JSON(w, http.StatusCreated, map[string]any{
			"status":       "created",
			"evidence_id":  record.ID,
			"id":           record.ID,
			"tenant_id":    tenantID,
			"type":         req.Type,
			"agent_id":     req.AgentID,
			"intent_id":    req.IntentID,
			"activity_id":  req.ActivityID,
			"execution_id": req.ExecutionID,
			"hash":         record.Hash,
		})
	}
}

// HandleGetEvidence — GET /api/v1/evlt/{id}
func HandleGetEvidence(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		id, idOk := respond.MustGetPathParam(w, r, "id")
		if !idOk {
			return
		}

		var result []database.QCoreEvidenceRecord
		if err := db.QueryRowsCompound(database.TblQCoreEvidenceRecords, database.ColsQCoreEvidenceRecord, "evidence_record_id", id, "tenant_id", tenantID, &result); err != nil || len(result) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "evlt not found")
			return
		}
		respond.OK(w, result[0])
	}
}

// HandleVerifyEvidence — POST /api/v1/evlt/{id}/verify
// HandleVerifyEvidence — POST /api/v1/evlt/{id}/verify
// F-RPT-02 FIX: accepts optional vault to check signing availability.
// Returns 503 SERVICE_SIGNING_UNAVAILABLE if signing is disabled.
func HandleVerifyEvidence(db database.DB, vault ...VaultSigner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		// F-RPT-02: Refuse verification when signing is disabled.
		// Signing disabled = keypair generation failed at startup = no cryptographic proof.
		if len(vault) > 0 && vault[0] != nil && !vault[0].IsSigningEnabled() {
			slog.Error("F-RPT-02: VerifyEvidence blocked — signing disabled, evidence would be stamped without crypto proof")
			respond.ErrorWithCode(w, http.StatusServiceUnavailable, "SERVICE_SIGNING_UNAVAILABLE",
				"evidence signing is currently unavailable — verification blocked to prevent false attestation")
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		id, idOk := respond.MustGetPathParam(w, r, "id")
		if !idOk {
			return
		}

		// Verify tenant ownership before allowing verification
		var currentRows []map[string]any
		if err := db.QueryRowsCompound(database.TblQCoreEvidenceRecords, "timestamp,tenant_id", "evidence_record_id", id, "tenant_id", tenantID, &currentRows); err != nil || len(currentRows) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "evlt not found")
			return
		}
		ts, _ := currentRows[0]["timestamp"].(string)

		update := map[string]any{
			"verified":    true,
			"verified_at": time.Now().UTC().Format(time.RFC3339),
		}
		if err := db.UpdateRowCompound(database.TblQCoreEvidenceRecords, "evidence_record_id", id, "timestamp", ts, update); err != nil {
			slog.Error("VerifyEvidence update failed", "id", id, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "verify evidence", err)
			return
		}

		respond.OK(w, map[string]any{
			"id":          id,
			"verified":    true,
			"verified_at": time.Now().UTC().Format(time.RFC3339),
		})
	}
}

// VaultSigner is the subset of EvidenceVault used by evidence handlers.
// Allows handlers to check signing health without importing the full vault package.
type VaultSigner interface {
	IsSigningEnabled() bool
}

// HandleAttestEvidence — POST /api/v1/evlt/{id}/attest
// F-RPT-02 FIX: accepts optional vault to check signing availability.
// Returns 503 SERVICE_SIGNING_UNAVAILABLE if signing is disabled.
func HandleAttestEvidence(db database.DB, vault ...VaultSigner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		// F-RPT-02: Refuse attestation when signing is disabled.
		if len(vault) > 0 && vault[0] != nil && !vault[0].IsSigningEnabled() {
			slog.Error("F-RPT-02: AttestEvidence blocked — signing disabled, attestation would have no cryptographic proof")
			respond.ErrorWithCode(w, http.StatusServiceUnavailable, "SERVICE_SIGNING_UNAVAILABLE",
				"evidence signing is currently unavailable — attestation blocked to prevent false compliance records")
			return
		}

		id, idOk := respond.MustGetPathParam(w, r, "id")
		if !idOk {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		respond.LimitBody(r)
		var req struct {
			AttestorType      string `json:"attestor_type"`
			Attestor          string `json:"attestor"`
			AttestationStatus string `json:"attestation_status" validate:"omitempty,oneof=APPROVED REJECTED PENDING"`
		}
		// body is optional — ignore decode error
		if !validate.BindOptional(w, r, &req) {
			return
		}
		var ownership []struct {
			TenantID string `json:"tenant_id"`
		}
		if err := db.QueryRowsCompound(database.TblQCoreEvidenceRecords, "tenant_id", "evidence_record_id", id, "tenant_id", tenantID, &ownership); err != nil || len(ownership) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "evidence record not found")
			return
		}
		// qcore_evidence_records — write real attestation columns (added in 009_analytics_monitoring_parity.sql)
		attestorType := req.AttestorType
		if attestorType == "" {
			attestorType = "HUMAN"
		}
		attestationStatus := req.AttestationStatus
		if attestationStatus == "" {
			attestationStatus = "APPROVED"
		}
		attestorID := req.Attestor
		if attestorID == "" {
			attestorID = "system"
		}

		// qcore_evidence_records — write real attestation columns (added in 009_analytics_monitoring_parity.sql)
		// and always store a fallback in event_data JSONB (which exists in base DDL).
		eventData, _ := json.Marshal(map[string]any{
			"attestor_type":      attestorType,
			"attestor_id":        attestorID,
			"attestation_status": attestationStatus,
			"attested":           true,
			"attested_at":        time.Now().UTC().Format(time.RFC3339),
		})
		// Try writing real columns first; if schema not yet migrated, fall back to event_data only.
		fullRow := map[string]any{
			"verified":            true,
			"verification_status": attestationStatus,
			"attestor_type":       attestorType,
			"attestor_id":         attestorID,
			"attestation_status":  attestationStatus,
			"attested":            true,
			"attested_at":         time.Now().UTC().Format(time.RFC3339),
			"event_data":          string(eventData),
		}
		if err := db.UpdateRowCompound(database.TblQCoreEvidenceRecords, "evidence_record_id", id, "tenant_id", tenantID, fullRow); err != nil {
			// PGRST204 = column not found (migration not yet applied) — fall back to event_data only
			if strings.Contains(err.Error(), "PGRST204") {
				fallbackRow := map[string]any{
					"verified":            true,
					"verification_status": attestationStatus,
					"event_data":          string(eventData),
				}
				if err2 := db.UpdateRowCompound(database.TblQCoreEvidenceRecords, "evidence_record_id", id, "tenant_id", tenantID, fallbackRow); err2 != nil {
					slog.Error("AttestEvidence fallback update failed", "evidence_id", id, "error", err2)
					respond.InternalError(w, http.StatusInternalServerError, "attest evidence", err2)
					return
				}
				slog.Warn("AttestEvidence: attestation columns missing — run 009_analytics_monitoring_parity.sql", "evidence_id", id)
			} else {
				slog.Error("AttestEvidence update failed", "evidence_id", id, "error", err)
				respond.InternalError(w, http.StatusInternalServerError, "attest evidence", err)
				return
			}
		}

		respond.OK(w, map[string]any{
			"id":          id,
			"attested":    true,
			"attested_at": time.Now().UTC().Format(time.RFC3339),
			"attestor_id": attestorID,
		})
	}
}

// HandleGetEvidenceAttestations — GET /api/v1/evlt/{id}/attestations
func HandleGetEvidenceAttestations(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		id, idOk := respond.MustGetPathParam(w, r, "id")
		if !idOk {
			return
		}

		// Verify parent evidence belongs to this tenant first
		var evidenceRows []map[string]any
		if err := db.QueryRowsCompound(database.TblQCoreEvidenceRecords, "tenant_id", "evidence_record_id", id, "tenant_id", tenantID, &evidenceRows); err != nil || len(evidenceRows) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "evidence not found")
			return
		}

		var result []database.QCoreEvidenceRecord
		// Attestations are columns on the evidence record itself
		if err := db.QueryRowsCompound(database.TblQCoreEvidenceRecords, database.ColsQCoreEvidenceRecord, "evidence_record_id", id, "tenant_id", tenantID, &result); err != nil || len(result) == 0 {
			slog.Error("GetEvidenceAttestations failed", "evidence_id", id, "error", err)
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "evidence not found")
			return
		}
		evr := result[0]
		respond.OK(w, map[string]any{
			"evidence_id":        id,
			"attestor_type":      evr.AttestorType,
			"attestor_id":        evr.AttestorID,
			"attestation_status": evr.AttestationStatus,
			"attested":           evr.Attested,
			"attested_at":        evr.AttestedAt,
			"attestations":       evr.Attestations,
			"count":              1,
		})
	}
}

// HandleListEvidenceAttestations — GET /api/v1/evidence-attestations
// Lists ALL attestations for the calling tenant (not scoped to a single evidence record).
// This is the list endpoint; HandleGetEvidenceAttestations handles the /{id} single-record variant.
func HandleListEvidenceAttestations(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized, "missing tenant_id")
			return
		}

		var result []database.QCoreEvidenceRecord
		// List attested evidence records for this tenant
		if err := db.QueryRowsCtx(r.Context(), database.TblQCoreEvidenceRecords, database.ColsQCoreEvidenceRecord, "tenant_id", tenantID, &result); err != nil {
			slog.Error("ListEvidenceAttestations failed", "tenant_id", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "list evidence attestations", err)
			return
		}
		// Filter to only attested records
		attested := make([]database.QCoreEvidenceRecord, 0, len(result))
		for _, ev := range result {
			if ev.Attested {
				attested = append(attested, ev)
			}
		}
		respond.OK(w, map[string]any{
			"attestations": attested,
			"count":        len(attested),
		})
	}
}

// HandleGetEvidenceChainByID — GET /api/v1/evlt/{id}/chain
func HandleGetEvidenceChainByID(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		id := mux.Vars(r)["id"]
		if id == "" {
			id = r.URL.Query().Get("id") // accept ?id= when called via /evidence/chain alias
		}
		if id == "" {
			respond.OK(w, map[string]any{"evidence_id": "", "chain": []any{}, "total": 0, "length": 0})
			return
		}

		// Verify parent evidence belongs to this tenant first
		var evidenceRows []map[string]any
		if err := db.QueryRowsCompound(database.TblQCoreEvidenceRecords, "tenant_id", "evidence_record_id", id, "tenant_id", tenantID, &evidenceRows); err != nil || len(evidenceRows) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "evidence not found")
			return
		}

		var result []database.QCoreEvidenceRecord
		// Chain data is columns on the evidence record itself
		if err := db.QueryRowsCompound(database.TblQCoreEvidenceRecords, database.ColsQCoreEvidenceRecord, "evidence_record_id", id, "tenant_id", tenantID, &result); err != nil || len(result) == 0 {
			slog.Error("GetEvidenceChainByID failed", "evidence_id", id, "error", err)
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "evidence not found")
			return
		}
		evr := result[0]
		respond.OK(w, map[string]any{
			"evidence_id":         id,
			"chain_position":      evr.ChainPosition,
			"merkle_root":         evr.MerkleRoot,
			"previous_block_hash": evr.PreviousBlockHash,
			"chain_hash":          evr.ChainHash,
			"tampered":            evr.Tampered,
			"attestation_count":   evr.AttestationCount,
			"ed25519_sig":         evr.ED25519Sig,
			"length":              1,
		})
	}
}

// HandleGetEvidenceStats — GET /api/v1/evlt/stats
func HandleGetEvidenceStats(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var records []database.QCoreEvidenceRecord
		if err := db.QueryRowsCtx(r.Context(), database.TblQCoreEvidenceRecords, database.ColsQCoreEvidenceRecord, "tenant_id", tenantID, &records); err != nil {
			slog.Error("GetEvidenceStats query failed", "tenant_id", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "get evidence stats", err)
			return
		}

		stats := map[string]int{
			"total": len(records),
			"gov":   0,
			"esc":   0,
			"hitl":  0,
			"fed":   0,
			"jury":  0,
		}
		for _, r := range records {
			switch r.Type {
			case "GOV":
				stats["gov"]++
			case "ESC":
				stats["esc"]++
			case "HITL":
				stats["hitl"]++
			case "FED":
				stats["fed"]++
			case "JURY":
				stats["jury"]++
			}
		}
		respond.OK(w, stats)
	}
}

// NOTE: HandleSearchEvidence is declared in evidence_reporting.go.
// Do NOT re-declare here — it caused a duplicate symbol compile error.
// Search logic uses strings.Contains directly in evidence_reporting.go.
