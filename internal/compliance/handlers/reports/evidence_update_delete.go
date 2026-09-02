package reports

// Table: qcore_evidence_records (PK: id, compound key with timestamp for chain integrity)
// Update: allows correction of metadata fields (type, action_class) before attestation.
// Delete: soft-delete — sets a deleted_at marker; immutable chain fields (hash, previous_hash)
//         are preserved to keep the cryptographic audit chain intact.

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

// PUT /api/v1/evlt/{id}
// Updates mutable metadata on an evidence record before it is attested.
// After attestation (attested=true), returns 409 to prevent tampering.
func HandleUpdateEvidence(db database.DB) http.HandlerFunc {
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
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing id")
			return
		}
		// Verify ownership and attestation status
		var rows []database.QCoreEvidenceRecord
		if err := db.QueryRowsCompound(database.TblQCoreEvidenceRecords, database.ColsQCoreEvidenceRecord, "evidence_record_id", id, "tenant_id", tenantID, &rows); err != nil || len(rows) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "evidence not found")
			return
		}
		rec := rows[0]
		if rec.Attested {
			respond.ErrorWithCode(w, http.StatusConflict, respond.ErrCodeConflict, "attested evidence records cannot be modified")
			return
		}
		respond.LimitBody(r)
		var req UpdateEvidenceRequest
		respond.LimitBody(r)
		if !validate.Bind(w, r, &req) {
			return
		}
		updates := map[string]any{}
		if req.Type != "" {
			updates["type"] = req.Type
		}
		if req.ActionClass != "" {
			updates["action_class"] = req.ActionClass
		}
		if req.PayloadData != nil {
			payloadBytes, marshalErr := json.Marshal(req.PayloadData)
			if marshalErr != nil {
				slog.Error("json.Marshal failed", "err", marshalErr)
				return
			}
			updates["payload"] = payloadBytes
		}
		if len(updates) == 0 {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "no fields to update")
			return
		}
		if dbErr := db.UpdateRowCompound(database.TblQCoreEvidenceRecords, "evidence_record_id", id, "tenant_id", tenantID, updates); dbErr != nil {
			respond.InternalError(w, http.StatusInternalServerError, "update evidence", dbErr)
			return
		}
		respond.JSON(w, http.StatusOK, map[string]any{"id": id, "updated": true})
	}
}

// DELETE /api/v1/evlt/{id}
// Soft-delete: marks the record as deleted without removing hash chain columns,
// preserving the cryptographic audit chain integrity for SOX/GDPR compliance.
func HandleDeleteEvidence(db database.DB) http.HandlerFunc {
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
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing id")
			return
		}
		// Verify ownership
		var rows []database.QCoreEvidenceRecord
		if err := db.QueryRowsCompound(database.TblQCoreEvidenceRecords, "evidence_record_id,tenant_id,verified", "evidence_record_id", id, "tenant_id", tenantID, &rows); err != nil || len(rows) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "evidence not found")
			return
		}
		if rows[0].Attested {
			respond.ErrorWithCode(w, http.StatusConflict, respond.ErrCodeConflict, "attested evidence records cannot be deleted")
			return
		}
		// Soft-delete preserves hash chain — sets verification_status=DELETED
		updates := map[string]any{
			"verification_status": "DELETED",
			"verified":            false,
		}
		delEvent, _ := json.Marshal(map[string]any{"deleted_at": time.Now().UTC().Format(time.RFC3339)})
		updates["event_data"] = string(delEvent)
		if dbErr := db.UpdateRowCompound(database.TblQCoreEvidenceRecords, "evidence_record_id", id, "tenant_id", tenantID, updates); dbErr != nil {
			respond.InternalError(w, http.StatusInternalServerError, "delete evidence", dbErr)
			return
		}
		respond.JSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": id})
	}
}
