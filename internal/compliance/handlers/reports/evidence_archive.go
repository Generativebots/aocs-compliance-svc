package reports

// Table: core_evidence_records (PK: evidence_record_id).
// Evidence is immutable — there is no update path. Delete archives the record
// (verification_status=ARCHIVED, archived_at/archived_by host columns); the
// hashed content and chain fields are never modified.

import (
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
)

// HandleDeleteEvidence archives an evidence record.
// DELETE /api/v1/evidence/{id}, DELETE /api/v1/compliance/evidence/{id}
func HandleDeleteEvidence(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDBWrite(w, db) {
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
		if err := db.QueryRowsCompound(database.TblCoreEvidenceRecords, "evidence_record_id,tenant_id,verification_status", "evidence_record_id", id, "tenant_id", tenantID, &rows); err != nil || len(rows) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "evidence not found")
			return
		}
		if rows[0].VerificationStatus == "ARCHIVED" {
			respond.ErrorWithCode(w, http.StatusConflict, respond.ErrCodeConflict, "evidence record already archived")
			return
		}
		// Evidence is immutable: archive via host columns only. Nothing in the
		// hashed content (type/payload/previous_hash) is touched, so the record
		// and the chain remain verifiable after archival.
		archivedAt := time.Now().UTC().Format(time.RFC3339)
		updates := map[string]any{
			"verification_status": "ARCHIVED",
			"archived_at":         archivedAt,
		}
		if uid := auth.GetUserID(r.Context()); uid != "" {
			updates["archived_by"] = uid
		}
		if dbErr := db.UpdateRowCompound(database.TblCoreEvidenceRecords, "evidence_record_id", id, "tenant_id", tenantID, updates); dbErr != nil {
			respond.InternalError(w, http.StatusInternalServerError, "archive evidence", dbErr)
			return
		}
		respond.JSON(w, http.StatusOK, map[string]string{"status": "ARCHIVED", "id": id, "archived_at": archivedAt})
	}
}
