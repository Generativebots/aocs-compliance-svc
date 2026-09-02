// cases_comments.go — Case comment and GetCase handlers.
// Cases list/arbitrate/assign: see cases.go | ZKP proof chain: see cases_proof.go
package compliance

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/serviceclient"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

// HandleCreateCaseComment appends a comment to an existing case.
// POST /hitl/cases/{case_id}/comments  |  POST /cases/{id}/comments
func HandleCreateCaseComment(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		vars := mux.Vars(r)
		caseID := vars["case_id"]
		if caseID == "" {
			caseID = vars["id"]
		}
		if caseID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing case id")
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		respond.LimitBody(r)
		var body AddCaseCommentRequest
		respond.LimitBody(r)
		if !validate.Bind(w, r, &body) {
			return
		}
		if body.AuthorID == "" {
			if au, auErr := auth.GetAuthUser(r.Context()); auErr == nil && au != nil {
				body.AuthorID = au.UserID
			}
			if body.AuthorID == "" {
				body.AuthorID = r.Header.Get("X-User-Id")
			}
		}
		comment := database.CaseComment{
			CaseID:     caseID,
			TenantID:   tenantID,
			AuthorID:   body.AuthorID,
			Body:       body.Body,
			IsInternal: body.IsInternal,
		}
		if err := db.InsertRow(database.TblCaseComments, comment.InsertPayload()); err != nil {
			slog.Error("AddCaseComment failed", "case_id", caseID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "add case comment", err)
			return
		}
		respond.JSON(w, http.StatusCreated, map[string]string{"status": "comment added", "case_id": caseID})
	}
}

// HandleListCaseComments returns the comment thread for a case.
// GET /hitl/cases/{case_id}/comments  |  GET /cases/{id}/comments
func HandleListCaseComments(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		vars := mux.Vars(r)
		caseID := vars["case_id"]
		if caseID == "" {
			caseID = vars["id"]
		}
		if caseID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing case id")
			return
		}
		var rows []map[string]any

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var err error
		if tenantID != "" {
			err = db.QueryRowsCompound(database.TblCaseComments, database.ColsCaseComment,
				"case_id", caseID, "tenant_id", tenantID, &rows)
		} else {
			err = db.QueryRowsCompoundCtx(r.Context(), database.TblCaseComments, database.ColsCaseComment, "case_id", caseID, "tenant_id", tenantID, &rows)
		}
		if err != nil {
			slog.Error("ListCaseComments failed", "case_id", caseID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "list comments", err)
			return
		}
		if rows == nil {
			rows = []map[string]any{}
		}
		respond.OK(w, map[string]any{"case_id": caseID, "comments": rows, "total": len(rows)})
	}
}

// HandleGetCase returns a single compliance/HITL case by ID.
// GET /hitl/cases/{case_id}  |  GET /cases/{id}
func HandleGetCase(db database.DB, coreClients ...*serviceclient.Client) http.HandlerFunc {
	var coreClient *serviceclient.Client
	if len(coreClients) > 0 {
		coreClient = coreClients[0]
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		vars := mux.Vars(r)
		caseID := vars["case_id"]
		if caseID == "" {
			caseID = vars["id"]
		}
		if caseID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing case id")
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var row map[string]any
		if coreClient != nil {
			// SVC-BOUNDARY: read core_hitl via ocx-core-svc API
			hitlRow, _rErr := coreClient.GetHITLCase(r.Context(), tenantID, caseID, database.ColsHITLDecision)
			if _rErr != nil || hitlRow == nil {
				respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "case not found")
				return
			}
			row = hitlRow
		} else {
			// Fallback: direct DB access when coreClient not wired (test mode)
			var rows []map[string]any
			if err := db.QueryRowsCompound(database.TblCoreHitl, database.ColsHITLDecision,
				"decision_id", caseID, "tenant_id", tenantID, &rows); err != nil || len(rows) == 0 {
				respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "case not found")
				return
			}
			row = rows[0]
		}

		var cd map[string]any
		switch v := row["context_data"].(type) {
		case map[string]any:
			cd = v
		case string:
			if _jsonErr := json.Unmarshal([]byte(v), &cd); _jsonErr != nil {
				slog.Warn("metadata unmarshal failed", "source_len", len([]byte(v)), "error", _jsonErr)
			}
		}
		if cd != nil {
			if pe, exists := cd["policy_evaluations"]; exists {
				row["policy_evaluations"] = pe
			}
			if sig, exists := cd["decision_signature"]; exists {
				row["decision_signature"] = sig
			}
		}
		respond.OK(w, map[string]any{"case": row})
	}
}
