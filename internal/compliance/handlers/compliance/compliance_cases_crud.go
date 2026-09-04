package compliance

// compliance_cases_crud.go — CRUD handlers for compliance.compliance_cases
//
// C1 FIX: Table moved from extc_compliance_cases (ocx-extension-svc) to
// compliance.compliance_cases (aocs-compliance-svc) on 2026-09-04.
//
// Routes registered in routes_compliance.go:
//   GET    /compliance/investigation-cases              — list cases
//   GET    /compliance/investigation-cases/{id}         — get single case
//   POST   /compliance/investigation-cases              — create case
//   PATCH  /compliance/investigation-cases/{id}/status  — update status
//   POST   /compliance/investigation-cases/{id}/assign  — assign investigator
//   POST   /compliance/investigation-cases/{id}/comments — add comment

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

type complianceCaseRow struct {
	CaseID       string          `json:"case_id"`
	TenantID     string          `json:"tenant_id"`
	Title        string          `json:"title"`
	Description  *string         `json:"description,omitempty"`
	Status       string          `json:"status"`
	Severity     *string         `json:"severity,omitempty"`
	AssignedTo   *string         `json:"assigned_to,omitempty"`
	Framework    *string         `json:"framework,omitempty"`
	ControlRef   *string         `json:"control_ref,omitempty"`
	AgentID      *string         `json:"agent_id,omitempty"`
	CaseComments json.RawMessage `json:"case_comments,omitempty"`
	Metadata     json.RawMessage `json:"metadata,omitempty"`
	CreatedAt    string          `json:"created_at"`
	UpdatedAt    string          `json:"updated_at"`
	ResolvedAt   *string         `json:"resolved_at,omitempty"`
	ClosedAt     *string         `json:"closed_at,omitempty"`
}

// HandleListComplianceCases — GET /compliance/investigation-cases
func HandleListComplianceCases(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var rows []complianceCaseRow
		if err := db.QueryRowsCtx(r.Context(),
			database.TblComplianceComplianceCases,
			"case_id,tenant_id,title,description,status,severity,assigned_to,framework,control_ref,agent_id,metadata,created_at,updated_at,resolved_at,closed_at",
			"tenant_id", tenantID, &rows,
		); err != nil {
			slog.Error("HandleListComplianceCases: query failed", "tenant_id", tenantID, "err", err)
			respond.Error(w, http.StatusInternalServerError, "failed to list compliance cases")
			return
		}
		if rows == nil {
			rows = []complianceCaseRow{}
		}
		if sf := r.URL.Query().Get("status"); sf != "" {
			filtered := rows[:0]
			for _, row := range rows {
				if row.Status == sf {
					filtered = append(filtered, row)
				}
			}
			rows = filtered
		}
		respond.JSON(w, http.StatusOK, map[string]any{"cases": rows, "count": len(rows)})
	}
}

// HandleGetComplianceCase — GET /compliance/investigation-cases/{id}
func HandleGetComplianceCase(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		caseID := mux.Vars(r)["id"]
		var rows []complianceCaseRow
		if err := db.QueryRowsCompound(
			database.TblComplianceComplianceCases,
			"case_id,tenant_id,title,description,status,severity,assigned_to,framework,control_ref,agent_id,case_comments,metadata,created_at,updated_at,resolved_at,closed_at",
			"case_id", caseID, "tenant_id", tenantID, &rows,
		); err != nil || len(rows) == 0 {
			respond.Error(w, http.StatusNotFound, "case not found")
			return
		}
		respond.JSON(w, http.StatusOK, rows[0])
	}
}

// HandleCreateComplianceCase — POST /compliance/investigation-cases
func HandleCreateComplianceCase(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		respond.LimitBody(r)
		var input struct {
			Title       string  `json:"title"`
			Description *string `json:"description"`
			Severity    *string `json:"severity"`
			Framework   *string `json:"framework"`
			ControlRef  *string `json:"control_ref"`
			AgentID     *string `json:"agent_id"`
		}
		if !validate.Bind(w, r, &input) {
			return
		}
		if input.Title == "" {
			respond.Error(w, http.StatusBadRequest, "title is required")
			return
		}
		now := time.Now().UTC().Format(time.RFC3339)
		caseID := uuid.NewString()
		row := map[string]any{
			"case_id":      caseID,
			"tenant_id":    tenantID,
			"title":        input.Title,
			"description":  input.Description,
			"status":       "OPEN",
			"severity":     input.Severity,
			"framework":    input.Framework,
			"control_ref":  input.ControlRef,
			"agent_id":     input.AgentID,
			"metadata":     "{}",
			"case_comments": "[]",
			"created_at":   now,
			"updated_at":   now,
		}
		if err := db.InsertRow(database.TblComplianceComplianceCases, row); err != nil {
			slog.Error("HandleCreateComplianceCase: insert failed", "tenant_id", tenantID, "err", err)
			respond.Error(w, http.StatusInternalServerError, "failed to create compliance case")
			return
		}
		respond.JSON(w, http.StatusCreated, map[string]any{
			"case_id":    caseID,
			"tenant_id":  tenantID,
			"status":     "OPEN",
			"created_at": now,
		})
	}
}

// HandleUpdateComplianceCaseStatus — PATCH /compliance/investigation-cases/{id}/status
func HandleUpdateComplianceCaseStatus(db database.DB) http.HandlerFunc {
	validStatuses := map[string]bool{
		"OPEN": true, "INVESTIGATING": true, "RESOLVED": true, "CLOSED": true, "ARCHIVED": true,
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		caseID := mux.Vars(r)["id"]
		respond.LimitBody(r)
		var body struct {
			Status string  `json:"status"`
			Note   *string `json:"note"`
		}
		if !validate.Bind(w, r, &body) {
			return
		}
		if !validStatuses[body.Status] {
			respond.Error(w, http.StatusBadRequest, "status must be one of: OPEN, INVESTIGATING, RESOLVED, CLOSED, ARCHIVED")
			return
		}
		now := time.Now().UTC().Format(time.RFC3339)
		updates := map[string]any{"status": body.Status, "updated_at": now}
		if body.Status == "RESOLVED" {
			updates["resolved_at"] = now
		}
		if body.Status == "CLOSED" || body.Status == "ARCHIVED" {
			updates["closed_at"] = now
		}
		if err := db.UpdateRowCompound(database.TblComplianceComplianceCases,
			"case_id", caseID, "tenant_id", tenantID, updates,
		); err != nil {
			respond.Error(w, http.StatusInternalServerError, "failed to update case status")
			return
		}
		respond.JSON(w, http.StatusOK, map[string]any{"case_id": caseID, "status": body.Status, "updated_at": now})
	}
}

// HandleAssignComplianceCase — POST /compliance/investigation-cases/{id}/assign
func HandleAssignComplianceCase(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		caseID := mux.Vars(r)["id"]
		respond.LimitBody(r)
		var body struct {
			AssignedTo string `json:"assigned_to"`
		}
		if !validate.Bind(w, r, &body) {
			return
		}
		if body.AssignedTo == "" {
			respond.Error(w, http.StatusBadRequest, "assigned_to is required")
			return
		}
		now := time.Now().UTC().Format(time.RFC3339)
		if err := db.UpdateRowCompound(database.TblComplianceComplianceCases,
			"case_id", caseID, "tenant_id", tenantID,
			map[string]any{"assigned_to": body.AssignedTo, "status": "INVESTIGATING", "updated_at": now},
		); err != nil {
			respond.Error(w, http.StatusInternalServerError, "failed to assign case")
			return
		}
		respond.JSON(w, http.StatusOK, map[string]any{"case_id": caseID, "assigned_to": body.AssignedTo, "status": "INVESTIGATING", "updated_at": now})
	}
}

// HandleAddComplianceCaseComment — POST /compliance/investigation-cases/{id}/comments
func HandleAddComplianceCaseComment(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		caseID := mux.Vars(r)["id"]
		respond.LimitBody(r)
		var body struct {
			Text   string `json:"text"`
			Author string `json:"author"`
		}
		if !validate.Bind(w, r, &body) {
			return
		}
		if body.Text == "" {
			respond.Error(w, http.StatusBadRequest, "text is required")
			return
		}
		var rows []struct {
			CaseComments json.RawMessage `json:"case_comments"`
		}
		_ = db.QueryRowsCompound(database.TblComplianceComplianceCases, "case_comments",
			"case_id", caseID, "tenant_id", tenantID, &rows)
		var comments []map[string]any
		if len(rows) > 0 && len(rows[0].CaseComments) > 0 {
			_ = json.Unmarshal(rows[0].CaseComments, &comments)
		}
		now := time.Now().UTC().Format(time.RFC3339)
		comments = append(comments, map[string]any{
			"comment_id": uuid.NewString(), "author": body.Author, "text": body.Text, "created_at": now,
		})
		commentsJSON, _ := json.Marshal(comments)
		if err := db.UpdateRowCompound(database.TblComplianceComplianceCases,
			"case_id", caseID, "tenant_id", tenantID,
			map[string]any{"case_comments": string(commentsJSON), "updated_at": now},
		); err != nil {
			respond.Error(w, http.StatusInternalServerError, "failed to add comment")
			return
		}
		respond.JSON(w, http.StatusCreated, map[string]any{"case_id": caseID, "comment_count": len(comments), "updated_at": now})
	}
}
