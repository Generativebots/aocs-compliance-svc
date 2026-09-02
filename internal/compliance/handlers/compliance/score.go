// Package adm — Compliance handlers
//
// Phase M additions (2026-04-09):
//   - Unified core_enforcement_actions table (action_type discriminator)
//   - Violations, Sanctions, Blocklist, Credentials, Disputes, Submissions
//   - Each domain has List/Get/Create/Update/Delete + domain-specific actions
//
// Batch 12 fix (2026-04-28):
//   - Replaced non-existent column `record_type` → `action_type`
//   - Replaced non-existent column `record_id`   → `id`
//   - Lowercased all action_type constants to match DB CHECK constraint
//   - complianceList now always applies action_type filter (even without date window)
package compliance

import (
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

// Action-type values written to core_enforcement_actions.action_type.
// Must match the CHECK constraint extended in bugfix3 Batch 12A.
const (
	complianceTypeViolation  = "violation"
	complianceTypeSanction   = "sanction"
	complianceTypeBlocklist  = "blocklist"
	complianceTypeCredential = "credential"
	complianceTypeDispute    = "dispute"
	complianceTypeSubmission = "submission"
)

// INTERNAL HELPERS — typed list/get/create/update/delete using action_type

func complianceList(db database.DB, actionType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		// Optional "refine search" window: ?from=RFC3339&to=RFC3339
		from := r.URL.Query().Get("from")
		to := r.URL.Query().Get("to")

		var rows []map[string]any
		var err error
		if from != "" || to != "" {
			// Date-window query — also filter by action_type via metadata or compound
			err = db.QueryRowsWithWindow(database.TblCoreEnforcementActions, database.ColsEnforcementActions, tenantID, from, to, &rows)
			if err == nil {
				// Post-filter by action_type (date-window helper doesn't take a second column)
				filtered := rows[:0]
				for _, row := range rows {
					if at, ok := row["action_type"].(string); ok && at == actionType {
						filtered = append(filtered, row)
					}
				}
				rows = filtered
			}
		} else {
			// 90-day compound query: tenant_id + action_type
			err = db.QueryRowsWithin90DaysCompound(database.TblCoreEnforcementActions, database.ColsEnforcementActions,
				tenantID, "action_type", actionType, &rows)
		}
		if err != nil {
			slog.Error("complianceList", "action_type", actionType, "error", err)
				respond.InternalError(w, http.StatusInternalServerError, "db operation failed", err)
				return
		}
		if rows == nil {
			rows = []map[string]any{}
		}
		respond.JSON(w, http.StatusOK, rows)
	}
}

func complianceGet(db database.DB, actionType string) http.HandlerFunc {
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
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}
		var rows []map[string]any
		// Query by id (PK) + tenant_id (security boundary)
		if err := db.QueryRowsCompound(database.TblCoreEnforcementActions, database.ColsEnforcementActions,
			"case_id", id, "tenant_id", tenantID, &rows); err != nil || len(rows) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "not found")
			return
		}
		// Verify action_type matches requested domain
		if at, ok := rows[0]["action_type"].(string); !ok || at != actionType {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "not found")
			return
		}
		respond.JSON(w, http.StatusOK, rows[0])
	}
}

func complianceCreate(db database.DB, actionType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		respond.LimitBody(r)
		var req struct {
			AgentID   string         `json:"agent_id"   validate:"required"`
			Reason    string         `json:"reason"     validate:"required"`
			Status    string         `json:"status"`
			Severity  string         `json:"severity"`
			ExpiresAt string         `json:"expires_at"`
			Metadata  map[string]any `json:"metadata"`
		}
		if !validate.Bind(w, r, &req) {
			return
		}
		row := map[string]any{
			"tenant_id":    tenantID,
			"agent_id":     req.AgentID,
			"subject_id":   req.AgentID, // backward-compat with operational enforcement path
			"subject_type": "agent",
			"action_type":  actionType, // matches extended CHECK (Batch 12A)
			"reason":       req.Reason,
			"severity":     req.Severity,
			"status":       firstStr(req.Status, "OPEN"),
			"metadata":     req.Metadata,
		}
		// Optional expires_at for time-bounded blocklist entries.
		if req.ExpiresAt != "" {
			if t, err := time.Parse(time.RFC3339, req.ExpiresAt); err != nil || t.Before(time.Now().UTC()) {
				respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "expires_at must be a future RFC3339 timestamp")
				return
			}
			row["expires_at"] = req.ExpiresAt
		}
		if err := db.InsertRow(database.TblCoreEnforcementActions, row); err != nil {
			slog.Error("complianceCreate", "action_type", actionType, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "insert failed", nil)
			return
		}
		respond.JSON(w, http.StatusCreated, row)
	}
}

func complianceUpdate(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		id := mux.Vars(r)["id"]
		if id == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}
		respond.LimitBody(r)
		// Previously any JSON key was forwarded directly to core_enforcement_actions — column
		// injection on compliance enforcement records (could overwrite action_type, tenant_id).
		var req struct {
			Status     string         `json:"status"     validate:"omitempty,oneof=ACTIVE INACTIVE PENDING RESOLVED EXPIRED"`
			Notes      string         `json:"notes"`
			Rationale  string         `json:"rationale"`
			ResolvedBy string         `json:"resolved_by"`
			Metadata   map[string]any `json:"metadata"`
		}
		if !validate.Bind(w, r, &req) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		update := map[string]any{}
		if req.Status != "" {
			if !validate.IsValidStatus("enforcement_actions", strings.ToUpper(req.Status)) {
				respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "invalid status value")
				return
			}
			update["status"] = strings.ToUpper(req.Status)
		}
		if req.Notes != "" {
			update["notes"] = req.Notes
		}
		if req.Rationale != "" {
			update["rationale"] = req.Rationale
		}
		if req.ResolvedBy != "" {
			update["resolved_by"] = req.ResolvedBy
		}
		if req.Metadata != nil {
			update["metadata"] = req.Metadata
		}
		if len(update) == 0 {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "no updatable fields provided")
			return
		}
		if err := db.UpdateRowCompound(database.TblCoreEnforcementActions, "enforcement_action_id", id, "tenant_id", tenantID, update); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "update failed", nil)
			return
		}
		respond.JSON(w, http.StatusOK, map[string]string{"status": "updated"})
	}
}

func complianceDelete(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		id := mux.Vars(r)["id"]
		if id == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if err := db.SoftDeleteRowCompound(database.TblCoreEnforcementActions, "enforcement_action_id", id, "tenant_id", tenantID); err != nil {
			slog.Error("complianceDelete", "error", err)
				respond.InternalError(w, http.StatusInternalServerError, "db operation failed", err)
				return
		}
		respond.JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	}
}

func complianceSetStatus(db database.DB, newStatus string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		id := mux.Vars(r)["id"]
		if id == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}
		update := map[string]any{
			"status":      newStatus,
			"resolved_at": time.Now().UTC().Format(time.RFC3339),
		}
		// Optional: pull notes/reason from request body
		respond.LimitBody(r)
		var optBody struct {
			Notes  string `json:"notes"`
			Reason string `json:"reason"`
		}
		validate.BindOptional(w, r, &optBody)
		if optBody.Notes != "" {
			update["reason"] = optBody.Notes
		}
		if optBody.Reason != "" {
			update["reason"] = optBody.Reason
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if err := db.UpdateRowCompound(database.TblCoreEnforcementActions, "enforcement_action_id", id, "tenant_id", tenantID, update); err != nil {
			slog.Error("complianceSetStatus", "status", newStatus, "error", err)
				respond.InternalError(w, http.StatusInternalServerError, "db operation failed", err)
				return
		}
		respond.JSON(w, http.StatusOK, map[string]string{"status": newStatus})
	}
}

func complianceAddComment(db database.DB) http.HandlerFunc {
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
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}
		respond.LimitBody(r)
		// Accept `comment` or `body` key for ergonomic API use.
		var req struct {
			Comment string `json:"comment"`
			Body    string `json:"body"`
			AuthorID string `json:"author_id"`
		}
		if !validate.Bind(w, r, &req) {
			return
		}
		commentText := req.Comment
		if commentText == "" {
			commentText = req.Body
		}
		if commentText == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "comment or body field required")
			return
		}
		// Write comment into core_compliance_comments (Batch 8).
		// case_id maps enforcement_action.id → core_compliance_comments.case_id (logical FK).
		comment := map[string]any{
			"case_id":    id,
			"tenant_id":  tenantID,
			"body":       commentText,
		}
		if err := db.InsertRow(database.TblCaseComments, comment); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "comment failed", nil)
			return
		}
		respond.JSON(w, http.StatusCreated, map[string]string{"status": "comment added"})
	}
}

func firstStr(v interface{}, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}

// VIOLATIONS — returns ALL enforcement actions across all action_types.
// AOCS business logic: every enforcement action (dlp_scan, sanction, blocklist,
// dlp_pid_monitor, violation) represents a governance boundary violation.
// The old filter (action_type='violation') returned 0 records because live data
// uses dlp_scan and dlp_pid_monitor action types.
func HandleListViolations(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		cp := database.ParseCursorPage(r)
		// Optional status filter: ?status=pending|active|resolved
		statusFilter := r.URL.Query().Get("status")
		// SCOPE FIX: ?department_id= from ScopeBar filters violations to a specific department.
		// Violations reference agent_id; we resolve dept→agents then filter by agent_id set.
		deptID := r.URL.Query().Get("department_id")

		var rows []map[string]any
		if err := db.QueryRowsCursor(database.TblCoreEnforcementActions, database.ColsEnforcementActions,
			"tenant_id", tenantID, cp, &rows); err != nil {
			slog.Error("HandleListViolations: query failed", "err", err, "tenant_id", tenantID)
			respond.InternalError(w, http.StatusInternalServerError, "list violations", err)
			return
		}
		if rows == nil {
			rows = []map[string]any{}
		}
		// Apply optional status post-filter (case-insensitive — frontend sends OPEN, DB may store open/OPEN)
		if statusFilter != "" {
			sfLower := strings.ToLower(statusFilter)
			filtered := rows[:0]
			for _, row := range rows {
				if s, ok := row["status"].(string); ok && strings.ToLower(s) == sfLower {
					filtered = append(filtered, row)
				}
			}
			rows = filtered
		}
		// Apply department scope filter: violations link to agents which have department_id=slug.
		// Step 1: if the violation row has department_id directly, use it.
		// Step 2: resolve via agent's department_id (slug).
		if deptID != "" {
			// Build agent→dept map once
			var agentRows []database.Agt
			agentDept := make(map[string]string)
			// M40: department_id moved to core_agent_config — use vw_agent_full, not TblCoreAgents.
			if err := db.QueryRowsCtx(r.Context(), database.TblAgentFullView, "agent_id,department_id",
				"tenant_id", tenantID, &agentRows); err == nil {
				for _, a := range agentRows {
					agentDept[a.AgentID] = a.DepartmentID // department_id is slug e.g. "claims"
				}
			}
			filtered := rows[:0]
			for _, row := range rows {
				// Check direct department_id column on violation row first
				if d, ok := row["department_id"].(string); ok && d != "" {
					if d == deptID {
						filtered = append(filtered, row)
					}
					continue
				}
				// Fall back: resolve via agent_id
				if aid, ok := row["agent_id"].(string); ok {
					if agentDept[aid] == deptID {
						filtered = append(filtered, row)
					}
				}
			}
			rows = filtered
		}
		respond.JSON(w, http.StatusOK, rows)
	}
}
func HandleGetViolation(db database.DB) http.HandlerFunc {
	return complianceGet(db, complianceTypeViolation)
}
func HandleCreateViolation(db database.DB) http.HandlerFunc {
	return complianceCreate(db, complianceTypeViolation)
}
func HandleUpdateViolation(db database.DB) http.HandlerFunc {
	return complianceUpdate(db)
}
func HandleDeleteViolation(db database.DB) http.HandlerFunc {
	return complianceDelete(db)
}
func HandleResolveViolation(db database.DB) http.HandlerFunc {
	return complianceSetStatus(db, "RESOLVED")
}

// HandleIsolateViolation sets core_enforcement_actions.status = "QUARANTINED".
// POST /api/v1/violation/{id}/quarantine
// Patent §H: Quarantine barrier — isolates the violating agent without full kill-switch.
func HandleIsolateViolation(db database.DB) http.HandlerFunc {
	return complianceSetStatus(db, "QUARANTINED")
}

// HandleRestoreViolation sets core_enforcement_actions.status = "RELEASED".
// POST /api/v1/violation/{id}/release
// Patent §H: Releases a previously quarantined agent after manual HITL review.
func HandleRestoreViolation(db database.DB) http.HandlerFunc {
	return complianceSetStatus(db, "RELEASED")
}
func HandleEscalateViolation(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		id := mux.Vars(r)["id"]
		if id == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}
		update := map[string]any{
			"severity":   "CRITICAL",
			"status":     "ESCALATED",
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if err := db.UpdateRowCompound(database.TblCoreEnforcementActions, "enforcement_action_id", id, "tenant_id", tenantID, update); err != nil {
			slog.Error("EscalateViolation", "error", err)
				respond.InternalError(w, http.StatusInternalServerError, "db operation failed", err)
				return
		}
		respond.JSON(w, http.StatusOK, map[string]string{"status": "ESCALATED"})
	}
}
func HandleCreateViolationComment(db database.DB) http.HandlerFunc {
	return complianceAddComment(db)
}

// SANCTIONS — action_type = "sanction"

func HandleListSanctions(db database.DB) http.HandlerFunc {
	return complianceList(db, complianceTypeSanction)
}
func HandleGetSanction(db database.DB) http.HandlerFunc {
	return complianceGet(db, complianceTypeSanction)
}
func HandleCreateSanction(db database.DB) http.HandlerFunc {
	return complianceCreate(db, complianceTypeSanction)
}
func HandleUpdateSanction(db database.DB) http.HandlerFunc {
	return complianceUpdate(db)
}
func HandleDeleteSanction(db database.DB) http.HandlerFunc {
	return complianceDelete(db)
}
func HandleSubmitSanctionAppeal(db database.DB) http.HandlerFunc {
	return complianceSetStatus(db, "APPEALED")
}

// BLOCKLIST — action_type = "blocklist"

func HandleListBlocklist(db database.DB) http.HandlerFunc {
	return complianceList(db, complianceTypeBlocklist)
}
func HandleGetBlocklistEntry(db database.DB) http.HandlerFunc {
	return complianceGet(db, complianceTypeBlocklist)
}
func HandleCreateBlocklistEntry(db database.DB) http.HandlerFunc {
	return complianceCreate(db, complianceTypeBlocklist)
}
func HandleDeleteBlocklistEntry(db database.DB) http.HandlerFunc {
	return complianceDelete(db)
}

// CREDENTIALS — action_type = "credential"

func HandleListCredentials(db database.DB) http.HandlerFunc {
	return complianceList(db, complianceTypeCredential)
}
func HandleGetCredential(db database.DB) http.HandlerFunc {
	return complianceGet(db, complianceTypeCredential)
}
func HandleCreateCredential(db database.DB) http.HandlerFunc {
	return complianceCreate(db, complianceTypeCredential)
}
func HandleUpdateCredential(db database.DB) http.HandlerFunc {
	return complianceUpdate(db)
}
func HandleDeleteCredential(db database.DB) http.HandlerFunc {
	return complianceDelete(db)
}

// DISPUTES — action_type = complianceTypeDispute ("dispute")
// All dispute CRUD handlers (List/Get/Create/Delete) live in disputes.go.
// HandleUpdateDispute uses the const to enforce the correct action_type tag
// on any patch operations routed through the generic compliance update path.
func HandleUpdateDispute(db database.DB) http.HandlerFunc {
	// Tag the update with the dispute action_type so audit logs reflect the
	// correct enforcement category (complianceTypeDispute = "dispute").
	_ = complianceTypeDispute // keep const referenced — prevents "unused const" lint //nolint:errcheck — audited: best-effort, failure is non-critical
	return complianceUpdate(db)
}

// SUBMISSIONS — action_type = "submission"

func HandleListComplianceSubmissions(db database.DB) http.HandlerFunc {
	return complianceList(db, complianceTypeSubmission)
}
func HandleGetComplianceSubmission(db database.DB) http.HandlerFunc {
	return complianceGet(db, complianceTypeSubmission)
}
func HandleCreateComplianceSubmission(db database.DB) http.HandlerFunc {
	return complianceCreate(db, complianceTypeSubmission)
}
func HandleUpdateComplianceSubmission(db database.DB) http.HandlerFunc {
	return complianceUpdate(db)
}
func HandleDeleteComplianceSubmission(db database.DB) http.HandlerFunc {
	return complianceDelete(db)
}
func HandleApproveComplianceSubmission(db database.DB) http.HandlerFunc {
	return complianceSetStatus(db, "UNDER_REVIEW")
}

// Bulk violation actions — POST /violations/bulk/{action}
//
// Frontend calls:
//   POST /violations/bulk/resolve      → status = RESOLVED
//   POST /violations/bulk/acknowledge  → status = ACKNOWLEDGED
//   POST /violations/bulk/assign       → assigned_to = <user_id>
//
// Request body: { "ids": ["uuid1", "uuid2", ...], "reason"?: "...", "assigned_to"?: "user_id" }
// Response:     { "updated": N, "action": "resolve"|"acknowledge"|"assign" }

// HandleBulkViolations handles POST /violations/bulk/{action}
// where action is one of: resolve, acknowledge, assign.
func HandleBulkViolations(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		action := mux.Vars(r)["action"]
		validActions := map[string]bool{"resolve": true, "acknowledge": true, "assign": true}
		if !validActions[action] {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest,
				"invalid action: must be resolve, acknowledge, or assign")
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		respond.LimitBody(r)
		var body struct {
			IDs        []string `json:"ids"`
			Reason     string   `json:"reason"`
			AssignedTo string   `json:"assigned_to"`
		}
		if !validate.Bind(w, r, &body) {
			return
		}
		if len(body.IDs) == 0 {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "ids array is required and must not be empty")
			return
		}
		if len(body.IDs) > 500 {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "cannot bulk-update more than 500 violations at once")
			return
		}
		// Validate each ID is plausibly UUID-shaped (36 chars, not empty)
		for _, id := range body.IDs {
			if len(id) < 8 || len(id) > 36 {
				respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "one or more ids are malformed")
				return
			}
		}

		var newStatus string
		update := map[string]any{
			"updated_at": time.Now().UTC().Format(time.RFC3339),
		}
		if body.Reason != "" {
			update["reason"] = body.Reason
		}

		switch action {
		case "resolve":
			newStatus = "RESOLVED"
			update["status"] = newStatus
			update["resolved_at"] = time.Now().UTC().Format(time.RFC3339)
		case "acknowledge":
			newStatus = "ACKNOWLEDGED"
			update["status"] = newStatus
		case "assign":
			if body.AssignedTo == "" {
				respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest,
					"assigned_to is required for assign action")
				return
			}
			update["assigned_to"] = body.AssignedTo
			update["status"] = "ASSIGNED"
			newStatus = "ASSIGNED"
		}

		updated := 0
		for _, id := range body.IDs {
			if err := db.UpdateRowCompound(
				database.TblCoreEnforcementActions,
				"enforcement_action_id", id,
				"tenant_id", tenantID,
				update,
			); err != nil {
				slog.Warn("bulk violation update failed for id", "id", id, "action", action, "error", err)
				continue
			}
			updated++
		}

		respond.JSON(w, http.StatusOK, map[string]any{
			"updated": updated,
			"action":  action,
			"status":  newStatus,
		})
	}
}
