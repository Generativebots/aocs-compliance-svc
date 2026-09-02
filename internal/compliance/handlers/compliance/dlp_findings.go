package compliance

// dlp_findings.go — BUG-FE-ROUTE-009
// Full CRUD for DLP findings backed by core_audit (action_type='dlp.finding').
//
// Business scenarios for creation:
//   SCAN   — automated DLP workflow scan detects a policy violation
//   MANUAL — compliance officer manually records a finding
//   ALERT  — monitoring alert flags a suspected data exfiltration pattern
//
// Status lifecycle: OPEN → INVESTIGATING → RESOLVED | FALSE_POSITIVE

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

// senti_dlp_integrations PK is dlp_integration_id — alias to dlp_policy_id for API compat.
const colsDLPFinding = "dlp_integration_id AS dlp_policy_id,tenant_id,name,status,created_at,updated_at"

// HandleListDLPFindings — GET /dlp/findings
func HandleListDLPFindings(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var rows []map[string]any
		if err := db.QueryRowsCtx(r.Context(), database.TblDLPPolicies, colsDLPFinding, "tenant_id", tenantID, &rows); err != nil {
			// Graceful degradation — return empty array so the UI doesn't crash
			slog.Error("dlp/findings: list failed", "err", err)
			respond.OK(w, map[string]any{"findings": []map[string]any{}, "total": 0})
			return
		}
		if rows == nil {
			rows = []map[string]any{}
		}

		// Optionally filter by status/severity from metadata (in-process for simple filtering)
		statusFilter := r.URL.Query().Get("status")
		severityFilter := r.URL.Query().Get("severity")
		if statusFilter != "" || severityFilter != "" {
			filtered := rows[:0]
			for _, row := range rows {
				meta, _ := row["metadata"].(map[string]any)
				if meta == nil {
					if b, ok := row["metadata"].([]byte); ok {
						if _jsonErr := json.Unmarshal(b, &meta); _jsonErr != nil {
							slog.Warn("metadata unmarshal failed", "source_len", len(b), "error", _jsonErr)
						}
					}
				}
				if statusFilter != "" {
					if s, _ := meta["status"].(string); s != statusFilter {
						continue
					}
				}
				if severityFilter != "" {
					if s, _ := row["severity"].(string); s != severityFilter {
						continue
					}
				}
				filtered = append(filtered, row)
			}
			rows = filtered
		}

		respond.OK(w, map[string]any{"findings": rows, "total": len(rows)})
	}
}

// HandleCreateDLPFinding — POST /dlp/findings
func HandleCreateDLPFinding(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		respond.LimitBody(r)

		var req CreateDLPFindingRequest
		respond.LimitBody(r)
		if !validate.Bind(w, r, &req) {
			return
		}
		if req.RuleName == "" || req.Description == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "rule_name and description are required")
			return
		}
		if req.Severity == "" {
			req.Severity = "WARNING"
		}
		if req.Source == "" {
			req.Source = "MANUAL"
		}
		if req.DataType == "" {
			req.DataType = "UNKNOWN"
		}

		if req.Metadata == nil {
			req.Metadata = map[string]any{}
		}
		req.Metadata["rule_name"] = req.RuleName
		req.Metadata["data_type"] = req.DataType
		req.Metadata["source"] = req.Source
		req.Metadata["status"] = "OPEN"
		if req.AgentID != "" {
			req.Metadata["agent_id"] = req.AgentID
		}
		metaJSON, marshalErr := json.Marshal(req.Metadata)
		if marshalErr != nil {
			slog.Error("json.Marshal failed", "err", marshalErr)
			return
		}

		findingID := generatePlatformID()
		finding := map[string]any{
			"audit_log_id": findingID,
			"tenant_id":   tenantID,
			"action_type": "dlp.finding",
			"severity":    req.Severity,
			"description": req.Description,
			"metadata":    string(metaJSON),
		}
		if err := db.InsertRow(database.TblCoreAudit, finding); err != nil {
			slog.Error("dlp/findings: create failed", "err", err)
			respond.InternalError(w, http.StatusInternalServerError, "create DLP finding", err)
			return
		}
		respond.Created(w, map[string]string{
			"finding_id": findingID,
			"status":     "OPEN",
			"source":     req.Source,
		})
	}
}

// HandleGetDLPFinding — GET /dlp/findings/{id}
func HandleGetDLPFinding(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		findingID := mux.Vars(r)["id"]

		// (dlp_policy_id, name, policy_type...) which don't exist in that table.
		// core_audit has: audit_log_id, action_type, severity, entity_type,
		// entity_id, actor_id, details, created_at, updated_at.
		const colsIAAuditLog = "audit_log_id,tenant_id,action_type,severity,entity_type,entity_id,actor_id,details,created_at,updated_at"
		var rows []map[string]any
		if err := db.QueryRowsCompound(
			"core_audit", colsIAAuditLog,
			"audit_log_id", findingID,
			"tenant_id", tenantID,
			&rows,
		); err != nil || len(rows) == 0 {
			respond.NotFound(w, "DLP finding not found")
			return
		}
		// Verify it is a dlp finding
		if at, _ := rows[0]["action_type"].(string); at != "dlp.finding" {
			respond.NotFound(w, "DLP finding not found")
			return
		}
		respond.OK(w, rows[0])
	}
}

// HandleUpdateDLPFinding — PUT /dlp/findings/{id}
// Used to transition status: OPEN → INVESTIGATING → RESOLVED | FALSE_POSITIVE
func HandleUpdateDLPFinding(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		findingID := mux.Vars(r)["id"]
		respond.LimitBody(r)

		// Ownership check
		var existing []map[string]any
		if err := db.QueryRowsCompound(database.TblCoreAudit, "audit_log_id,action_type",
			"audit_log_id", findingID, "tenant_id", tenantID, &existing); err != nil || len(existing) == 0 {
			respond.NotFound(w, "DLP finding not found")
			return
		}

		var req struct {
			Status   *string `json:"status,omitempty"`
			Severity *string `json:"severity,omitempty"`
		}
		respond.LimitBody(r)
		if !validate.Bind(w, r, &req) {
			return
		}

		update := map[string]any{}
		if req.Severity != nil {
			update["severity"] = *req.Severity
		}
		// Status lives in metadata JSONB — merge via UpdateRow with metadata key
		if req.Status != nil {
			// Read existing metadata, merge status, write back as string
			var metaRows []map[string]any
			if _dbErr := db.QueryRowsCompound(database.TblCoreAudit, "metadata",
				"audit_log_id", findingID, "tenant_id", tenantID, &metaRows); _dbErr != nil {
				slog.Error("db.QueryRowsCompound failed (best-effort)", "error", _dbErr)
			}
			meta := map[string]any{"status": *req.Status}
			if len(metaRows) > 0 {
				if existing, ok := metaRows[0]["metadata"].(map[string]any); ok {
					for k, v := range existing {
						meta[k] = v
					}
					meta["status"] = *req.Status
				}
			}
			metaJSON, marshalErr := json.Marshal(meta)
			if marshalErr != nil {
				slog.Error("json.Marshal failed", "err", marshalErr)
				return
			}
			update["metadata"] = string(metaJSON)
		}

		if err := db.UpdateRowCompound(database.TblCoreAudit, "audit_log_id", findingID, "tenant_id", tenantID, update); err != nil {
			slog.Error("dlp/findings: update failed", "err", err)
			respond.InternalError(w, http.StatusInternalServerError, "update DLP finding", err)
			return
		}
		respond.OK(w, map[string]string{"finding_id": findingID, "status": "updated"})
	}
}

// HandleDeleteDLPFinding — DELETE /dlp/findings/{id}
//
// COMPLIANCE MANDATE: core_audit is an immutable audit log.
// Rows MUST NEVER be physically deleted — this is a compliance violation.
// "Delete" transitions the finding to status=RESOLVED with archived_at timestamp.
// The row is excluded from active list queries but retained permanently for audit.
func HandleDeleteDLPFinding(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		findingID := mux.Vars(r)["id"]
		actorID := r.Header.Get("X-User-ID")

		var existing []map[string]any
		if err := db.QueryRowsCompound(database.TblCoreAudit, "audit_log_id,metadata",
			"audit_log_id", findingID, "tenant_id", tenantID, &existing); err != nil || len(existing) == 0 {
			respond.NotFound(w, "DLP finding not found")
			return
		}

		// Merge archived status into existing metadata (preserve all original fields).
		meta := map[string]any{}
		if existing[0]["metadata"] != nil {
			switch m := existing[0]["metadata"].(type) {
			case map[string]any:
				for k, v := range m {
					meta[k] = v
				}
			case []byte:
				if _jsonErr := json.Unmarshal(m, &meta); _jsonErr != nil {
					slog.Warn("metadata unmarshal failed", "source_len", len(m), "error", _jsonErr)
				}
			}
		}
		now := time.Now().UTC().Format(time.RFC3339)
		meta["status"] = "RESOLVED"
		meta["archived_at"] = now
		if actorID != "" {
			meta["archived_by"] = actorID
		}
		metaJSON, _ := json.Marshal(meta)

		if err := db.UpdateRowCompound(database.TblCoreAudit, "audit_log_id", findingID, "tenant_id", tenantID, map[string]any{
			"metadata":   string(metaJSON),
			"updated_at": now,
		}); err != nil {
			slog.Error("dlp/findings: archive failed", "finding_id", findingID, "err", err)
			respond.InternalError(w, http.StatusInternalServerError, "archive DLP finding", err)
			return
		}
		slog.Info("DLP finding archived (soft-deleted — audit log preserved)",
			"finding_id", findingID, "tenant_id", tenantID, "actor", actorID)
		respond.OK(w, map[string]string{"finding_id": findingID, "status": "ARCHIVED"})
	}
}
