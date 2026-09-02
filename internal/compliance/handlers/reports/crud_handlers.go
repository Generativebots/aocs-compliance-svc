// Package analytics — full CRUD handlers for P2b high-value tables and system tables.
//
// Every table has GET (list + by-ID), POST (create), PATCH (update), and
// DELETE/archive where semantically correct. All handlers are:
//   - Tenant-scoped via auth.MustGetTenantID
//   - Body-validated (required fields checked before DB call)
//   - Using exact DB interface signatures: InsertRow(table, row) error
//     UpdateRowCompound(table, col1, val1, col2, val2, updates) error
//     DeleteRowCompound(table, col1, val1, col2, val2) error
package reports

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

// ── shared helpers ────────────────────────────────────────────────────────────

func decodeBody(w http.ResponseWriter, r *http.Request, dst *map[string]any) bool {
	// B6 FIX: Limit request body to 2MB to prevent DoS via oversized payloads.
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	// validate.Bind handles *map[string]any: decodes JSON + calls MarkValidated
	// (StructOnly skips tag checks for non-struct types but still marks validated).
	return validate.Bind(w, r, dst)
}

func requireField(w http.ResponseWriter, body map[string]any, field string) (string, bool) {
	v, ok := body[field].(string)
	if !ok || v == "" {
		respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, field+" is required")
		return "", false
	}
	return v, true
}

func noContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

// sysGetByID fetches a single row matching (tenant_id=tenantID, pkCol=id).
func sysGetByID(w http.ResponseWriter, db database.DB, tbl, pkCol, tenantID, id string) {
	var rows []map[string]any
	if err := db.QueryRowsCompound(tbl, "*", "tenant_id", tenantID, pkCol, id, &rows); err != nil || len(rows) == 0 {
		respond.NotFound(w, tbl+" not found")
		return
	}
	respond.OK(w, rows[0])
}

// ADMIN AUDIT LOG — aocs_admin_audit_log
// PK: audit_id | Operations: list, get, create (immutable — no update/delete)

func HandleListAdminAuditLog(db database.DB) http.HandlerFunc {
	return sysListHandler(database.TblAdminAuditLog, "*", db)
}
func HandleGetAdminAuditLogEntry(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		sysGetByID(w, db, database.TblAdminAuditLog, "audit_id", tenantID, mux.Vars(r)["id"])
	}
}
func HandleCreateAdminAuditLog(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		var body map[string]any
		if !decodeBody(w, r, &body) { return }
		body["tenant_id"] = tenantID
		body["created_at"] = time.Now().UTC()
		if _, ok := requireField(w, body, "operation"); !ok { return }
		if _, ok := requireField(w, body, "resource_type"); !ok { return }
		if err := db.InsertRow(database.TblAdminAuditLog, body); err != nil {
			slog.Error("HandleCreateAdminAuditLog", "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "create audit log failed", err)
			return
		}
		respond.Created(w, body)
	}
}

// AI PROVIDER CONFIGS — aocs_ai_provider_configs
// PK: ai_provider_config_id | Full CRUD (api_key_encrypted excluded from reads)

func HandleListAIProviderConfigs(db database.DB) http.HandlerFunc {
	return sysListHandler(database.TblAIProviderConfigs,
		"ai_provider_config_id,tenant_id,provider_name,display_name,model,base_url,is_active,is_default,monthly_quota_tokens,max_requests_per_hour,dlp_enabled,created_at,updated_at", db)
}
func HandleGetAIProviderConfig(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		sysGetByID(w, db, database.TblAIProviderConfigs, "ai_provider_config_id", tenantID, mux.Vars(r)["id"])
	}
}
func HandleCreateAIProviderConfig(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		var body map[string]any
		if !decodeBody(w, r, &body) { return }
		body["tenant_id"] = tenantID
		body["created_at"] = time.Now().UTC()
		body["updated_at"] = time.Now().UTC()
		if _, ok := requireField(w, body, "provider_name"); !ok { return }
		if _, ok := requireField(w, body, "model"); !ok { return }
		if err := db.InsertRow(database.TblAIProviderConfigs, body); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "create AI provider config failed", err)
			return
		}
		respond.Created(w, body)
	}
}
func HandleUpdateAIProviderConfig(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		id, idOk := respond.MustGetPathParam(w, r, "id")
		if !idOk { return }
		var body map[string]any
		if !decodeBody(w, r, &body) { return }
		body["updated_at"] = time.Now().UTC()
		delete(body, "tenant_id"); delete(body, "ai_provider_config_id"); delete(body, "api_key_encrypted")
		if err := db.UpdateRowCompound(database.TblAIProviderConfigs, "tenant_id", tenantID, "ai_provider_config_id", id, body); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "update failed", err)
			return
		}
		respond.OK(w, map[string]any{"updated": true, "id": id})
	}
}
func HandleDeleteAIProviderConfig(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		id, idOk := respond.MustGetPathParam(w, r, "id")
		if !idOk { return }
		if err := db.DeleteRowCompound(database.TblAIProviderConfigs, "tenant_id", tenantID, "ai_provider_config_id", id); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "delete failed", err)
			return
		}
		noContent(w)
	}
}

// AGENT ROI METRICS — aocs_agent_roi_metrics  PK: metric_id

func HandleListAgentROIMetrics(db database.DB) http.HandlerFunc {
	return sysListHandler(database.TblAgentROIMetrics, "*", db)
}
func HandleCreateAgentROIMetric(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		var body map[string]any
		if !decodeBody(w, r, &body) { return }
		body["tenant_id"] = tenantID
		body["created_at"] = time.Now().UTC()
		if _, ok := requireField(w, body, "agent_id"); !ok { return }
		if err := db.InsertRow(database.TblAgentROIMetrics, body); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "record ROI metric failed", err)
			return
		}
		respond.Created(w, body)
	}
}
func HandleUpdateAgentROIMetric(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		id, idOk := respond.MustGetPathParam(w, r, "id")
		if !idOk { return }
		var body map[string]any
		if !decodeBody(w, r, &body) { return }
		body["updated_at"] = time.Now().UTC()
		delete(body, "tenant_id"); delete(body, "metric_id")
		if err := db.UpdateRowCompound(database.TblAgentROIMetrics, "tenant_id", tenantID, "metric_id", id, body); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "update failed", err)
			return
		}
		respond.OK(w, map[string]any{"updated": true, "id": id})
	}
}

// AGENT STATUS TIMELINE — aocs_agent_status_timeline  PK: agent_status_timeline_id
// Append-only log — no update/delete

func HandleListAgentStatusTimeline(db database.DB) http.HandlerFunc {
	return sysListHandler(database.TblCoreAgentStatus, "*", db)
}
func HandleCreateAgentStatusEvent(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		var body map[string]any
		if !decodeBody(w, r, &body) { return }
		body["tenant_id"] = tenantID
		body["created_at"] = time.Now().UTC()
		body["recorded_at"] = time.Now().UTC()
		if _, ok := requireField(w, body, "agent_id"); !ok { return }
		if _, ok := requireField(w, body, "new_status"); !ok { return }
		if err := db.InsertRow(database.TblCoreAgentStatus, body); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "record status event failed", err)
			return
		}
		respond.Created(w, body)
	}
}

// CASE LIFECYCLE EVENTS — aocs_case_lifecycle_events  PK: event_id
// Append-only compliance log — no update/delete

func HandleListCaseLifecycleEvents(db database.DB) http.HandlerFunc {
	return sysListHandler(database.TblCaseLifecycleEvents, "*", db)
}
func HandleCreateCaseLifecycleEvent(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		var body map[string]any
		if !decodeBody(w, r, &body) { return }
		body["tenant_id"] = tenantID
		body["created_at"] = time.Now().UTC()
		if _, ok := requireField(w, body, "event_type"); !ok { return }
		if err := db.InsertRow(database.TblCaseLifecycleEvents, body); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "create lifecycle event failed", err)
			return
		}
		respond.Created(w, body)
	}
}

// COLLABORATION CHANNELS — aocs_collaboration_channels  PK: channel_id

func HandleListCollaborationChannels(db database.DB) http.HandlerFunc {
	return sysListHandler(database.TblCollaborationChannels,
		"channel_id,tenant_id,name,description,channel_type,visibility,is_active,is_archived,created_at,updated_at", db)
}
func HandleGetCollaborationChannel(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		sysGetByID(w, db, database.TblCollaborationChannels, "channel_id", tenantID, mux.Vars(r)["id"])
	}
}
func HandleCreateCollaborationChannel(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		var body map[string]any
		if !decodeBody(w, r, &body) { return }
		body["tenant_id"] = tenantID
		body["is_active"] = true
		body["is_archived"] = false
		body["created_at"] = time.Now().UTC()
		body["updated_at"] = time.Now().UTC()
		if _, ok := requireField(w, body, "name"); !ok { return }
		if _, ok := requireField(w, body, "channel_type"); !ok { return }
		if err := db.InsertRow(database.TblCollaborationChannels, body); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "create channel failed", err)
			return
		}
		respond.Created(w, body)
	}
}
func HandleUpdateCollaborationChannel(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		id, idOk := respond.MustGetPathParam(w, r, "id")
		if !idOk { return }
		var body map[string]any
		if !decodeBody(w, r, &body) { return }
		body["updated_at"] = time.Now().UTC()
		delete(body, "tenant_id"); delete(body, "channel_id")
		if err := db.UpdateRowCompound(database.TblCollaborationChannels, "tenant_id", tenantID, "channel_id", id, body); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "update failed", err)
			return
		}
		respond.OK(w, map[string]any{"updated": true, "id": id})
	}
}
func HandleArchiveCollaborationChannel(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		id, idOk := respond.MustGetPathParam(w, r, "id")
		if !idOk { return }
		patch := map[string]any{"is_archived": true, "is_active": false, "updated_at": time.Now().UTC()}
		if err := db.UpdateRowCompound(database.TblCollaborationChannels, "tenant_id", tenantID, "channel_id", id, patch); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "archive failed", err)
			return
		}
		respond.OK(w, map[string]any{"archived": true, "id": id})
	}
}

// COLLABORATION MESSAGES — aocs_collaboration_messages  PK: message_id

func HandleListCollaborationMessages(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		channelID, idOk := respond.MustGetPathParam(w, r, "channel_id")
		if !idOk { return }
		if channelID == "" { channelID = r.URL.Query().Get("channel_id") }
		pp := parseLimit(r, 50, 200)
		cols := "message_id,tenant_id,channel_id,user_id,message_type,content,created_at,updated_at"
		var rows []map[string]any
		var err error
		if channelID != "" {
			err = db.QueryRowsCompound(database.TblCollaborationMessages, cols, "tenant_id", tenantID, "channel_id", channelID, &rows)
		} else {
			err = db.QueryRowsLimited(database.TblCollaborationMessages, cols, "tenant_id", tenantID, pp, &rows)
		}
		if err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "messages query failed", err)
			return
		}
		if rows == nil { rows = []map[string]any{} }
		respond.OK(w, map[string]any{"messages": rows, "count": len(rows)})
	}
}
func HandleCreateCollaborationMessage(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		var body map[string]any
		if !decodeBody(w, r, &body) { return }
		body["tenant_id"] = tenantID
		body["created_at"] = time.Now().UTC()
		body["updated_at"] = time.Now().UTC()
		if _, ok := requireField(w, body, "channel_id"); !ok { return }
		if _, ok := requireField(w, body, "content"); !ok { return }
		if _, ok := body["message_type"].(string); !ok { body["message_type"] = "text" }
		if err := db.InsertRow(database.TblCollaborationMessages, body); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "send message failed", err)
			return
		}
		respond.Created(w, body)
	}
}

// COMPLIANCE CONTROLS — aocs_compliance_controls  PK: control_id

func HandleListComplianceControls(db database.DB) http.HandlerFunc {
	return sysListHandler(database.TblComplianceControls, "*", db)
}
func HandleGetComplianceControl(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		sysGetByID(w, db, database.TblComplianceControls, "control_id", tenantID, mux.Vars(r)["id"])
	}
}
func HandleCreateComplianceControl(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		var body map[string]any
		if !decodeBody(w, r, &body) { return }
		body["tenant_id"] = tenantID
		body["created_at"] = time.Now().UTC()
		body["last_checked_at"] = time.Now().UTC()
		if _, ok := requireField(w, body, "framework"); !ok { return }
		if _, ok := requireField(w, body, "title"); !ok { return }
		if _, ok := body["status"].(string); !ok { body["status"] = "pending" }
		if _, ok := body["evidence_count"]; !ok { body["evidence_count"] = 0 }
		if err := db.InsertRow(database.TblComplianceControls, body); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "create control failed", err)
			return
		}
		respond.Created(w, body)
	}
}
func HandleUpdateComplianceControl(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		id, idOk := respond.MustGetPathParam(w, r, "id")
		if !idOk { return }
		var body map[string]any
		if !decodeBody(w, r, &body) { return }
		body["last_checked_at"] = time.Now().UTC()
		delete(body, "tenant_id"); delete(body, "control_id"); delete(body, "created_at")
		if err := db.UpdateRowCompound(database.TblComplianceControls, "tenant_id", tenantID, "control_id", id, body); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "update failed", err)
			return
		}
		respond.OK(w, map[string]any{"updated": true, "id": id})
	}
}

// DATA LAKE OBJECTS — aocs_data_lake_objects  PK: object_id

func HandleListDataLakeObjects(db database.DB) http.HandlerFunc {
	return sysListHandler(database.TblDataLakeObjects,
		"object_id,tenant_id,object_type,source_type,source_id,name,mime_type,size_bytes,checksum,version,created_at", db)
}
func HandleGetDataLakeObject(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		sysGetByID(w, db, database.TblDataLakeObjects, "object_id", tenantID, mux.Vars(r)["id"])
	}
}
func HandleCreateDataLakeObject(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		var body map[string]any
		if !decodeBody(w, r, &body) { return }
		body["tenant_id"] = tenantID
		body["created_at"] = time.Now().UTC()
		body["updated_at"] = time.Now().UTC()
		if _, ok := requireField(w, body, "name"); !ok { return }
		if _, ok := requireField(w, body, "object_type"); !ok { return }
		if _, ok := requireField(w, body, "source_type"); !ok { return }
		if _, ok := body["version"]; !ok { body["version"] = "1" }
		if err := db.InsertRow(database.TblDataLakeObjects, body); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "register data lake object failed", err)
			return
		}
		respond.Created(w, body)
	}
}
func HandleDeleteDataLakeObject(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		id, idOk := respond.MustGetPathParam(w, r, "id")
		if !idOk { return }
		if err := db.DeleteRowCompound(database.TblDataLakeObjects, "tenant_id", tenantID, "object_id", id); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "delete failed", err)
			return
		}
		noContent(w)
	}
}

// CAE SESSIONS — aocs_cae_sessions  PK: session_id

func HandleListCAESessions(db database.DB) http.HandlerFunc {
	return sysListHandler(database.TblCAESessions,
		"session_id,tenant_id,agent_id,session_type,status,trust_score,verdict,hitl_triggered,started_at,created_at", db)
}
func HandleGetCAESession(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		sysGetByID(w, db, database.TblCAESessions, "session_id", tenantID, mux.Vars(r)["id"])
	}
}
func HandleCreateCAESession(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		var body map[string]any
		if !decodeBody(w, r, &body) { return }
		now := time.Now().UTC()
		body["tenant_id"] = tenantID
		body["started_at"] = now
		body["created_at"] = now
		body["updated_at"] = now
		if _, ok := body["status"].(string); !ok { body["status"] = "open" }
		if err := db.InsertRow(database.TblCAESessions, body); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "create CAE session failed", err)
			return
		}
		respond.Created(w, body)
	}
}
func HandleUpdateCAESession(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		id, idOk := respond.MustGetPathParam(w, r, "id")
		if !idOk { return }
		var body map[string]any
		if !decodeBody(w, r, &body) { return }
		body["updated_at"] = time.Now().UTC()
		delete(body, "tenant_id"); delete(body, "session_id")
		if err := db.UpdateRowCompound(database.TblCAESessions, "tenant_id", tenantID, "session_id", id, body); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "update failed", err)
			return
		}
		respond.OK(w, map[string]any{"updated": true, "id": id})
	}
}

// BULK IMPORT JOBS — aocs_bulk_import_jobs  PK: job_id

func HandleListBulkImportJobs(db database.DB) http.HandlerFunc {
	return sysListHandler(database.TblBulkImportJobs,
		"job_id,tenant_id,status,total_rows,processed_rows,success_rows,failed_rows,file_name,created_by,created_at,completed_at", db)
}
func HandleGetBulkImportJob(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		sysGetByID(w, db, database.TblBulkImportJobs, "job_id", tenantID, mux.Vars(r)["id"])
	}
}
func HandleCreateBulkImportJob(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		var body map[string]any
		if !decodeBody(w, r, &body) { return }
		body["tenant_id"] = tenantID
		body["status"] = "pending"
		body["processed_rows"] = 0
		body["success_rows"] = 0
		body["failed_rows"] = 0
		body["created_at"] = time.Now().UTC()
		body["updated_at"] = time.Now().UTC()
		if _, ok := requireField(w, body, "file_name"); !ok { return }
		if err := db.InsertRow(database.TblBulkImportJobs, body); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "create import job failed", err)
			return
		}
		respond.Created(w, body)
	}
}
func HandleUpdateBulkImportJob(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		id, idOk := respond.MustGetPathParam(w, r, "id")
		if !idOk { return }
		var body map[string]any
		if !decodeBody(w, r, &body) { return }
		body["updated_at"] = time.Now().UTC()
		delete(body, "tenant_id"); delete(body, "job_id")
		if err := db.UpdateRowCompound(database.TblBulkImportJobs, "tenant_id", tenantID, "job_id", id, body); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "update failed", err)
			return
		}
		respond.OK(w, map[string]any{"updated": true, "id": id})
	}
}

// KILL SWITCH ENTRIES — aocs_kill_switch_entries  PK: entry_id

func HandleCreateKillSwitchEntry(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		var body map[string]any
		if !decodeBody(w, r, &body) { return }
		body["tenant_id"] = tenantID
		body["is_active"] = true
		body["created_at"] = time.Now().UTC()
		body["updated_at"] = time.Now().UTC()
		if _, ok := requireField(w, body, "subject_id"); !ok { return }
		if _, ok := requireField(w, body, "reason"); !ok { return }
		if err := db.InsertRow(database.TblCoreKillSwitch, body); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "create kill switch failed", err)
			return
		}
		respond.Created(w, body)
	}
}
func HandleDeactivateKillSwitch(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		id, idOk := respond.MustGetPathParam(w, r, "id")
		if !idOk { return }
		patch := map[string]any{"is_active": false, "updated_at": time.Now().UTC()}
		if err := db.UpdateRowCompound(database.TblCoreKillSwitch, "tenant_id", tenantID, "entry_id", id, patch); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "deactivation failed", err)
			return
		}
		respond.OK(w, map[string]any{"deactivated": true, "id": id})
	}
}

// ACTIVITY EXECUTIONS — aocs_activity_executions  PK: execution_id

func HandleCreateActivityExecution(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		var body map[string]any
		if !decodeBody(w, r, &body) { return }
		body["tenant_id"] = tenantID
		body["status"] = "running"
		body["created_at"] = time.Now().UTC()
		body["updated_at"] = time.Now().UTC()
		if _, ok := requireField(w, body, "activity_id"); !ok { return }
		if err := db.InsertRow(database.TblActivityExecutions, body); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "create execution failed", err)
			return
		}
		respond.Created(w, body)
	}
}
func HandleUpdateActivityExecution(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		id, idOk := respond.MustGetPathParam(w, r, "id")
		if !idOk { return }
		var body map[string]any
		if !decodeBody(w, r, &body) { return }
		body["updated_at"] = time.Now().UTC()
		delete(body, "tenant_id"); delete(body, "execution_id")
		if err := db.UpdateRowCompound(database.TblActivityExecutions, "tenant_id", tenantID, "execution_id", id, body); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "update failed", err)
			return
		}
		respond.OK(w, map[string]any{"updated": true, "id": id})
	}
}

// MCP TENANT CONFIGS — extc_installs  PK: config_id

func HandleCreateMCPTenantConfig(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		var body map[string]any
		if !decodeBody(w, r, &body) { return }
		body["tenant_id"] = tenantID
		body["created_at"] = time.Now().UTC()
		body["updated_at"] = time.Now().UTC()
		if _, ok := requireField(w, body, "server_id"); !ok { return }
		if err := db.InsertRow(database.TblMCPTenantConfigs, body); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "create MCP config failed", err)
			return
		}
		respond.Created(w, body)
	}
}
func HandleUpdateMCPTenantConfig(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		id, idOk := respond.MustGetPathParam(w, r, "id")
		if !idOk { return }
		var body map[string]any
		if !decodeBody(w, r, &body) { return }
		body["updated_at"] = time.Now().UTC()
		delete(body, "tenant_id"); delete(body, "config_id")
		if err := db.UpdateRowCompound(database.TblMCPTenantConfigs, "tenant_id", tenantID, "config_id", id, body); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "update failed", err)
			return
		}
		respond.OK(w, map[string]any{"updated": true, "id": id})
	}
}

// EXPORT HISTORY — aocs_export_history  PK: export_id

func HandleCreateExportJob(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		var body map[string]any
		if !decodeBody(w, r, &body) { return }
		body["tenant_id"] = tenantID
		body["status"] = "pending"
		body["created_at"] = time.Now().UTC()
		if _, ok := requireField(w, body, "export_type"); !ok { return }
		if err := db.InsertRow(database.TblExportHistory, body); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "create export job failed", err)
			return
		}
		respond.Created(w, body)
	}
}
func HandleUpdateExportJob(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		id, idOk := respond.MustGetPathParam(w, r, "id")
		if !idOk { return }
		var body map[string]any
		if !decodeBody(w, r, &body) { return }
		delete(body, "tenant_id"); delete(body, "export_id")
		if err := db.UpdateRowCompound(database.TblExportHistory, "tenant_id", tenantID, "export_id", id, body); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "update failed", err)
			return
		}
		respond.OK(w, map[string]any{"updated": true, "id": id})
	}
}

// QUOTA SNAPSHOT LOG — aocs_quota_snapshot_log  PK: snapshot_id (write-only)

func HandleCreateQuotaSnapshot(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		var body map[string]any
		if !decodeBody(w, r, &body) { return }
		body["tenant_id"] = tenantID
		body["created_at"] = time.Now().UTC()
		if _, ok := requireField(w, body, "resource_type"); !ok { return }
		if err := db.InsertRow(database.TblQuotaSnapshotLog, body); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "record quota snapshot failed", err)
			return
		}
		respond.Created(w, body)
	}
}

// HITL VERDICT REASONS — aocs_hitl_verdict_reasons  PK: reason_id

func HandleListVerdictReasons(db database.DB) http.HandlerFunc {
	return sysListHandler(database.TblHITLVerdictReasons, "verdict_reason_id,tenant_id,decision_id,reason_code,description,created_at", db)
}
func HandleCreateVerdictReason(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		var body map[string]any
		if !decodeBody(w, r, &body) { return }
		body["tenant_id"] = tenantID
		body["is_active"] = true
		body["created_at"] = time.Now().UTC()
		body["updated_at"] = time.Now().UTC()
		if _, ok := requireField(w, body, "label"); !ok { return }
		if _, ok := requireField(w, body, "verdict"); !ok { return }
		if err := db.InsertRow(database.TblHITLVerdictReasons, body); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "create verdict reason failed", err)
			return
		}
		respond.Created(w, body)
	}
}
func HandleUpdateVerdictReason(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		id, idOk := respond.MustGetPathParam(w, r, "id")
		if !idOk { return }
		var body map[string]any
		if !decodeBody(w, r, &body) { return }
		body["updated_at"] = time.Now().UTC()
		delete(body, "tenant_id"); delete(body, "reason_id")
		if err := db.UpdateRowCompound(database.TblHITLVerdictReasons, "tenant_id", tenantID, "reason_id", id, body); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "update failed", err)
			return
		}
		respond.OK(w, map[string]any{"updated": true, "id": id})
	}
}
func HandleDeleteVerdictReason(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) { return }
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok { return }
		id, idOk := respond.MustGetPathParam(w, r, "id")
		if !idOk { return }
		// Soft delete: deactivate rather than hard delete (audit trail preserved)
		patch := map[string]any{"is_active": false, "updated_at": time.Now().UTC()}
		if err := db.UpdateRowCompound(database.TblHITLVerdictReasons, "tenant_id", tenantID, "reason_id", id, patch); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "deactivation failed", err)
			return
		}
		noContent(w)
	}
}
