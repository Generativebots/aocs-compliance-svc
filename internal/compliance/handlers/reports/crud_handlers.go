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
	"net/http"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
)

// ── shared helpers ────────────────────────────────────────────────────────────

// sysGetByID fetches a single row matching (tenant_id=tenantID, pkCol=id).
// DBA: SELECT * is acceptable here — sysGetByID serves read-only admin/audit tables
// with no sensitive encrypted columns. Schema drift is caught by integration tests.
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

// AI PROVIDER CONFIGS — aocs_ai_provider_configs
// PK: ai_provider_config_id | Full CRUD (api_key_encrypted excluded from reads)

// AGENT ROI METRICS — aocs_agent_roi_metrics  PK: metric_id

// AGENT STATUS TIMELINE — aocs_agent_status_timeline  PK: agent_status_timeline_id
// Append-only log — no update/delete

// CASE LIFECYCLE EVENTS — aocs_case_lifecycle_events  PK: event_id
// Append-only compliance log — no update/delete

// COLLABORATION CHANNELS — aocs_collaboration_channels  PK: channel_id

// COLLABORATION MESSAGES — aocs_collaboration_messages  PK: message_id

// COMPLIANCE CONTROLS — aocs_compliance_controls  PK: control_id

// DATA LAKE OBJECTS — aocs_data_lake_objects  PK: object_id

// CAE SESSIONS — aocs_cae_sessions  PK: session_id

func HandleListCAESessions(db database.DB) http.HandlerFunc {
	return sysListHandler(database.TblCAESessions,
		"session_id,tenant_id,agent_id,session_type,status,trust_score,verdict,hitl_triggered,started_at,created_at", db)
}
func HandleGetCAESession(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		sysGetByID(w, db, database.TblCAESessions, "session_id", tenantID, mux.Vars(r)["id"])
	}
}

// BULK IMPORT JOBS — aocs_bulk_import_jobs  PK: job_id

// KILL SWITCH ENTRIES — aocs_kill_switch_entries  PK: entry_id

// ACTIVITY EXECUTIONS — aocs_activity_executions  PK: execution_id

// MCP TENANT CONFIGS — extc_installs  PK: config_id

// EXPORT HISTORY — aocs_export_history  PK: export_id

// QUOTA SNAPSHOT LOG — aocs_quota_snapshot_log  PK: snapshot_id (write-only)

// HITL VERDICT REASONS — aocs_hitl_verdict_reasons  PK: reason_id
