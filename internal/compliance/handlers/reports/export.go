package reports

import (
	"log/slog"
	"net/http"

	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
)

// HandleExportHistory — GET /api/v1/export/history
// Returns a list of past data export jobs for the tenant.
// Used by the analytics dashboard to show export audit trail.
func HandleExportHistory(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		// nexus_export_jobs is the canonical export table (nexus_exports does not exist in schema)
		var rows []struct {
			ID          string `json:"id"`
			TenantID    string `json:"tenant_id"`
			ExportType  string `json:"export_type"` // mapped from job_type
			Status      string `json:"status"`
			RecordCount int64  `json:"record_count"` // mapped from file_size
			FilePath    string `json:"file_path"`    // mapped from download_url
			CreatedAt   string `json:"created_at"`
			CompletedAt string `json:"completed_at"`
		}
		if err := db.QueryRowsCtx(r.Context(), database.TblCoreEvents,
			"id,tenant_id,job_type,status,file_size,download_url,created_at,completed_at",
			"tenant_id", tenantID, &rows); err != nil {
			slog.Error("HandleExportHistory: query failed", "tenant_id", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "load export history", err)
			return
		}
		if rows == nil {
			rows = []struct {
				ID          string `json:"id"`
				TenantID    string `json:"tenant_id"`
				ExportType  string `json:"export_type"`
				Status      string `json:"status"`
				RecordCount int64  `json:"record_count"`
				FilePath    string `json:"file_path"`
				CreatedAt   string `json:"created_at"`
				CompletedAt string `json:"completed_at"`
			}{}
		}
		respond.OK(w, rows)
	}
}

// HANDLER-1 FIX: Canonical name alias — HandleListExportHistory is the enterprise AIP standard name.
// Handle{Verb}{Noun} where Verb ∈ {Create, Get, List, Update, Delete}.
// HandleExportHistory kept for backward compatibility; new code should use HandleListExportHistory.
var HandleListExportHistory = HandleExportHistory
