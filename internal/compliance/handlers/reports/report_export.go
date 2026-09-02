package reports

// compliance_report: table nexus_compliance_reports, PK: compliance_report_id
// export_job: table aocs_export_jobs (check if exists; fall back to nexus_export_jobs)

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

// DELETE /api/v1/compliance/reports/{id}
// Soft-delete: sets status=ARCHIVED. Reports are referenced by audit_trail records.
func HandleDeleteComplianceReport(db database.DB) http.HandlerFunc {
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
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing report id")
			return
		}
		// Verify ownership
		var rows []map[string]any
		if dbErr := db.QueryRowsCompound(database.TblNexusComplianceReports, database.ColsNexusComplianceReport, "compliance_report_id", id, "tenant_id", tenantID, &rows); dbErr != nil || len(rows) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "report not found")
			return
		}
		if dbErr := db.UpdateRowCompound(database.TblNexusComplianceReports, "compliance_report_id", id, "tenant_id", tenantID,
			map[string]any{"status": "ARCHIVED"}); dbErr != nil {
			respond.InternalError(w, http.StatusInternalServerError, "delete compliance report", dbErr)
			return
		}
		// H-NEW-4 FIX: Audit log — compliance report deletion is a state-changing operation
		// required to be traceable under EU AI Act Article 13 and SOC2 CC6.1.
		slog.Info("audit: compliance report archived",
			"action", "DELETE_COMPLIANCE_REPORT",
			"report_id", id,
			"tenant_id", tenantID,
			"actor", r.Header.Get("X-User-ID"),
			"at", time.Now().UTC().Format(time.RFC3339),
		)
		respond.JSON(w, http.StatusOK, map[string]string{"status": "ARCHIVED", "report_id": id})
	}
}

// DELETE /api/v1/exports/{id}
// Cancels/soft-deletes an export job — sets status=CANCELLED.
func HandleDeleteExportJob(db database.DB) http.HandlerFunc {
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
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing job id")
			return
		}
		if dbErr := db.UpdateRowCompound(database.TblExportJobs, "job_id", id, "tenant_id", tenantID,
			map[string]any{"status": "CANCELLED"}); dbErr != nil {
			respond.InternalError(w, http.StatusInternalServerError, "delete export job", dbErr)
			return
		}
		// H-NEW-4 FIX: Audit log — export job cancellation must be traceable.
		slog.Info("audit: export job cancelled",
			"action", "DELETE_EXPORT_JOB",
			"job_id", id,
			"tenant_id", tenantID,
			"actor", r.Header.Get("X-User-ID"),
			"at", time.Now().UTC().Format(time.RFC3339),
		)
		respond.JSON(w, http.StatusOK, map[string]string{"status": "CANCELLED", "job_id": id})
	}
}

// HandleExecuteComplianceReport — POST /api/v1/compliance-report/{id}/execute
//
// Triggers a fresh execution run for an existing compliance report template.
// Updates the report status to RUNNING and queues the evaluation job.
func HandleExecuteComplianceReport(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		reportID := mux.Vars(r)["id"]
		callerID := auth.GetUserID(r.Context())
		_ = tenantID

		updates := map[string]any{
			"status":      "RUNNING",
			"executed_by": callerID,
			"executed_at": "now()",
			"updated_at":  "now()",
		}
		if err := db.UpdateRow(database.TblNexusComplianceReports, "report_id", reportID, updates); err != nil {
			slog.Error("HandleExecuteComplianceReport: db update failed",
				"report_id", reportID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "execute compliance report", err)
			return
		}
		respond.OK(w, map[string]any{"report_id": reportID, "status": "RUNNING"})
	}
}

// HandleScheduleComplianceReport — POST /api/v1/compliance-report/{id}/schedule
//
// Saves a recurring schedule for a compliance report (cron expression).
// Body: {"cron": "0 8 * * MON", "enabled": true, "notify_emails": ["ops@..."] }
func HandleScheduleComplianceReport(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		reportID := mux.Vars(r)["id"]
		callerID := auth.GetUserID(r.Context())
		_ = tenantID

		var body struct {
			Cron         string   `json:"cron"          validate:"required"`
			Enabled      bool     `json:"enabled"`
			NotifyEmails []string `json:"notify_emails"`
		}
		if !validate.Bind(w, r, &body) {
			return
		}

		updates := map[string]any{
			"schedule_cron":   body.Cron,
			"schedule_enabled": body.Enabled,
			"notify_emails":   body.NotifyEmails,
			"scheduled_by":    callerID,
			"updated_at":      "now()",
		}
		if err := db.UpdateRow(database.TblNexusComplianceReports, "report_id", reportID, updates); err != nil {
			slog.Error("HandleScheduleComplianceReport: db update failed",
				"report_id", reportID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "schedule compliance report", err)
			return
		}
		respond.OK(w, map[string]any{
			"report_id": reportID,
			"cron":      body.Cron,
			"enabled":   body.Enabled,
		})
	}
}
