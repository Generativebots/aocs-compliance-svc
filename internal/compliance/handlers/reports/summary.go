// Package handlers — Analytics, Reports, Dashboards, Export handlers.
//
// These are DB-backed implementations for analytics features. Reports and
// compliance reports use the compliance_reports table. Dashboards use
// platform_config for storage. Export jobs are computed at request time.
package reports

import (
	"github.com/ocx/shared/idgen"
	"encoding/json"
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

// HandleGetAnalyticsQuery — POST /api/v1/analytics/query
// Was returning HTTP 501. Now performs real DB reads across key
// analytics tables and returns aggregated results keyed to the requested metric.

// generatePlatformID generates a platform-standard ID: YYYYMM + 8 UPPERCASE alphanumeric chars.
func generatePlatformID() string { return idgen.GenID() }

func HandleGetAnalyticsQuery(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		respond.LimitBody(r)

		var body AnalyticsQueryRequest2
		respond.LimitBody(r)
		if !validate.Bind(w, r, &body) {
			return
		}
		if body.Metric == "" {
			body.Metric = "overview"
		}

		// Aggregate across key analytics tables based on requested metric
		result := map[string]any{
			"tenant_id":  tenantID,
			"metric":     body.Metric,
			"queried_at": time.Now().UTC().Format(time.RFC3339),
		}

		switch body.Metric {
		case "usage", "usage_by_agent":
			var events []map[string]any
			if _dbErr := db.QueryRowsCtx(r.Context(), database.TblQuotaUsage, "agent_id,cost_units,metric_name,created_at", "tenant_id", tenantID, &events); _dbErr != nil {
				slog.Error("db.QueryRows failed (best-effort)", "error", _dbErr)
			}
			totals := map[string]float64{}
			for _, e := range events {
				aid, _ := e["agent_id"].(string)
				cu, _ := e["cost_units"].(float64)
				if aid != "" {
					totals[aid] += cu
				}
			}
			agents := make([]map[string]any, 0, len(totals))
			for id, cu := range totals {
				agents = append(agents, map[string]any{"agent_id": id, "cost_units": cu})
			}
			result["usage_by_agent"] = agents
			result["total_events"] = len(events)

		case "evidence", "evidence_chain":
			var records []map[string]any
			if _dbErr := db.QueryRowsCtx(r.Context(), database.TblCoreEvidence, "evidence_record_id,agent_id,type,tampered,created_at", "tenant_id", tenantID, &records); _dbErr != nil {
				slog.Error("db.QueryRows failed (best-effort)", "error", _dbErr)
			}
			byType := map[string]int{}
			tampered := 0
			for _, rec := range records {
				if t, ok := rec["type"].(string); ok {
					byType[t]++
				}
				if tp, ok := rec["tampered"].(bool); ok && tp {
					tampered++
				}
			}
			result["total_records"] = len(records)
			result["by_type"] = byType
			result["tampered_count"] = tampered

		case "policies":
			var policies []map[string]any
			if _dbErr := db.QueryRowsCtx(r.Context(), database.TblQCorePolicies, "policy_id,name,status,policy_type", "tenant_id", tenantID, &policies); _dbErr != nil {
				slog.Error("db.QueryRows failed (best-effort)", "error", _dbErr)
			}
			byStatus := map[string]int{}
			for _, p := range policies {
				if s, ok := p["status"].(string); ok {
					byStatus[s]++
				}
			}
			result["total_policies"] = len(policies)
			result["by_status"] = byStatus

		case "escrow":
			var txns []map[string]any
			if _dbErr := db.QueryRowsCtx(r.Context(), database.TblCoreEscrowTxns, "status,amount", "tenant_id", tenantID, &txns); _dbErr != nil {
				slog.Error("db.QueryRows failed (best-effort)", "error", _dbErr)
			}
			held, released := 0, 0
			for _, t := range txns {
				if s, ok := t["status"].(string); ok {
					switch s {
					case "HELD":
						held++
					case "RELEASED":
						released++
					}
				}
			}
			result["total_transactions"] = len(txns)
			result["held"] = held
			result["released"] = released

		default: // "overview" and any unrecognised metric
			var agents []map[string]any
			var evidence []map[string]any
			var policies []map[string]any
			if _dbErr := db.QueryRowsCtx(r.Context(), database.TblCoreAgents, "agent_id", "tenant_id", tenantID, &agents); _dbErr != nil {
				slog.Error("db.QueryRows failed (best-effort)", "error", _dbErr)
			}
			if _dbErr := db.QueryRowsCtx(r.Context(), database.TblCoreEvidence, "evidence_record_id", "tenant_id", tenantID, &evidence); _dbErr != nil {
				slog.Error("db.QueryRows failed (best-effort)", "error", _dbErr)
			}
			if _dbErr := db.QueryRowsCtx(r.Context(), database.TblQCorePolicies, "policy_id", "tenant_id", tenantID, &policies); _dbErr != nil {
				slog.Error("db.QueryRows failed (best-effort)", "error", _dbErr)
			}
			result["total_agents"] = len(agents)
			result["total_evidence_records"] = len(evidence)
			result["total_policies"] = len(policies)
		}

		slog.Info("AnalyticsQuery executed", "metric", body.Metric, "tenant_id", tenantID)
		respond.OK(w, result)
	}
}

// REPORTS — CRUD backed by compliance_reports table

// HandleListReports removed — duplicate of handlers.HandleListComplianceReports.
// Admin /reports route wired to handlers.HandleListComplianceReports in main.go.

// HandleGetReport returns a single report by ID.
// GET /api/v1/reports/{id}
func HandleGetReport(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		reportID := mux.Vars(r)["id"]
		if reportID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}

		var result []map[string]any
		if err := db.QueryRowsCompoundCtx(r.Context(), database.TblComplianceReportsFull, database.ColsNexusComplianceReports, "compliance_report_id", reportID, "tenant_id", tenantID, &result); err != nil || len(result) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "report not found")
			return
		}
		rpt := result[0]
		// Verify tenant ownership
		if rt, ok := rpt["tenant_id"].(string); ok && rt != tenantID && tenantID != "" {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "report not found")
			return
		}
		schedule := rpt["schedule_config"]
		createdBy := rpt["created_by"]
		if createdBy == nil {
			createdBy = ""
		}
		respond.OK(w, map[string]any{
			"id":          rpt["compliance_report_id"],
			"name":        rpt["report_type"],
			"description": rpt["reason"],
			"type":        rpt["report_type"],
			"schedule":    schedule,
			"created_at":  rpt["generated_at"],
			"updated_at":  rpt["updated_at"],
			"created_by":  createdBy,
		})
	}
}

// HandleCreateReport creates a new report.
// POST /api/v1/reports
func HandleCreateReport(db database.DB) http.HandlerFunc {
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
			ReportType  string `json:"report_type"`
			Title       string `json:"title"`
			StartDate   string `json:"start_date"`
			EndDate     string `json:"end_date"`
		}
		if !validate.Bind(w, r, &req) {
			return
		}
		// B-AN1 FIX: was time.Now().UTC() (local time) — all other handlers use UTC. Standardise.
		now := time.Now().UTC()
		if req.StartDate == "" {
			req.StartDate = now.AddDate(0, 0, -30).Format(time.RFC3339)
		}
		if req.EndDate == "" {
			req.EndDate = now.Format(time.RFC3339)
		}
		row := map[string]any{
			"tenant_id":    tenantID,
			"report_type":  req.ReportType,
			"title":        req.Title,
			"start_date":   req.StartDate,
			"end_date":     req.EndDate,
			"generated_at": now.Format(time.RFC3339),
		}
		if err := db.InsertRow(database.TblSharComplianceReports, row); err != nil {
			slog.Error("CreateReport failed", "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "failed to create report", nil)
			return
		}
		respond.JSON(w, http.StatusCreated, map[string]string{"status": "created"})
	}
}

// HandleUpdateReport updates an existing report.
// PUT /api/v1/reports/{id}
func HandleUpdateReport(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		reportID := mux.Vars(r)["id"]
		if reportID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}
		respond.LimitBody(r)
		// Previously any JSON key forwarded directly to nexus_compliance_reports.
		var req struct {
			ReportType    string          `json:"report_type"`
			Status        string          `json:"status"      validate:"omitempty,oneof=PENDING RUNNING COMPLETED FAILED CANCELLED"`
			StartDate     string          `json:"start_date"`
			EndDate       string          `json:"end_date"`
			Framework     string          `json:"framework"`
			GeneratedBy   string          `json:"generated_by"`
			ReportData    json.RawMessage `json:"report_data"`
			ScheduleConfig json.RawMessage `json:"schedule_config"`
		}
		if !validate.Bind(w, r, &req) {
			return
		}
		update := map[string]any{}
		if req.ReportType != "" {
			update["report_type"] = req.ReportType
		}
		if req.Status != "" {
			if !validate.IsValidStatus("compliance_reports", strings.ToUpper(req.Status)) {
				respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "invalid status value")
				return
			}
			update["status"] = strings.ToUpper(req.Status)
		}
		if req.StartDate != "" {
			update["start_date"] = req.StartDate
		}
		if req.EndDate != "" {
			update["end_date"] = req.EndDate
		}
		if req.Framework != "" {
			update["framework"] = req.Framework
		}
		if req.GeneratedBy != "" {
			update["generated_by"] = req.GeneratedBy
		}
		if len(req.ReportData) > 0 {
			update["report_data"] = req.ReportData
		}
		if len(req.ScheduleConfig) > 0 {
			update["schedule_config"] = req.ScheduleConfig
		}
		if len(update) == 0 {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "no updatable fields provided")
			return
		}
		if err := db.UpdateRowCompound(database.TblSharComplianceReports, "compliance_report_id", reportID, "tenant_id", tenantID, update); err != nil {
			slog.Error("UpdateReport failed", "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "update_report_failed", nil)
			return
		}
		respond.OK(w, map[string]string{"status": "updated"})
	}
}

// HandleDeleteReport deletes a report.
// DELETE /api/v1/reports/{id}
func HandleDeleteReport(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		reportID := mux.Vars(r)["id"]
		if reportID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}
		// Scope delete to tenant
		if err := db.SoftDeleteRowCompound(database.TblSharComplianceReports, "compliance_report_id", reportID, "tenant_id", tenantID); err != nil {
			slog.Error("DeleteReport failed", "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "delete_report_failed", nil)
			return
		}
		respond.OK(w, map[string]string{"status": "deleted"})
	}
}

// HandleExecuteReport runs a report and returns results.
// POST /api/v1/reports/{id}/execute
func HandleExecuteReport(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		reportID := mux.Vars(r)["id"]
		if reportID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}

		var result []map[string]any
		if _dbErr := db.QueryRowsCompoundCtx(r.Context(), database.TblComplianceReportsFull, database.ColsNexusComplianceReports, "compliance_report_id", reportID, "tenant_id", tenantID, &result); _dbErr != nil {
			slog.Error("db.QueryRows failed (best-effort)", "error", _dbErr)
		}
		if len(result) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "report not found")
			return
		}
		// Verify tenant ownership
		if rt, ok := result[0]["tenant_id"].(string); ok && rt != tenantID && tenantID != "" {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "report not found")
			return
		}

		respond.OK(w, map[string]any{
			"columns": []string{"report_type", "compliance_score", "total_evidence", "verified_evidence", "policy_violations"},
			"report":  result[0],
		})
	}
}

// HandleScheduleReport persists a schedule config onto the report row.
// POST /api/v1/reports/{id}/schedule
func HandleScheduleReport(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		reportID := mux.Vars(r)["id"]
		if reportID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}
		respond.LimitBody(r)
		// Previously any JSON key could be written to schedule_config JSONB.
		var schedReq struct {
			CronExpression string `json:"cron_expression"`
			Timezone       string `json:"timezone"`
			Enabled        *bool  `json:"enabled"`
			NextRunAt      string `json:"next_run_at"`
			NotifyEmails   []string `json:"notify_emails"`
		}
		if !validate.Bind(w, r, &schedReq) {
			return
		}
		schedData, _ := json.Marshal(schedReq)
		patch := map[string]any{
			"schedule_config": string(schedData),
		}
		// Scope update to tenant
		if err := db.UpdateRowCompound(database.TblSharComplianceReports, "compliance_report_id", reportID, "tenant_id", tenantID, patch); err != nil {
			slog.Error("ScheduleReport persist failed", "report_id", reportID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "failed to persist schedule", nil)
			return
		}
		respond.OK(w, map[string]string{"status": "scheduled", "report_id": reportID})
	}
}

// EXPORT — stateless export generation

// HandleCreateExport persists an export job record and returns 202 Accepted.
// POST /api/v1/export
func HandleCreateExport(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		respond.LimitBody(r)
		respond.LimitBody(r)
		var req struct {
			Format     string         `json:"format"      validate:"required"`
			EntityType string         `json:"entity_type"`
			Filters    map[string]any `json:"filters"`
			Name       string         `json:"name"`
		}
		if !validate.Bind(w, r, &req) {
			return
		}
		now := time.Now().UTC().Format(time.RFC3339)
		// SCHEMA FIX: aocs_bulk_import_jobs (TblCoreJobs) columns:
		// job_id(PK), tenant_id, status, job_type, export_type, format, metadata, created_at.
		// entity_type/filters/name/updated_at do NOT exist on this table.
		row := map[string]any{
			"tenant_id":   tenantID,
			"format":      req.Format,
			"job_type":    req.EntityType, // maps to job_type discriminator
			"status":      "PENDING",
			"created_at":  now,
		}
		if err := db.InsertRow(database.TblCoreJobs, row); err != nil {
			slog.Error("CreateExport insert failed", "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "failed to create export job", nil)
			return
		}
		respond.JSON(w, http.StatusAccepted, map[string]any{
			"status":      "PENDING",
			"format":      req.Format,
			"entity_type": req.EntityType,
			"created_at":  now,
			"message":     "export job queued; poll GET /export/{id} for status",
		})
	}
}

// HandleGetExportStatus returns the live status of a persisted export job.
// GET /api/v1/export/{id}
func HandleGetExportStatus(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		jobID := mux.Vars(r)["id"]
		if jobID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}
		var rows []map[string]any
		// SCHEMA FIX: PK on aocs_bulk_import_jobs is 'job_id', not 'export_job_id'.
		if err := db.QueryRowsCompoundCtx(r.Context(), database.TblCoreJobs, database.ColsReportExportJobs, "job_id", jobID, "tenant_id", tenantID, &rows); err != nil || len(rows) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "export job not found")
			return
		}
		// Verify tenant ownership
		if rt, ok := rows[0]["tenant_id"].(string); ok && rt != tenantID && tenantID != "" {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "export job not found")
			return
		}
		respond.OK(w, rows[0])
	}
}

// HandleExportDownload serves the exported file for download.
// GET /api/v1/export/{id}/download
func HandleExportDownload(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		jobID := mux.Vars(r)["id"]
		if jobID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}
		var rows []map[string]any
		// SCHEMA FIX: PK is 'job_id'; 'download_url' doesn't exist (real col is 'file_url').
		if err := db.QueryRowsCtx(r.Context(), database.TblCoreJobs, "status,file_url,tenant_id", "job_id", jobID, &rows); err != nil || len(rows) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "export job not found")
			return
		}
		// Verify tenant ownership
		if rt, ok := rows[0]["tenant_id"].(string); ok && rt != tenantID && tenantID != "" {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "export job not found")
			return
		}
		status, _ := rows[0]["status"].(string)
		if status != "COMPLETED" {
			respond.ErrorWithCode(w, http.StatusConflict, respond.ErrCodeConflict, "export job not yet completed; status: "+status)
			return
		}
		downloadURL, _ := rows[0]["file_url"].(string)
		if downloadURL == "" {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "download URL not available")
			return
		}
		http.Redirect(w, r, downloadURL, http.StatusFound)
	}
}

// DASHBOARDS — stored in platform_config as JSON

// HandleListDashboards lists all dashboards.
// GET /api/v1/dashboards
func HandleListDashboards(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var result []map[string]any
		if _dbErr := db.QueryRowsCtx(r.Context(), database.TblPlatformConfig, database.ColsAocsPlatformConfig, "category", "dashboard_"+tenantID, &result); _dbErr != nil {
			slog.Error("db.QueryRows failed (best-effort)", "error", _dbErr)
		}
		if result == nil {
			result = []map[string]any{}
		}

		dashboards := make([]map[string]any, 0, len(result))
		for _, cfg := range result {
			dashboards = append(dashboards, map[string]any{
				"id":          cfg["key"],
				"name":        cfg["key"],
				"description": "",
				"widgets": []map[string]any{
					{
						"id":          "w1",
						"type":        "chart",
						"title":       "Overview",
						"data_source": database.TblCoreAgents,
						"config": map[string]any{
							"refresh_interval": 30,
							"color_scheme":     "default",
							"show_legend":      true,
						},
						"position": map[string]any{
							"x":      0,
							"y":      0,
							"width":  6,
							"height": 4,
						},
					},
				},
			})
		}
		respond.OK(w, dashboards)
	}
}

// HandleGetDashboard returns a single dashboard from core_gov_config.
// GET /api/v1/dashboards/{id}
func HandleGetDashboard(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		dashID := mux.Vars(r)["id"]
		if dashID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}
		var rows []map[string]any
		if _dbErr := db.QueryRowsCompound(database.TblPlatformConfig, database.ColsAocsPlatformConfig,
			"category", "dashboard_"+tenantID, "key", dashID, &rows); _dbErr != nil {
			slog.Error("db.QueryRowsCompound failed (best-effort)", "error", _dbErr)
		}
		if len(rows) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "dashboard not found")
			return
		}
		respond.OK(w, rows[0])
	}
}

// HandleCreateDashboard creates a new dashboard in core_gov_config.
// POST /api/v1/dashboards
func HandleCreateDashboard(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		respond.LimitBody(r)
		// are structured. Inner widget config is preserved as JSONB.
		// Previously the full raw body was stored, allowing category/key/tenant injection.
		var req struct {
			Name        string         `json:"name"`
			Description string         `json:"description"`
			Layout      map[string]any `json:"layout"`
			Widgets     []map[string]any `json:"widgets"`
			Settings    map[string]any `json:"settings"`
		}
		if !validate.Bind(w, r, &req) {
			return
		}
		name := req.Name
		if name == "" {
			name = "untitled-" + time.Now().UTC().Format("20060102T150405")
		}
		// Use UUID as the PK so concurrent creates don't collide.
		dashID := generatePlatformID()
		now := time.Now().UTC().Format(time.RFC3339)
		dashContent := map[string]any{
			"name":        name,
			"description": req.Description,
			"layout":      req.Layout,
			"widgets":     req.Widgets,
			"settings":    req.Settings,
		}
		// core_gov_config: record_key (NOT NULL), record_value, category, tenant_id.
		// updated_at is DB-managed. No key/value columns — use record_key/record_value.
		cfg := map[string]any{
			"tenant_id":    tenantID,
			"category":     "dashboard_" + tenantID,
			"record_key":   dashID,
			"record_value": dashContent,
		}
		if err := db.InsertRow(database.TblPlatformConfig, cfg); err != nil {
			slog.Error("CreateDashboard insert failed", "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "failed to create dashboard", nil)
			return
		}
		respond.JSON(w, http.StatusCreated, map[string]any{
			"id":         dashID,
			"name":       name,
			"created_at": now,
		})
	}
}

// HandleUpdateDashboard persists dashboard changes to core_gov_config.
// PUT /api/v1/dashboards/{id}
func HandleUpdateDashboard(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		dashID := mux.Vars(r)["id"]
		if dashID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}
		respond.LimitBody(r)
		var req struct {
			Name        string         `json:"name"`
			Description string         `json:"description"`
			Layout      map[string]any `json:"layout"`
			Widgets     []map[string]any `json:"widgets"`
			Settings    map[string]any `json:"settings"`
		}
		if !validate.Bind(w, r, &req) {
			return
		}
		dashContent := map[string]any{
			"name":        req.Name,
			"description": req.Description,
			"layout":      req.Layout,
			"widgets":     req.Widgets,
			"settings":    req.Settings,
		}
		patch := map[string]any{
			"value": dashContent,
		}
		// Propagate update errors to client instead of silently swallowing.
		if err := db.UpdateRowCompound(database.TblPlatformConfig,
			"category", "dashboard_"+tenantID, "key", dashID, patch); err != nil {
			slog.Error("UpdateDashboard failed", "dashboard_id", dashID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "failed to update dashboard", nil)
			return
		}
		respond.OK(w, map[string]any{"status": "updated", "id": dashID})
	}
}

// NOTE: HandleDeleteDashboard is declared in analytics_economics.go.
// NOTE: HandleGetAnalyticsQuery (full implementation) is declared below in analytics_economics.go.
// Do NOT re-declare here — duplicate symbol compile error.
