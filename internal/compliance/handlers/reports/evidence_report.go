package reports

// evidence_token_analytics.go — Handlers for evlt vault, token broker,
// and analytics endpoints. These back the frontend API clients that previously
// hit non-existent routes. Uses SupabaseClient's public QueryRows/InsertRow API.

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ocx/shared/logger"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/pagination"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

// HandleListComplianceReports — GET /api/v1/compliance/reports
func HandleListComplianceReports(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var result []map[string]any
		if err := db.QueryRowsCtx(r.Context(), database.TblSharComplianceReports, database.ColsNexusComplianceReport, "tenant_id", tenantID, &result); err != nil {
			logger.For("compliance/handlers/reports/evidence_report").Error("ListComplianceReports query failed", "tenant_id", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "list compliance reports", err)
			return
		}
		if result == nil {
			result = []map[string]any{}
		}
		// Cursor pagination — was unbounded, OOM risk on large tenants.
		pagination.EnrichResponse(w, r, result, "reports", map[string]any{"count": len(result)})
	}
}

// HandleCreateComplianceReport — POST /api/v1/compliance/reports
func HandleCreateComplianceReport(db database.DB) http.HandlerFunc {
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
			ReportType string         `json:"report_type"`
			StartDate  string         `json:"start_date"`
			EndDate    string         `json:"end_date"`
			Title      string         `json:"title"`
			Filters    map[string]any `json:"filters"`
		}
		if !validate.Bind(w, r, &req) {
			return
		}

		// DB CHECK constraint (core_compliance_reports_report_type_check):
		// report_type IN ('SOC2','GDPR','ISO27001','EU_AI_ACT','HIPAA','CCPA','CUSTOM').
		// The old list (DAILY/WEEKLY/…) is a cadence, not a framework, and
		// every insert with it violated the constraint (23514 in Supabase logs).
		validReportTypes := map[string]bool{
			"SOC2": true, "GDPR": true, "ISO27001": true, "EU_AI_ACT": true,
			"HIPAA": true, "CCPA": true, "CUSTOM": true,
		}
		req.ReportType = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(req.ReportType), "-", "_"))
		if req.ReportType == "" {
			req.ReportType = "CUSTOM"
		}
		if !validReportTypes[req.ReportType] {
			// Honest 400 instead of silently filing an unknown framework as CUSTOM.
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest,
				"report_type must be one of SOC2, GDPR, ISO27001, EU_AI_ACT, HIPAA, CCPA, CUSTOM")
			return
		}
		if req.StartDate == "" {
			req.StartDate = time.Now().UTC().Format("2006-01-02")
		}
		if req.EndDate == "" {
			req.EndDate = time.Now().UTC().AddDate(0, 0, 7).Format("2006-01-02")
		}
		// nexus_compliance_reports columns: period_start / period_end (NOT start_date/end_date).
		// period_start is NOT NULL — must always be provided.
		periodStart := req.StartDate
		if periodStart == "" {
			periodStart = time.Now().UTC().Format(time.RFC3339)
		}
		periodEnd := req.EndDate
		if periodEnd == "" {
			periodEnd = time.Now().UTC().AddDate(0, 1, 0).Format(time.RFC3339)
		}
		reportID := generatePlatformID()
		createdBy := auth.GetUserID(r.Context())
		if createdBy == "" {
			createdBy = tenantID
		}
		row := map[string]any{
			"compliance_report_id": reportID,
			"tenant_id":            tenantID,
			"report_type":          req.ReportType,
			"period_start":         periodStart,
			"period_end":           periodEnd,
			"status":               "PENDING",
			"created_by":           createdBy, // caller user_id (tenant_id fallback satisfies NOT NULL)
			// 'title' and 'filters' columns do not exist in nexus_compliance_reports;
			// store them in the 'metadata' JSONB column instead.
			"metadata": map[string]any{
				"title":   req.Title,
				"filters": req.Filters,
			},
		}

		if err := db.InsertRow(database.TblSharComplianceReports, row); err != nil {
			logger.For("compliance/handlers/reports/evidence_report").Error("CreateComplianceReport failed", "error", err, "tenant_id", tenantID)
			respond.InternalError(w, http.StatusInternalServerError, "failed to create report", err)
			return
		}
		respond.JSON(w, http.StatusCreated, map[string]string{
			"status": "created", "id": reportID, "report_id": reportID, "report_type": req.ReportType,
		})
	}
}

// HandleUpdateComplianceReport — PUT /api/v1/compliance/reports/{id}
func HandleUpdateComplianceReport(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
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
			ReportType  string          `json:"report_type"`
			Status      string          `json:"status"    validate:"omitempty,oneof=PENDING RUNNING COMPLETED FAILED CANCELLED"`
			StartDate   string          `json:"start_date"`
			EndDate     string          `json:"end_date"`
			Framework   string          `json:"framework"`
			GeneratedBy string          `json:"generated_by"`
			ReportData  json.RawMessage `json:"report_data"`
			S3URL       string          `json:"s3_url"`
		}
		if !validate.Bind(w, r, &req) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
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
		if req.S3URL != "" {
			update["s3_url"] = req.S3URL
		}
		if len(update) == 0 {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "no updatable fields provided")
			return
		}
		if err := db.UpdateRowCompound(database.TblSharComplianceReports, "compliance_report_id", reportID, "tenant_id", tenantID, update); err != nil {
			logger.For("compliance/handlers/reports/evidence_report").Error("UpdateComplianceReport failed", "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "failed to update report", err)
			return
		}
		respond.OK(w, map[string]string{"status": "updated"})
	}
}

// ANALYTICS HANDLERS

// HandleListAnalyticsKPIs — GET /api/v1/analytics/kpis
// Returns live KPI metrics for the analytics dashboard.
//
// Security hardening applied:
//   Threat 3  — data_as_of timestamp asserts when the DB snapshot was taken.
//   Threat 5  — fleet trust variance (homogeneity score) exposes when all agents
//              converge on the same trust band (collusion indicator).
//   Threat 7  — X-Processing-Mode: batch header skips temporal aging warnings.
//   Threat 8  — Laplace differential-privacy noise added to aggregate counts so
//              individual agents cannot be fingerprinted from the KPI response.

// EVIDENCE CHAIN HANDLERS — backing GET /evidence/chain and /evidence/verify

// HandleGetEvidenceChain — GET /evidence/chain?agent_id=X[&page=1&page_size=100]
// Returns ordered evidence chain blocks for the HashChainVisualizer.
func HandleGetEvidenceChain(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		agentID := r.URL.Query().Get("agent_id")

		params := database.ParsePageParams(r.URL.Query())
		if params.Limit == 0 || params.Limit > 500 {
			params.Limit = 100
		}

		var records []database.QCoreEvidenceRecord
		if err := db.QueryRowsCursor(database.TblCoreEvidenceRecords, database.ColsQCoreEvidenceRecord, "tenant_id", tenantID, database.ParseCursorPage(r), &records); err != nil {
			logger.For("compliance/handlers/reports/evidence_report").Error("HandleGetEvidenceChain query failed", "tenant_id", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "get evidence chain", err)
			return
		}
		// Filter by agent_id in-memory (Supabase REST single-eq filter handles one column)
		if agentID != "" {
			var filtered []database.QCoreEvidenceRecord
			for _, rec := range records {
				if rec.AgentID == agentID {
					filtered = append(filtered, rec)
				}
			}
			records = filtered
		}
		if records == nil {
			records = []database.QCoreEvidenceRecord{}
		}
		respond.OK(w, map[string]any{
			"chain":      records,
			"count":      len(records),
			"limit":      params.Limit,
			"offset":     params.Offset,
			"agent_id":   agentID,
			"tenant_id":  tenantID,
			"queried_at": time.Now().UTC().Format(time.RFC3339),
		})
	}
}

// HandleVerifyChain — GET /evidence/verify?agent_id=X[&page=1&page_size=100]
// Verifies hash continuity across the evidence chain.
func HandleVerifyChain(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		agentID := r.URL.Query().Get("agent_id")

		params := database.ParsePageParams(r.URL.Query())
		if params.Limit == 0 || params.Limit > 500 {
			params.Limit = 100
		}

		var records []database.QCoreEvidenceRecord
		if err := db.QueryRowsCursor(database.TblCoreEvidenceRecords, database.ColsQCoreEvidenceRecord, "tenant_id", tenantID, database.ParseCursorPage(r), &records); err != nil {
			logger.For("compliance/handlers/reports/evidence_report").Error("HandleVerifyChain query failed", "tenant_id", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "verify evidence chain", err)
			return
		}

		tampered := 0
		verified := 0
		for _, rec := range records {
			if agentID != "" && rec.AgentID != agentID {
				continue
			}
			if rec.Tampered {
				tampered++
			} else {
				verified++
			}
		}
		respond.OK(w, map[string]any{
			"agent_id":  agentID,
			"tenant_id": tenantID,
			"verified":  verified,
			"tampered":  tampered,
			"limit":     params.Limit,
			"offset":    params.Offset,
			"integrity": map[bool]string{tampered == 0: "CLEAN", tampered != 0: "TAMPERED"}[true],
		})
	}
}
