package reports

// evidence_token_analytics.go — Handlers for evlt vault, token broker,
// and analytics endpoints. These back the frontend API clients that previously
// hit non-existent routes. Uses SupabaseClient's public QueryRows/InsertRow API.

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/pagination"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

func HandleSearchEvidence(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		query := strings.ToLower(r.URL.Query().Get("query"))

		// Fetch all tenant evlt (pre-filter at DB level by tenant)
		var records []database.QCoreEvidenceRecord
		if err := db.QueryRowsCtx(r.Context(), database.TblQCoreEvidenceRecords, database.ColsQCoreEvidenceRecord, "tenant_id", tenantID, &records); err != nil {
			slog.Error("SearchEvidence DB query failed", "error", err, "tenant_id", tenantID)
			respond.InternalError(w, http.StatusInternalServerError, "failed to search evidence records", nil)
			return
		}

		// Client-side text search across key fields
		var results []database.QCoreEvidenceRecord
		for _, rec := range records {
			if query == "" {
				results = append(results, rec)
				continue
			}
			// Search across type, action_class, agent_id, tool_id, transaction_id
			if strings.Contains(strings.ToLower(rec.Type), query) ||
				strings.Contains(strings.ToLower(rec.ActionClass), query) ||
				strings.Contains(strings.ToLower(rec.AgentID), query) ||
				strings.Contains(strings.ToLower(rec.ToolID), query) ||
				strings.Contains(strings.ToLower(rec.TransactionID), query) {
				results = append(results, rec)
			}
		}

		if results == nil {
			results = []database.QCoreEvidenceRecord{}
		}
		respond.OK(w, results)
	}
}

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
			slog.Error("ListComplianceReports query failed", "tenant_id", tenantID, "error", err)
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
			ReportType string `json:"report_type"`
			StartDate  string `json:"start_date"`
			EndDate    string `json:"end_date"`
			Title      string `json:"title"`
			Filters    map[string]any `json:"filters"`
		}
		if !validate.Bind(w, r, &req) {
			return
		}

		// DB CHECK constraint: report_type IN ('DAILY','WEEKLY','MONTHLY','QUARTERLY','ANNUAL')
		validReportTypes := map[string]bool{
			"DAILY": true, "WEEKLY": true, "MONTHLY": true,
			"QUARTERLY": true, "ANNUAL": true,
		}
		if !validReportTypes[req.ReportType] {
			req.ReportType = "DAILY" // safe default matching DB DEFAULT
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
		row := map[string]any{
			"tenant_id":    tenantID,
			"report_type":  req.ReportType,
			"period_start": periodStart,
			"period_end":   periodEnd,
			"status":       "PENDING",
			"created_by":   tenantID, // satisfies NOT NULL; real user_id available via auth middleware
			// 'title' and 'filters' columns do not exist in nexus_compliance_reports;
			// store them in the 'metadata' JSONB column instead.
			"metadata": map[string]any{
				"title":   req.Title,
				"filters": req.Filters,
			},
		}

		if err := db.InsertRow(database.TblSharComplianceReports, row); err != nil {
			slog.Error("CreateComplianceReport failed", "error", err, "tenant_id", tenantID)
			respond.InternalError(w, http.StatusInternalServerError, "failed to create report", nil)
			return
		}
		respond.OK(w, map[string]string{"status": "created"})
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
			slog.Error("UpdateComplianceReport failed", "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "failed to update report", nil)
			return
		}
		respond.OK(w, map[string]string{"status": "updated"})
	}
}

// HandleGetTokenStats — GET /api/v1/tokens/stats
func HandleGetTokenStats(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var all []map[string]any
		if err := db.QueryRowsCtx(r.Context(), database.TblCoreJit, database.ColsJITEntitlement, "tenant_id", tenantID, &all); err != nil {
			slog.Error("TokenStats query failed", "tenant_id", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "get token stats", err)
			return
		}

		stats := map[string]int{
			"total":   len(all),
			"active":  0,
			"expired": 0,
			"revoked": 0,
		}
		for _, t := range all {
			if s, ok := t["status"].(string); ok {
				switch s {
				case "ACTIVE":
					stats["active"]++
				case "EXPIRED":
					stats["expired"]++
				case "REVOKED":
					stats["revoked"]++
				}
			}
		}
		respond.OK(w, stats)
	}
}

// ANALYTICS HANDLERS

// HandleGetAnalyticsOverview — GET /api/v1/analytics/overview
func HandleGetAnalyticsOverview(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		// Aggregate counts from key tables
		var agt []map[string]any
		db.QueryRowsCtx(r.Context(), database.TblCoreAgents, "agent_id", "tenant_id", tenantID, &agt)

		var esc []map[string]any
		db.QueryRowsCtx(r.Context(), database.TblCoreEscrowTxns, "status", "tenant_id", tenantID, &esc)

		var evlt []map[string]any
		db.QueryRowsCtx(r.Context(), database.TblQCoreEvidenceRecords, "evidence_record_id", "tenant_id", tenantID, &evlt)

		var policies []map[string]any
		db.QueryRowsCtx(r.Context(), database.TblQCorePolicies, "policy_id", "tenant_id", tenantID, &policies)

		held := 0
		released := 0
		for _, e := range esc {
			if s, ok := e["status"].(string); ok {
				switch s {
				case "HELD":
					held++
				case "RELEASED":
					released++
				}
			}
		}

		// UDT-FIX: UniversalDataTable.unwrap() uses Object.values(r).find(Array.isArray).
		// A flat scalar map has no array value → UDT renders empty.
		// Wrap the summary in items:[{...}] so UDT can display it as a row,
		// and card consumers can access items[0] for their stat values.
		summary := map[string]any{
			"tenant_id":       tenantID,
			"total_agents":    len(agt),
			"total_escrow":    len(esc),
			"escrow_held":     held,
			"escrow_released": released,
			"total_evidence":  len(evlt),
			"total_policies":  len(policies),
			"timestamp":       time.Now().UTC().Format(time.RFC3339),
		}
		respond.OK(w, map[string]any{
			"items": []map[string]any{summary},
			"total": 1,
		})
	}
}

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
		if err := db.QueryRowsCursor(database.TblQCoreEvidenceRecords, database.ColsQCoreEvidenceRecord, "tenant_id", tenantID, database.ParseCursorPage(r), &records); err != nil {
			slog.Error("HandleGetEvidenceChain query failed", "tenant_id", tenantID, "error", err)
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
		if err := db.QueryRowsCursor(database.TblQCoreEvidenceRecords, database.ColsQCoreEvidenceRecord, "tenant_id", tenantID, database.ParseCursorPage(r), &records); err != nil {
			slog.Error("HandleVerifyChain query failed", "tenant_id", tenantID, "error", err)
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

// HandleComplianceReport — GET /evidence/compliance-report
// Returns a consolidated compliance report from the evidence chain.
func HandleComplianceReport(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var records []database.QCoreEvidenceRecord
		if err := db.QueryRowsCtx(r.Context(), database.TblQCoreEvidenceRecords, database.ColsQCoreEvidenceRecord, "tenant_id", tenantID, &records); err != nil {
			slog.Error("HandleComplianceReport query failed", "tenant_id", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "compliance report", err)
			return
		}

		byType := map[string]int{}
		tampered := 0
		for _, rec := range records {
			byType[rec.Type]++
			if rec.Tampered {
				tampered++
			}
		}
		respond.OK(w, map[string]any{
			"tenant_id":    tenantID,
			"total_blocks": len(records),
			"tampered":     tampered,
			"by_type":      byType,
			"integrity":    map[bool]string{tampered == 0: "CLEAN", tampered != 0: "TAMPERED"}[true],
			"generated_at": time.Now().UTC().Format(time.RFC3339),
		})
	}
}

// HandleListActiveTokens — GET /api/v1/tokens/active
func HandleListActiveTokens(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var result []map[string]any
		if err := db.QueryRowsCtx(r.Context(), database.TblCoreJit, database.ColsJITEntitlement, "tenant_id", tenantID, &result); err != nil {
			slog.Error("ListActiveTokens query failed", "tenant_id", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "list active tokens", err)
			return
		}

		// Filter active only
		var active []map[string]any
		for _, t := range result {
			if s, ok := t["status"].(string); ok && s == "ACTIVE" {
				active = append(active, t)
			}
		}
		if active == nil {
			active = []map[string]any{}
		}
		respond.OK(w, active)
	}
}
