package compliance

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
)

// DashboardSummaryResponse consolidates parallel dashboard queries into a single round-trip (GAP-P3).
type DashboardSummaryResponse struct {
	TenantID     string           `json:"tenant_id"`
	GeneratedAt  string           `json:"generated_at"`
	OverallScore *float64         `json:"overall_score"` // nil when the tenant has no obligations (no score earned yet)
	Reports      []map[string]any `json:"reports"`
	Violations   []map[string]any `json:"violations"`
	Frameworks   []map[string]any `json:"frameworks"`
	DLP          map[string]any   `json:"dlp"`
	History7D    []map[string]any `json:"history_7d"`
	History90D   []map[string]any `json:"history_90d"`
}

// HandleGetComplianceDashboardSummary — GET /compliance/dashboard-summary
// Batches reports, violations, dlp scans, framework breakdown, and 7d history into 1 payload.
func HandleGetComplianceDashboardSummary(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		now := time.Now().UTC()

		// 1. Reports (recent 5)
		var reports []map[string]any
		if err := db.QueryRowsCompound(database.TblComplReports,
			"report_id, framework, status, compliance_score, total_controls, passed_controls, certifier_name, created_at, updated_at",
			"tenant_id", tenantID, "status", "pending", &reports); err != nil {
			// No "all reports" substitute: a failed read is reported as a failure.
			dashboardReadFailed(w, tenantID, err)
			return
		}
		if reports == nil {
			reports = []map[string]any{}
		}
		if len(reports) > 5 {
			reports = reports[:5]
		}

		// 2. Violations / Enforcement actions
		var violations []map[string]any
		if err := db.QueryRows(database.TblCoreEnforcementActions,
			database.ColsEnforcementActions,
			"tenant_id", tenantID, &violations); err != nil {
			dashboardReadFailed(w, tenantID, err)
			return
		}
		if violations == nil {
			violations = []map[string]any{}
		}
		if len(violations) > 100 {
			violations = violations[:100]
		}

		// 3. Frameworks from compl_obligations
		var obligations []map[string]any
		if err := db.QueryRows(database.TblComplObligations,
			"control_id,name,control_ref,framework,status",
			"tenant_id", tenantID, &obligations); err != nil {
			slog.Warn("READ_DEGRADED: compliance dashboard obligations read failed",
				"tenant_id", tenantID, "error", err)
		}
		if obligations == nil {
			obligations = []map[string]any{}
		}

		fwMap := make(map[string]map[string]any)
		totalPassed := 0
		for _, ob := range obligations {
			fw, _ := ob["framework"].(string)
			if fw == "" {
				fw = "SOC2"
			}
			st, _ := ob["status"].(string)
			entry, exists := fwMap[fw]
			if !exists {
				entry = map[string]any{
					"framework": fw,
					"total":     0,
					"passed":    0,
					"score":     0.0,
				}
				fwMap[fw] = entry
			}
			tot := entry["total"].(int) + 1
			entry["total"] = tot
			if st == "COMPLIANT" || st == "PASSED" {
				pass := entry["passed"].(int) + 1
				entry["passed"] = pass
				totalPassed++
			}
			entry["score"] = (float64(entry["passed"].(int)) / float64(tot)) * 100.0
		}

		var frameworks []map[string]any
		for _, v := range fwMap {
			frameworks = append(frameworks, v)
		}
		if frameworks == nil {
			frameworks = []map[string]any{}
		}

		var overallScore *float64
		if len(obligations) > 0 {
			sc := (float64(totalPassed) / float64(len(obligations))) * 100.0
			overallScore = &sc
		}

		// 4. DLP telemetry. Quarantines are core_enforcement_actions rows with
		// subtype dlp_quarantine (see security/dlp_quarantine.go); a quarantine
		// stays open until it is released.
		var dlpEvidence []map[string]any
		if err := db.QueryRowsCompound(database.TblComplEvidence,
			"evidence_id, title, framework, created_at",
			"tenant_id", tenantID, "evidence_type", "DLP_SCAN", &dlpEvidence); err != nil {
			dashboardReadFailed(w, tenantID, err)
			return
		}
		dlpCount := len(dlpEvidence)
		var lastScanned any
		lastScannedStr := ""
		for _, e := range dlpEvidence {
			if c, _ := e["created_at"].(string); c > lastScannedStr {
				lastScannedStr = c
			}
		}
		if lastScannedStr != "" {
			lastScanned = lastScannedStr
		}

		var qRows []map[string]any
		if err := db.QueryRows(database.TblCoreEnforcementActions,
			"subtype,status,released_at,created_at",
			"tenant_id", tenantID, &qRows); err != nil {
			dashboardReadFailed(w, tenantID, err)
			return
		}
		quarantined := 0
		for _, q := range qRows {
			if st, _ := q["subtype"].(string); st != "dlp_quarantine" {
				continue
			}
			if q["released_at"] != nil {
				continue
			}
			if s, _ := q["status"].(string); strings.EqualFold(s, "resolved") || strings.EqualFold(s, "released") {
				continue
			}
			quarantined++
		}

		// clean_rate is only defined once something has been scanned.
		var cleanRate any
		if dlpCount > 0 {
			cr := 100.0 * (1 - float64(quarantined)/float64(dlpCount))
			if cr < 0 {
				cr = 0
			}
			cleanRate = cr
		}

		dlpStats := map[string]any{
			"total_scanned": dlpCount,
			"quarantined":   quarantined,
			"clean_rate":    cleanRate,
			"last_scanned":  lastScanned,
		}

		// 5. 7-Day History
		var historyRows []map[string]any
		sevenDaysAgo := now.AddDate(0, 0, -7).Format(time.RFC3339)
		if err := db.QueryRowsCompound(database.TblComplReports,
			"report_id, framework, compliance_score, created_at",
			"tenant_id", tenantID, "status", "CERTIFIED", &historyRows); err != nil {
			dashboardReadFailed(w, tenantID, err)
			return
		}
		// DAILY posture snapshots written by the report worker (report_snapshot.go).
		var dailyRows []map[string]any
		if err := db.QueryRowsCompound(database.TblComplReports,
			"report_id, framework, compliance_score, created_at",
			"tenant_id", tenantID, "report_type", "DAILY", &dailyRows); err != nil {
			dashboardReadFailed(w, tenantID, err)
			return
		}
		historyRows = append(historyRows, dailyRows...)

		var history7d, history90d []map[string]any
		ninetyDaysAgo := now.AddDate(0, 0, -90).Format(time.RFC3339)
		for _, h := range historyRows {
			cat, _ := h["created_at"].(string)
			if cat >= sevenDaysAgo {
				history7d = append(history7d, h)
			}
			if cat >= ninetyDaysAgo {
				history90d = append(history90d, h)
			}
		}
		if history7d == nil {
			history7d = []map[string]any{}
		}
		if history90d == nil {
			history90d = []map[string]any{}
		}

		resp := DashboardSummaryResponse{
			TenantID:     tenantID,
			GeneratedAt:  now.Format(time.RFC3339),
			OverallScore: overallScore,
			Reports:      reports,
			Violations:   violations,
			Frameworks:   frameworks,
			DLP:          dlpStats,
			History7D:    history7d,
			History90D:   history90d,
		}

		slog.Debug("HandleGetComplianceDashboardSummary served", "tenant_id", tenantID, "frameworks", len(frameworks))
		respond.JSON(w, http.StatusOK, resp)
	}
}

// dashboardReadFailed answers 503 when a dashboard input could not be read,
// instead of rendering zeros as if the tenant had no violations/evidence.
func dashboardReadFailed(w http.ResponseWriter, tenantID string, err error) {
	slog.Error("compliance dashboard: input read failed", "tenant_id", tenantID, "error", err)
	respond.ErrorWithCode(w, http.StatusServiceUnavailable, respond.ErrCodeUnavailable,
		"compliance data could not be read")
}
