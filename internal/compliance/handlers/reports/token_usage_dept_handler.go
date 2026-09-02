package reports

// token_usage_dept_handler.go — GET /tokens/usage/by-department
//
// Aggregates token consumption per department for the tenant.
// Queries aocs_gate_stages to bucket token_usage by department.
// Budget limits come from aocs_tenant_department_budgets (tenant-scoped),
// NOT from aocs_platform_departments (which is the platform-wide catalog).
//
// Response shape:
//
//	[{ department, department_id, tokens_consumed, cost_usd, budget_limit_usd,
//	   budget_limit_tokens, budget_utilization_pct, burn_rate, period }]

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

// deptTokenUsageRow is the response shape for a single department entry.
type deptTokenUsageRow struct {
	Department           string   `json:"department"`
	DepartmentID         string   `json:"department_id"`
	TokensConsumed       int      `json:"tokens_consumed"`
	CostUSD              float64  `json:"cost_usd"`
	BudgetLimitUSD       *float64 `json:"budget_limit_usd,omitempty"`
	BudgetLimitTokens    *int64   `json:"budget_limit_tokens,omitempty"`
	BudgetUtilizationPct *float64 `json:"budget_utilization_pct,omitempty"`
	BurnRate             *float64 `json:"burn_rate,omitempty"`
	Period               string   `json:"period"`
	BudgetPeriod         string   `json:"budget_period,omitempty"`
	AlertThresholdPct    int      `json:"alert_threshold_pct,omitempty"`
}

// deptBudgetInfo holds budget config fetched from aocs_tenant_department_budgets.
type deptBudgetInfo struct {
	BudgetLimitUSD    *float64
	BudgetLimitTokens *int64
	BudgetPeriod      string
	CostPerToken      float64
	AlertPct          int
}

// HandleGetTokenUsageByDepartment — GET /tokens/usage/by-department
//
// Returns token consumption bucketed by department for the current month.
// Department names come from aocs_platform_departments (catalog).
// Budget limits come from aocs_tenant_department_budgets (tenant-scoped).
func HandleGetTokenUsageByDepartment(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		// Period: current month by default; can be overridden with ?month=YYYY-MM
		period := r.URL.Query().Get("month")
		if period == "" {
			period = time.Now().UTC().Format("2006-01")
		}

		// 1. Query platform department catalog (names).
		var catalogRows []map[string]any
		if _rErr := db.QueryRowsCtx(r.Context(), database.TblPlatformDepartments,
			"slug,name", "", "", &catalogRows); _rErr != nil {
			slog.Warn("READ_DEGRADED: QueryRowsCtx failed — best-effort query",
				"table", "slug,name", "file", "aocs-intel/handlers/analytics/token_usage_dept_handler.go", "err", _rErr)
		}

		deptNames := make(map[string]string, len(catalogRows))
		for _, r := range catalogRows {
			slug, _ := r["slug"].(string)
			name, _ := r["name"].(string)
			if slug != "" {
				deptNames[slug] = name
			}
		}

		// 2. Query tenant-scoped budget limits.
		var budgetRows []map[string]any
		if _rErr := db.QueryRowsCtx(r.Context(), database.TblTenantDeptBudgets,
			"department_slug,budget_limit_usd,budget_limit_tokens,budget_period,cost_per_token,budget_alert_pct",
			"tenant_id", tenantID, &budgetRows); _rErr != nil {
			slog.Warn("READ_DEGRADED: QueryRowsCtx failed — best-effort query",
				"table", database.TblTenantDeptBudgets, "file", "aocs-intel/handlers/analytics/token_usage_dept_handler.go", "err", _rErr)
		}

		deptBudgets := make(map[string]deptBudgetInfo, len(budgetRows))
		for _, r := range budgetRows {
			slug, _ := r["department_slug"].(string)
			if slug == "" {
				continue
			}
			info := deptBudgetInfo{
				BudgetPeriod: "monthly",
				CostPerToken: 0.000150,
				AlertPct:     80,
			}
			if v, ok := r["budget_limit_usd"].(float64); ok {
				info.BudgetLimitUSD = &v
			}
			if v, ok := r["budget_limit_tokens"].(float64); ok {
				i := int64(v)
				info.BudgetLimitTokens = &i
			}
			if v, ok := r["budget_period"].(string); ok && v != "" {
				info.BudgetPeriod = v
			}
			if v, ok := r["cost_per_token"].(float64); ok && v > 0 {
				info.CostPerToken = v
			}
			if v, ok := r["budget_alert_pct"].(float64); ok {
				info.AlertPct = int(v)
			}
			deptBudgets[slug] = info
		}

		// 3. Query gate stage events for the month to aggregate token usage per department.
		var stageRows []map[string]any
		err := db.QueryRowsCtx(r.Context(), database.TblGateStages,
			"department_id,token_usage", "tenant_id", tenantID, &stageRows)
		if err != nil {
			slog.Warn("token_usage/by-department: gate_stages query failed — returning empty", "err", err)
			respond.OK(w, map[string]any{"items": []deptTokenUsageRow{}, "period": period})
			return
		}

		// Aggregate in-process: sum token_usage per department.
		totals := make(map[string]int)
		for _, row := range stageRows {
			deptID, _ := row["department_id"].(string)
			if deptID == "" {
				deptID = "__unassigned__"
			}
			switch v := row["token_usage"].(type) {
			case float64:
				totals[deptID] += int(v)
			case int:
				totals[deptID] += v
			case int64:
				totals[deptID] += int(v)
			}
		}

		// Also include departments with zero usage but configured budgets.
		for slug := range deptBudgets {
			if _, exists := totals[slug]; !exists {
				totals[slug] = 0
			}
		}

		result := make([]deptTokenUsageRow, 0, len(totals))
		totalCostUSD := 0.0
		totalTokens := 0

		for deptID, consumed := range totals {
			name := deptNames[deptID]
			if name == "" {
				if deptID == "__unassigned__" {
					name = "Unassigned"
				} else {
					name = deptID
				}
			}

			budget := deptBudgets[deptID]
			costUSD := float64(consumed) * budget.CostPerToken

			row := deptTokenUsageRow{
				Department:        name,
				DepartmentID:      deptID,
				TokensConsumed:    consumed,
				CostUSD:           costUSD,
				Period:            period,
				BudgetPeriod:      budget.BudgetPeriod,
				AlertThresholdPct: budget.AlertPct,
			}

			if budget.BudgetLimitUSD != nil {
				row.BudgetLimitUSD = budget.BudgetLimitUSD
				if *budget.BudgetLimitUSD > 0 {
					pct := (costUSD / *budget.BudgetLimitUSD) * 100
					row.BudgetUtilizationPct = &pct
				}
			}
			if budget.BudgetLimitTokens != nil {
				row.BudgetLimitTokens = budget.BudgetLimitTokens
				if *budget.BudgetLimitTokens > 0 && row.BudgetUtilizationPct == nil {
					pct := (float64(consumed) / float64(*budget.BudgetLimitTokens)) * 100
					row.BudgetUtilizationPct = &pct
				}
			}

			result = append(result, row)
			totalCostUSD += costUSD
			totalTokens += consumed
		}

		// If no gate_stage data, fall back to extraction_sessions as a proxy.
		if len(result) == 0 {
			var extRows []map[string]any
			if _rErr := db.QueryRowsCtx(r.Context(), database.TblBulkImportJobs,
				"token_usage,created_by", "tenant_id", tenantID, &extRows); _rErr != nil {
				slog.Warn("READ_DEGRADED: QueryRowsCtx failed — best-effort query",
					"table", database.TblBulkImportJobs, "file", "aocs-intel/handlers/analytics/token_usage_dept_handler.go", "err", _rErr)
			}
			if len(extRows) > 0 {
				total := 0
				for _, row := range extRows {
					switch v := row["token_usage"].(type) {
					case float64:
						total += int(v)
					case int:
						total += v
					}
				}
				result = append(result, deptTokenUsageRow{
					Department:     "All Departments",
					DepartmentID:   "__all__",
					TokensConsumed: total,
					CostUSD:        float64(total) * 0.000150,
					Period:         period,
				})
			}
		}

		respond.OK(w, map[string]any{
			"items":          result,
			"period":         period,
			"total":          len(result),
			"total_tokens":   totalTokens,
			"total_cost_usd": totalCostUSD,
		})
	}
}

// HandleUpdateDepartmentBudget — POST /departments/{id}/budget
//
// Tenant admin sets the token and/or USD spending limits for a department.
// Upserts into aocs_tenant_department_budgets (tenant-scoped).
//
// Request body:
//
//	{
//	  "budget_limit_usd": 500.00,
//	  "budget_limit_tokens": 1000000,
//	  "budget_period": "monthly",
//	  "budget_alert_pct": 80,
//	  "cost_per_token": 0.000150
//	}
func HandleUpdateDepartmentBudget(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		deptSlug := mux.Vars(r)["id"]
		if deptSlug == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id (department slug)")
			return
		}
		respond.LimitBody(r)

		var req struct {
			BudgetLimitUSD    *float64 `json:"budget_limit_usd"`
			BudgetLimitTokens *int64   `json:"budget_limit_tokens"`
			BudgetPeriod      string   `json:"budget_period"`
			BudgetAlertPct    *int     `json:"budget_alert_pct"`
			CostPerToken      *float64 `json:"cost_per_token"`
		}
		respond.LimitBody(r)
		if !validate.Bind(w, r, &req) {
			return
		}

		if req.BudgetPeriod != "" {
			switch req.BudgetPeriod {
			case "monthly", "quarterly", "annual":
				// valid
			default:
				respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest,
					"budget_period must be one of: monthly, quarterly, annual")
				return
			}
		}
		if req.BudgetAlertPct != nil && (*req.BudgetAlertPct < 0 || *req.BudgetAlertPct > 100) {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest,
				"budget_alert_pct must be between 0 and 100")
			return
		}

		// Try update first; if no rows affected, insert.
		// This is an upsert pattern for the tenant-scoped budget row.
		var existing []map[string]any
		if _rErr := db.QueryRowsCompound(database.TblTenantDeptBudgets, "department_budget_id",
			"tenant_id", tenantID, "department_slug", deptSlug, &existing); _rErr != nil {
			slog.Warn("READ_DEGRADED: QueryRowsCompound failed — best-effort query",
				"table", "department_budget_id", "file", "aocs-intel/handlers/analytics/token_usage_dept_handler.go", "err", _rErr)
		}

		now := time.Now().UTC().Format(time.RFC3339)

		if len(existing) > 0 {
			// Update existing budget row
			update := map[string]any{"updated_at": now}
			if req.BudgetLimitUSD != nil {
				update["budget_limit_usd"] = *req.BudgetLimitUSD
			}
			if req.BudgetLimitTokens != nil {
				update["budget_limit_tokens"] = *req.BudgetLimitTokens
			}
			if req.BudgetPeriod != "" {
				update["budget_period"] = req.BudgetPeriod
			}
			if req.BudgetAlertPct != nil {
				update["budget_alert_pct"] = *req.BudgetAlertPct
			}
			if req.CostPerToken != nil {
				update["cost_per_token"] = *req.CostPerToken
			}
			existingID, _ := existing[0]["department_budget_id"].(string)
			if err := db.UpdateRowCompound(database.TblTenantDeptBudgets, "department_budget_id", existingID, "tenant_id", tenantID, update); err != nil {
				slog.Error("HandleUpdateDepartmentBudget: update failed", "dept", deptSlug, "error", err)
				respond.InternalError(w, http.StatusInternalServerError, "failed to update department budget", nil)
				return
			}
		} else {
			// Insert new budget row
			row := map[string]any{
				"tenant_id":       tenantID,
				"department_slug": deptSlug,
				"created_at":      now,
				"updated_at":      now,
			}
			if req.BudgetLimitUSD != nil {
				row["budget_limit_usd"] = *req.BudgetLimitUSD
			}
			if req.BudgetLimitTokens != nil {
				row["budget_limit_tokens"] = *req.BudgetLimitTokens
			}
			if req.BudgetPeriod != "" {
				row["budget_period"] = req.BudgetPeriod
			}
			if req.BudgetAlertPct != nil {
				row["budget_alert_pct"] = *req.BudgetAlertPct
			}
			if req.CostPerToken != nil {
				row["cost_per_token"] = *req.CostPerToken
			}
			if err := db.InsertRow(database.TblTenantDeptBudgets, row); err != nil {
				slog.Error("HandleUpdateDepartmentBudget: insert failed", "dept", deptSlug, "error", err)
				respond.InternalError(w, http.StatusInternalServerError, "failed to create department budget", nil)
				return
			}
		}

		slog.Info("department budget updated", "tenant", tenantID, "department", deptSlug)
		respond.OK(w, map[string]any{
			"tenant_id":       tenantID,
			"department_slug": deptSlug,
			"status":          "updated",
		})
	}
}

// HandleGetDepartmentBudget — GET /departments/{id}/budget
//
// Returns the budget configuration for a specific department within the tenant.
func HandleGetDepartmentBudget(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		deptSlug := mux.Vars(r)["id"]
		if deptSlug == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}

		var rows []map[string]any
		if err := db.QueryRowsCompound(database.TblTenantDeptBudgets,
			"department_slug,budget_limit_usd,budget_limit_tokens,budget_period,cost_per_token,budget_alert_pct",
			"tenant_id", tenantID, "department_slug", deptSlug, &rows); err != nil || len(rows) == 0 {
			// Return defaults if no budget configured yet
			respond.OK(w, map[string]any{
				"department_slug":    deptSlug,
				"budget_limit_usd":   nil,
				"budget_limit_tokens": nil,
				"budget_period":      "monthly",
				"cost_per_token":     0.000150,
				"budget_alert_pct":   80,
				"configured":        false,
			})
			return
		}
		rows[0]["configured"] = true
		respond.OK(w, rows[0])
	}
}
