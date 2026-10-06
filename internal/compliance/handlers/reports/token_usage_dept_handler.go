package reports

// token_usage_dept_handler.go — GET /tokens/usage/by-department
//
// Aggregates token consumption per department for the tenant.
// Queries core_gate_stages to bucket token_usage by department.
// Budget limits come from aocs_tenant_department_budgets (tenant-scoped),
// NOT from syst_departments (which is the platform-wide catalog).
//
// Response shape:
//
//	[{ department, department_id, tokens_consumed, cost_usd, budget_limit_usd,
//	   budget_limit_tokens, budget_utilization_pct, burn_rate, period }]

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
