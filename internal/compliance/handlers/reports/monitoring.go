package reports

// monitoring.go — PERF-001 fix
//
// HandleGetMonitorAuditSummary: GET /monitor/audit-summary
//   Returns aggregated audit counts for the ops health dashboard.
//   PERF FIX: Now uses DB-side COUNT aggregations instead of fetching all 30-day rows
//   and filtering in-process (was causing 10+ second responses on tables with 10k+ rows).
//
// HandleGetSystemOverview: GET /monitor/overview
//   Returns real system metrics for the command-center dashboard.
//   PERF FIX: Same aggregation approach — COUNT in SQL, not Go slice iteration.

// HandleGetMonitorAuditSummary — GET /monitor/audit-summary

type auditSummaryRow struct {
	TenantID      string `json:"tenant_id"`
	TotalEvents   int    `json:"total_events"`
	Events24h     int    `json:"events_24h"`
	Violations24h int    `json:"violations_24h"`
	Warnings24h   int    `json:"warnings_24h"`
	GeneratedAt   string `json:"generated_at"`
}

// HandleGetSystemOverview — GET /monitor/overview

type systemOverview struct {
	AgentCount    int    `json:"agent_count"`
	ActiveAgents  int    `json:"active_agents"`
	GateCalls24h  int    `json:"gate_calls_24h"`
	Violations24h int    `json:"violations_24h"`
	GeneratedAt   string `json:"generated_at"`
}
