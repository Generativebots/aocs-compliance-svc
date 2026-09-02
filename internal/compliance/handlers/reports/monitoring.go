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

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
)

// HandleGetMonitorAuditSummary — GET /monitor/audit-summary

type auditSummaryRow struct {
	TenantID      string `json:"tenant_id"`
	TotalEvents   int    `json:"total_events"`
	Events24h     int    `json:"events_24h"`
	Violations24h int    `json:"violations_24h"`
	Warnings24h   int    `json:"warnings_24h"`
	GeneratedAt   string `json:"generated_at"`
}

func HandleGetMonitorAuditSummary(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		sum := auditSummaryRow{
			TenantID:    tenantID,
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		}

		cutoff24h := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
		cutoff30d  := time.Now().UTC().AddDate(0, 0, -30).Format(time.RFC3339)

		// PERF: DB-side COUNT aggregations — avoids fetching thousands of rows into Go memory.
		type countRow struct {
			Total         int `json:"total"`
			Events24h     int `json:"events_24h"`
			Violations24h int `json:"violations_24h"`
			Warnings24h   int `json:"warnings_24h"`
		}

		const aggSQL = `
SELECT
  COUNT(*)                                                           AS total,
  COUNT(*) FILTER (WHERE created_at >= $2)                          AS events_24h,
  COUNT(*) FILTER (WHERE created_at >= $2 AND severity IN ('ERROR','CRITICAL')) AS violations_24h,
  COUNT(*) FILTER (WHERE created_at >= $2 AND severity = 'WARNING') AS warnings_24h
FROM core_audit
WHERE tenant_id = $1 AND created_at >= $3`

		var rows []countRow
		if err := db.QueryRawCtx(r.Context(), aggSQL, &rows, tenantID, cutoff24h, cutoff30d); err != nil {
			slog.Debug("monitor/audit-summary: aggregation query failed", "tenant_id", tenantID, "err", err)
		} else if len(rows) > 0 {
			sum.TotalEvents   = rows[0].Total
			sum.Events24h     = rows[0].Events24h
			sum.Violations24h = rows[0].Violations24h
			sum.Warnings24h   = rows[0].Warnings24h
		}

		respond.OK(w, sum)
	}
}

// HandleGetSystemOverview — GET /monitor/overview

type systemOverview struct {
	AgentCount    int    `json:"agent_count"`
	ActiveAgents  int    `json:"active_agents"`
	GateCalls24h  int    `json:"gate_calls_24h"`
	Violations24h int    `json:"violations_24h"`
	GeneratedAt   string `json:"generated_at"`
}

// HandleGetSystemOverview — GET /monitor/overview
// V-06 FIX: agent counts fetched via Ring 1 internal API — no direct Ring 1 table access.
func HandleGetSystemOverview(db database.DB, internalAPIURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		ov := systemOverview{GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
		cutoff24h := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)

		// V-06 FIX: Agent counts via Ring 1 internal API (was: direct FROM core_agents SQL)
		// Ring 4 (compliance) must call Ring 1's API — never touch Ring 1 tables directly.
		if internalAPIURL != "" {
			apiURL := fmt.Sprintf("%s/internal/v1/agents/counts?tenant_id=%s", internalAPIURL, tenantID)
			apiReq, reqErr := http.NewRequestWithContext(r.Context(), http.MethodGet, apiURL, nil)
			if reqErr == nil {
				if svcJWT := r.Header.Get("X-Service-JWT"); svcJWT != "" {
					apiReq.Header.Set("Authorization", "Bearer "+svcJWT)
				}
				apiReq.Header.Set("X-Tenant-ID", tenantID)
				cl := &http.Client{Timeout: 5 * time.Second}
				apiResp, apiErr := cl.Do(apiReq)
				if apiErr == nil {
					defer apiResp.Body.Close()
					if apiResp.StatusCode == http.StatusOK {
						body, _ := io.ReadAll(io.LimitReader(apiResp.Body, 64*1024))
						var payload struct {
							Total  int `json:"total"`
							Active int `json:"active"`
						}
						if jsonErr := json.Unmarshal(body, &payload); jsonErr == nil {
							ov.AgentCount   = payload.Total
							ov.ActiveAgents = payload.Active
						}
					}
				} else {
					slog.Warn("monitoring: Ring 1 agent counts API unavailable", "error", apiErr)
				}
			}
		}

		// PERF: Gate calls + violations in a single aggregation query (was fetching all 30-day audit logs)
		type gateStats struct {
			GateCalls24h  int `json:"gate_calls_24h"`
			Violations24h int `json:"violations_24h"`
		}
		const gateSQL = `
SELECT
  COUNT(*)                                                                  AS gate_calls_24h,
  COUNT(*) FILTER (WHERE severity IN ('ERROR','CRITICAL'))                  AS violations_24h
FROM core_audit
WHERE tenant_id = $1 AND created_at >= $2`

		var gs []gateStats
		if err := db.QueryRawCtx(r.Context(), gateSQL, &gs, tenantID, cutoff24h); err == nil && len(gs) > 0 {
			ov.GateCalls24h  = gs[0].GateCalls24h
			ov.Violations24h = gs[0].Violations24h
		}

		respond.OK(w, ov)
	}
}
