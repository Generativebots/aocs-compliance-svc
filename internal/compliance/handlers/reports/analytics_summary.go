package reports

// analytics_summary.go — GET /analytics/summary
//
// Canonical path: GET /api/v1/analytics/summary
// Owner:          aocs-intel  (analytics sub-domain)
// RBAC:           resource=analytics, action=read
//
// Returns a platform-wide analytics digest scoped to the current tenant:
//   - agent counts + active ratio
//   - gate call volume (24h)
//   - violation count (24h)
//   - compliance posture score
//   - policy verdict distribution (24h)
//
// This is NOT an alias — it aggregates from multiple tables into a single
// summary payload optimised for dashboard header cards.

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

// HandleAnalyticsSummary returns a tenant-scoped analytics digest.
// Ring design: agent counts are fetched from Ring 1 internal API (not direct DB).
// Ring 4 (compliance) must never read Ring 1 tables — V-06 fix.
//
//	{
//	  "tenant_id":            "...",
//	  "generated_at":         "2026-...",
//	  "agents":               { "total": 42, "active": 38 },
//	  "gate_calls_24h":       1204,
//	  "violations_24h":       3,
//	  "allow_24h":            1190,
//	  "deny_24h":             11,
//	  "escalate_24h":         3,
//	  "compliance_score":     0.91
//	}
func HandleAnalyticsSummary(db database.DB, internalAPIURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "tenant context required")
			return
		}

		cutoff := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)

		// CAT-3 FIX: Collect DB errors instead of silently returning zeros.
		// If any query fails, the response carries partial_data=true + db_errors list
		// so dashboards can show a data-reliability warning rather than wrong zeros.
		var dbErrors []string

		// 1. Agent counts — fetched from Ring 1 internal API (V-06 fix: no direct Ring 1 table access)
		// Ring 4 (compliance) must use Ring 1's internal API, never direct SQL on Ring 1 tables.
		type agentCounts struct {
			Total  int `json:"total"`
			Active int `json:"active"`
		}
		agents := agentCounts{}
		{
			apiURL := fmt.Sprintf("%s/internal/v1/agents/counts?tenant_id=%s", internalAPIURL, tenantID)
			apiReq, reqErr := http.NewRequestWithContext(r.Context(), http.MethodGet, apiURL, nil)
			if reqErr == nil {
				// Forward the service JWT so Ring 1 trusts this internal call
				if svcJWT := r.Header.Get("X-Service-JWT"); svcJWT != "" {
					apiReq.Header.Set("Authorization", "Bearer "+svcJWT)
				}
				apiReq.Header.Set("X-Tenant-ID", tenantID)
				cl := &http.Client{Timeout: 5 * time.Second}
				apiResp, apiErr := cl.Do(apiReq)
				if apiErr != nil {
					slog.Warn("analytics_summary: Ring 1 agent counts API unavailable", "error", apiErr)
					dbErrors = append(dbErrors, "agents: ring1_api_unavailable")
				} else {
					defer apiResp.Body.Close()
					if apiResp.StatusCode == http.StatusOK {
						body, _ := io.ReadAll(io.LimitReader(apiResp.Body, 64*1024))
						var payload struct {
							Total  int `json:"total"`
							Active int `json:"active"`
						}
						if jsonErr := json.Unmarshal(body, &payload); jsonErr == nil {
							agents = agentCounts{Total: payload.Total, Active: payload.Active}
						}
					} else {
						slog.Warn("analytics_summary: Ring 1 agent counts API returned non-200",
							"status", apiResp.StatusCode)
						dbErrors = append(dbErrors, fmt.Sprintf("agents: ring1_api_status_%d", apiResp.StatusCode))
					}
				}
			} else {
				dbErrors = append(dbErrors, "agents: ring1_api_request_build_failed")
			}
		}

		// 2. Gate call stats + policy verdicts (24h window)
		type gateStats struct {
			GateCalls     int `json:"gate_calls_24h"`
			Violations    int `json:"violations_24h"`
			AllowCount    int `json:"allow_24h"`
			DenyCount     int `json:"deny_24h"`
			EscalateCount int `json:"escalate_24h"`
		}
		const gateSQL = `
SELECT
  COUNT(*)                                                                    AS gate_calls_24h,
  COUNT(*) FILTER (WHERE severity IN ('ERROR','CRITICAL'))                    AS violations_24h,
  COUNT(*) FILTER (WHERE outcome = 'ALLOW')                                  AS allow_24h,
  COUNT(*) FILTER (WHERE outcome = 'DENY')                                   AS deny_24h,
  COUNT(*) FILTER (WHERE outcome = 'ESCALATE')                               AS escalate_24h
FROM core_audit
WHERE tenant_id = $1 AND created_at >= $2`

		var gs []gateStats
		if _qErr := db.QueryRawCtx(r.Context(), gateSQL, &gs, tenantID, cutoff); _qErr != nil {
			slog.Error("analytics_summary: gate stats query failed", "tenant_id", tenantID, "error", _qErr)
			dbErrors = append(dbErrors, "gate_stats: "+_qErr.Error())
		}
		gate := gateStats{}
		if len(gs) > 0 {
			gate = gs[0]
		}

		// 3. Compliance posture score — normalised per active agent
		// P3-4 FIX: was AVG(score) over all core_compliance rows.
		// If only 10 of 100 agents have records, AVG ignores the 90 uncovered agents.
		// Fix: score = SUM(score) / GREATEST(total_active_agents, 1)
		// where total_active_agents comes from core_agents (Ring 2) for this tenant.
		// An agent with no compliance record counts as 0.0 (uncovered = non-compliant).
		type complianceRow struct {
			Score float64 `json:"score"`
		}
		const complianceSQL = `
SELECT
  COALESCE(
    SUM(c.score) / GREATEST(
      (SELECT COUNT(*) FROM core_agents WHERE tenant_id = $1 AND status = 'ACTIVE'),
      1
    ),
    0
  )::float8 AS score
FROM core_compliance c
WHERE c.tenant_id = $1`

		var cr []complianceRow
		if _qErr := db.QueryRawCtx(r.Context(), complianceSQL, &cr, tenantID); _qErr != nil {
			slog.Error("analytics_summary: compliance score query failed", "tenant_id", tenantID, "error", _qErr)
			dbErrors = append(dbErrors, "compliance_score: "+_qErr.Error())
		}
		complianceScore := 0.0
		if len(cr) > 0 {
			complianceScore = cr[0].Score
		}

		respond.OK(w, map[string]any{
			"tenant_id":        tenantID,
			"generated_at":     time.Now().UTC().Format(time.RFC3339),
			"agents":           agents,
			"gate_calls_24h":   gate.GateCalls,
			"violations_24h":   gate.Violations,
			"allow_24h":        gate.AllowCount,
			"deny_24h":         gate.DenyCount,
			"escalate_24h":     gate.EscalateCount,
			"compliance_score": complianceScore,
			// CAT-3 FIX: data quality signals — UI must show warning when partial_data=true
			"partial_data": len(dbErrors) > 0,
			"db_errors":    dbErrors, // empty slice when all queries succeeded
		})
	}
}

