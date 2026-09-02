package reports

import (
	"fmt"
	"math"
	"net/http"

	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
)

// HandleGetServiceMetrics returns per-agent service metrics for the analytics dashboard.
//
// GET /api/v1/admin/analytics/overview
//
// Response: ServiceMetric[] — each element represents one active agent treated as a service node.
//
//	[{
//	  "service":    "agent-name-or-id",
//	  "status":     "ONLINE" | "DEGRADED" | "OFFLINE",
//	  "uptime_pct": 99.2,
//	  "p95_ms":     142,
//	  "rps":        4.7,
//	  "error_rate": 0.3,
//	  "version":    "1.0",
//	}]
//
// Computed from aocs_agents using successful/failed_interactions as a proxy for error rate
// and behavioral_drift as a proxy for health degradation.
func HandleGetServiceMetrics(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized, "missing tenant_id")
			return
		}

		// M40: telemetry cols (total/successful/failed_interactions) + model_name live in
		// satellite tables. Must read vw_agent_full which JOINs aocs_agents +
		// aocs_agent_config + aocs_agent_telemetry — not TblAgents directly.
		var agents []map[string]any
		if err := db.QueryRowsCtx(r.Context(), database.TblAgentFullView,
			"agent_id,tenant_id,name,status,is_frozen,blacklisted,behavioral_drift,total_interactions,successful_interactions,failed_interactions,risk_tier,tier,model_name,created_at",
			"tenant_id", tenantID, &agents,
		); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "service metrics query", err)
			return
		}
		if agents == nil {
			agents = []map[string]any{}
		}

		type ServiceMetric struct {
			Service   string  `json:"service"`
			Status    string  `json:"status"`
			UptimePct float64 `json:"uptime_pct"`
			P95Ms     int     `json:"p95_ms"`
			Rps       float64 `json:"rps"`
			ErrorRate float64 `json:"error_rate"`
			Version   string  `json:"version"`
			AgentID   string  `json:"agent_id"`
			RiskTier  string  `json:"risk_tier"`
		}

		metrics := make([]ServiceMetric, 0, len(agents))
		for _, a := range agents {
			// Derive service name — guard against short/empty agent_id
			name := ""
			if n, ok := a["name"].(string); ok && n != "" {
				name = n
			} else if id, ok := a["agent_id"].(string); ok && id != "" {
				end := 8
				if len(id) < end {
					end = len(id)
				}
				name = fmt.Sprintf("agent-%s", id[:end])
			} else {
				name = "agent-unknown"
			}

			// Status mapping
			statusRaw, _ := a["status"].(string)
			frozen, _ := a["is_frozen"].(bool)
			blacklisted, _ := a["blacklisted"].(bool)
			status := "ONLINE"
			if blacklisted {
				status = "OFFLINE"
			} else if frozen {
				status = "DEGRADED"
			} else {
				switch statusRaw {
				case "Active", "ACTIVE":
					status = "ONLINE"
				case "Frozen", "FROZEN", "Suspended", "SUSPENDED":
					status = "DEGRADED"
				case "Blacklisted", "BLACKLISTED", "Inactive", "INACTIVE":
					status = "OFFLINE"
				}
			}

			// Compute uptime from successful/(successful+failed) interactions
			var total, successful, failed int64
			if v, ok := a["total_interactions"].(float64); ok {
				total = int64(v)
			}
			if v, ok := a["successful_interactions"].(float64); ok {
				successful = int64(v)
			}
			if v, ok := a["failed_interactions"].(float64); ok {
				failed = int64(v)
			}

			uptimePct := 100.0
			errorRate := 0.0
			if total > 0 {
				uptimePct = math.Round(float64(successful)/float64(total)*10000) / 100
				errorRate = math.Round(float64(failed)/float64(total)*10000) / 100
			}

			// Behavioral drift → p95_ms proxy (0-1 drift → 50ms-2000ms)
			drift := 0.0
			if d, ok := a["behavioral_drift"].(float64); ok {
				drift = d
			}
			p95 := 50 + int(drift*1950)

			// RPS: heuristic from total_interactions (interactions per day → per second)
			rps := 0.0
			if total > 0 {
				rps = math.Round(float64(total)/24*60*60 /* 1 day */*10) / 10
				if rps < 0.1 {
					rps = 0.1
				}
			}

			agentID, _ := a["agent_id"].(string)
			riskTier, _ := a["risk_tier"].(string)
			version, _ := a["tier"].(string)
			if version == "" {
				version = "1.0"
			}

			metrics = append(metrics, ServiceMetric{
				Service:   name,
				Status:    status,
				UptimePct: uptimePct,
				P95Ms:     p95,
				Rps:       rps,
				ErrorRate: errorRate,
				Version:   version,
				AgentID:   agentID,
				RiskTier:  riskTier,
			})
		}

		respond.OK(w, metrics)
	}
}
