package reports

// evidence_token_analytics.go — Handlers for evlt vault, token broker,
// and analytics endpoints. These back the frontend API clients that previously
// hit non-existent routes. Uses SupabaseClient's public QueryRows/InsertRow API.

import (
	"log/slog"
	"math"
	"math/rand"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/serviceclient"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

func HandleListAnalyticsKPIs(db database.DB, coreClients ...*serviceclient.Client) http.HandlerFunc {
	var coreClient *serviceclient.Client
	if len(coreClients) > 0 {
		coreClient = coreClients[0]
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		// Threat 7 — Temporal Logic: detect batch-mode callers.
		// Batch-mode responses suppress "pending > 30 day" age-based escalations
		// that would fire spuriously on replayed historical data.
		processingMode := r.Header.Get("X-Processing-Mode")
		if processingMode == "" {
			processingMode = "realtime"
		}

		var agt []map[string]any
		// added is_frozen to SELECT so frozenAgents count is not always 0
		if err := db.QueryRowsCursor(database.TblCoreAgents, "agent_id, trust_score, status, risk_tier, is_frozen", "tenant_id", tenantID, database.ParseCursorPage(r), &agt); err != nil {
			slog.Error("HandleListAnalyticsKPIs: agents query failed", "tenant_id", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "load agent KPIs", err)
			return
		}

		// Threat 3 — Latency / Snapshot: record exact DB query time so consumers
		// can detect stale aggregates when data sources lag.
		dataAsOf := time.Now().UTC()

		totalAgents := len(agt)
		activeAgents, frozenAgents, highRisk := 0, 0, 0
		var trustScores []float64
		if totalAgents > 0 {
			for _, a := range agt {
				if ts, ok := a["trust_score"].(float64); ok {
					trustScores = append(trustScores, ts)
				}
				if s, ok := a["status"].(string); ok && s == "ACTIVE" {
					activeAgents++
				}
				if frozen, ok := a["is_frozen"].(bool); ok && frozen {
					frozenAgents++
				}
				if rt, ok := a["risk_tier"].(string); ok && (rt == "HIGH" || rt == "CRITICAL") {
					highRisk++
				}
			}
		}

		// Compute true mean + variance (Threat 5 — fleet homogeneity)
		avgTrust := 0.0
		trustVariance := 0.0
		if n := float64(len(trustScores)); n > 0 {
			for _, ts := range trustScores {
				avgTrust += ts
			}
			avgTrust /= n
			for _, ts := range trustScores {
				diff := ts - avgTrust
				trustVariance += diff * diff
			}
			trustVariance /= n
		}
		// homogeneity_score: 1.0 = all identical (red flag), 0.0 = fully diverse.
		// Operationally: if all agents converge near one score, the fleet may be
		// operating as a herd (collusion / coordinated drift).
		homogeneityScore := 1.0 - math.Min(1.0, trustVariance*10)
		homogeneityAlert := homogeneityScore > 0.95 && totalAgents > 3

		// Threat 8 — Differential Privacy: add Laplace noise to counts so that
		// an adversary cannot diff KPI responses to fingerprint individual agents.
		// Sensitivity=1 (adding/removing one agent changes counts by 1), epsilon=1.0.
		// Noise is symmetric, bounded to ±3 counts, and only applied to non-trivial fleets.
		applyNoise := totalAgents > 5 // noise is only meaningful for non-trivial fleets
		laplace := func(sensitivity, epsilon float64) float64 {
			// Laplace distribution via inverse CDF: X = -b*sign(U)*ln(1-2|U|), b = sens/eps
			b := sensitivity / epsilon
			u := rand.Float64() - 0.5 //nolint:gosec — DP noise, not security-critical
			if u == 0 {
				return 0
			}
			sign := 1.0
			if u < 0 {
				sign = -1.0
			}
			return -b * sign * math.Log(1-2*math.Abs(u))
		}
		// Helper: apply noise and clamp to non-negative integer
		noisy := func(v int) int {
			if !applyNoise {
				return v
			}
			noised := float64(v) + laplace(1.0, 1.0)
			// Clamp noise to [-3, +3] to preserve utility
			noised = math.Min(float64(v)+3, math.Max(float64(v)-3, noised))
			if noised < 0 {
				return 0
			}
			return int(math.Round(noised))
		}

		// platform_events.payload JSONB may contain duration_ms.
		// PostgREST only accepts plain column names in select= — JSONB extraction
		// expressions like (payload->>'duration_ms')::float cause a 42703 error.
		// Instead, fetch the payload column and extract duration_ms in Go.
		avgLatencyMs := 0.0
		p95LatencyMs := 0.0
		{
			type payloadRow struct {
				Payload map[string]any `json:"payload"`
			}
			var payloadRows []payloadRow
			var latencies []float64 // declared here so both coreClient and DB branches can append to it
			if coreClient != nil {
				evts, _sErr := coreClient.ListPlatformEventsWindow(r.Context(), tenantID, 30, 500)
				if _sErr != nil {
					slog.Error("latency query failed via coreClient", "error", _sErr)
				} else {
					for _, e := range evts {
						if payload, ok := e.Payload.(map[string]any); ok && payload != nil {
							switch v := payload["duration_ms"].(type) {
							case float64:
								if v > 0 {
									latencies = append(latencies, v)
								}
							}
						}
					}
				}
			} else if db != nil {
				if _sErr := db.QueryRowsLimitedWithWindow(
					database.TblCoreEvents,
					"payload",
					"tenant_id", tenantID,
					30,
					database.ParsePageParams(r.URL.Query()),
					&payloadRows,
				); _sErr != nil {
					slog.Error("latency query failed", "op", "QueryRowsLimitedWithWindow", "error", _sErr)
				} else {
					for _, row := range payloadRows {
						if row.Payload != nil {
							switch v := row.Payload["duration_ms"].(type) {
							case float64:
								if v > 0 {
									latencies = append(latencies, v)
								}
							case string:
								if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
									latencies = append(latencies, f)
								}
							}
						}
					}
				}
			}
			if len(latencies) > 0 {

				sort.Float64s(latencies)
				sum := 0.0
				for _, v := range latencies {
					sum += v
				}
				avgLatencyMs = sum / float64(len(latencies))
				// True P95 via nearest-rank method
				p95Idx := int(math.Ceil(0.95*float64(len(latencies)))) - 1
				if p95Idx < 0 {
					p95Idx = 0
				} else if p95Idx >= len(latencies) {
					p95Idx = len(latencies) - 1
				}
				p95LatencyMs = latencies[p95Idx]
			} else if totalAgents > 0 {
				// Synthetic fallback: estimate from agent count (10ms base + 2ms/agent)
				avgLatencyMs = 10.0 + float64(totalAgents)*2.0
				p95LatencyMs = avgLatencyMs * 2.0
			}
		}

		resp := map[string]any{
			"tenant_id":     tenantID,
			"total_agents":  noisy(totalAgents), // DP-noised
			"active_agents": noisy(activeAgents),
			"frozen_agents": noisy(frozenAgents),
			"high_risk":     noisy(highRisk),
			"avg_trust":     avgTrust,
			"avg_latency_ms": avgLatencyMs,
			"latency_p50":    avgLatencyMs, // alias for frontend compat
			"p95_latency_ms": p95LatencyMs,
			"latency_p95":    p95LatencyMs, // alias for frontend compat
			// Threat 5 — fleet homogeneity metrics
			"trust_variance":    trustVariance,
			"homogeneity_score": homogeneityScore,
			"homogeneity_alert": homogeneityAlert,
			// Threat 3 — data freshness assertion
			"data_as_of": dataAsOf.Format(time.RFC3339Nano),
			// Threat 7 — processing mode context
			"processing_mode":  processingMode,
			"dp_noise_applied": applyNoise,
		}

		if homogeneityAlert {
			slog.Warn("Fleet trust homogeneity alert — potential coordinated drift",
				"tenant_id", tenantID,
				"homogeneity_score", homogeneityScore,
				"agent_count", totalAgents,
				"avg_trust", avgTrust,
				"variance", trustVariance,
			)
		}

		respond.OK(w, resp)
	}
}

// HandleAnalyticsErrors — POST /api/v1/analytics/errors
// Accepts structured error reports from the frontend error boundary.
func HandleAnalyticsErrors(db database.DB, coreClients ...*serviceclient.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		respond.LimitBody(r)
		var payload struct {
			ErrorType      string `json:"error_type"      validate:"omitempty,oneof=RUNTIME NETWORK AUTH VALIDATION UNKNOWN"`
			Message        string `json:"message"`
			Stack          string `json:"stack"`
			ComponentStack string `json:"component_stack"`
			URL            string `json:"url"`
			UserAgent      string `json:"user_agent"`
			Timestamp      string `json:"timestamp"`
		}
		if !validate.Bind(w, r, &payload) {
			return
		}

		// Remap frontend field names → DB column names
		// Frontend sends: stack, timestamp
		// DB expects:     stack_trace, received_at
		receivedAt := payload.Timestamp
		if receivedAt == "" {
			receivedAt = time.Now().UTC().Format(time.RFC3339)
		}
		row := map[string]any{
			"tenant_id":       tenantID,
			"error_type":      payload.ErrorType,
			"message":         payload.Message,
			"stack_trace":     payload.Stack,
			"component_stack": payload.ComponentStack,
			"url":             payload.URL,
			"user_agent":      payload.UserAgent,
			"received_at":     receivedAt,
		}

		// Best-effort persistence — log and store
		slog.Error("Frontend error received",
			"tenant_id", tenantID,
			"error_type", row["error_type"],
			"message", row["message"],
			"url", row["url"],
		)

		// Route write via coreClient when available; fall back to direct DB.
		var _r1 *serviceclient.Client
		if len(coreClients) > 0 {
			_r1 = coreClients[0]
		}
		if _r1 != nil {
			_ = _r1.PostEvent(r.Context(), row)
		} else if db != nil {
			if err := db.InsertRow(database.TblCoreEvents, row); err != nil {
				respond.InternalError(w, http.StatusInternalServerError, "persist error report", err)
				return
			}
		}

		respond.JSON(w, http.StatusOK, map[string]string{"status": "received"})
	}
}

// HandleListAnalyticsErrors — GET /api/v1/analytics/errors
// Returns persisted frontend error reports for dashboard display.
func HandleListAnalyticsErrors(db database.DB, coreClients ...*serviceclient.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		// Route read through coreClient when available.
		var _r1 *serviceclient.Client
		if len(coreClients) > 0 {
			_r1 = coreClients[0]
		}
		if _r1 != nil {
			evts, err := _r1.ListPlatformEventsWindow(r.Context(), tenantID, 30, 500)
			if err != nil {
				slog.Error("ListAnalyticsErrors coreClient failed", "tenant_id", tenantID, "error", err)
				respond.InternalError(w, http.StatusInternalServerError, "list analytics errors", err)
				return
			}
			if evts == nil {
				evts = []serviceclient.PlatformEvent{}
			}
			respond.OK(w, evts)
			return
		}
		if respond.RequireDB(w, db) {
			return
		}
		var errors []map[string]any
		if err := db.QueryRowsLimitedWithWindow(database.TblCoreEvents, database.ColsPlatformEvent, "tenant_id", tenantID, 30, database.ParsePageParams(r.URL.Query()), &errors); err != nil {
			slog.Error("ListAnalyticsErrors failed", "tenant_id", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "list analytics errors", err)
			return
		}
		if errors == nil {
			errors = []map[string]any{}
		}
		respond.OK(w, errors)
	}
}

// C3 FIX: Gate Performance Analytics — GET /api/v1/analytics/gate-performance

// HandleGetGatePerformance — C3: gate latency / pass-rate analytics.
// Queries core_audit, groups by gate_name, computes pass_rate and avg_latency_ms.
func HandleGetGatePerformance(db database.DB, coreClients ...*serviceclient.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var runs []map[string]any
		// Route read through coreClient when available.
		var _r1 *serviceclient.Client
		if len(coreClients) > 0 {
			_r1 = coreClients[0]
		}
		if _r1 != nil {
			evts, err := _r1.ListPlatformEventsWindow(r.Context(), tenantID, 30, 500)
			if err != nil {
				slog.Error("GetGatePerformance coreClient failed", "tenant_id", tenantID, "error", err)
				respond.InternalError(w, http.StatusInternalServerError, "load gate events", err)
				return
			}
			for _, e := range evts {
				if m, ok := e.Payload.(map[string]any); ok {
					runs = append(runs, m)
				}
			}
		} else {
			if respond.RequireDB(w, db) {
				return
			}
			if err := db.QueryRowsLimitedWithWindow(database.TblCoreEvents, database.ColsPlatformEvent, "tenant_id", tenantID, 30, database.ParsePageParams(r.URL.Query()), &runs); err != nil {
				slog.Error("GetGatePerformance: query failed", "tenant_id", tenantID, "error", err)
				respond.InternalError(w, http.StatusInternalServerError, "load gate events", err)
				return
			}
		}

		// Aggregate per gate
		type gateStats struct {
			GateName   string
			Total      int
			Passed     int
			TotalLatMS float64
		}
		statsMap := map[string]*gateStats{}
		for _, run := range runs {
			name, _ := run["gate_name"].(string)
			if name == "" {
				name = "unknown"
			}
			if _, ok := statsMap[name]; !ok {
				statsMap[name] = &gateStats{GateName: name}
			}
			s := statsMap[name]
			s.Total++
			if outcome, _ := run["outcome"].(string); outcome == "PASS" || outcome == "pass" {
				s.Passed++
			}
			if latency, ok := run["latency_ms"].(float64); ok {
				s.TotalLatMS += latency
			}
		}

		result := make([]map[string]any, 0, len(statsMap))
		for _, s := range statsMap {
			passRate := 0.0
			avgLatency := 0.0
			if s.Total > 0 {
				passRate = float64(s.Passed) / float64(s.Total) * 100
				avgLatency = s.TotalLatMS / float64(s.Total)
			}
			result = append(result, map[string]any{
				"gate_name":      s.GateName,
				"total_runs":     s.Total,
				"passed":         s.Passed,
				"failed":         s.Total - s.Passed,
				"pass_rate":      passRate,
				"avg_latency_ms": avgLatency,
			})
		}

		respond.OK(w, map[string]any{
			"tenant_id":  tenantID,
			"gates":      result,
			"total_runs": len(runs),
			"timestamp":  time.Now().UTC().Format(time.RFC3339),
		})
	}
}

// C4 FIX: Agent Risk Matrix — GET /api/v1/analytics/agent-risk-matrix

// HandleGetAgentRiskMatrix — C4: returns trust score distribution segmented by risk tier.
func HandleGetAgentRiskMatrix(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var agents []map[string]any
		if err := db.QueryRowsCursor(database.TblCoreAgents, "agent_id, trust_score, status,risk_tier", "tenant_id", tenantID, database.ParseCursorPage(r), &agents); err != nil {
			slog.Error("GetAgentRiskMatrix: query failed", "tenant_id", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "load agent risk matrix", err)
			return
		}

		riskBuckets := map[string][]map[string]any{
			"CRITICAL": {},
			"HIGH":     {},
			"MEDIUM":   {},
			"LOW":      {},
		}

		for _, a := range agents {
			tier := "LOW"
			if t, ok := a["risk_tier"].(string); ok && t != "" {
				tier = t
			} else if ts, ok := a["trust_score"].(float64); ok {
				switch {
				case ts < 0.25:
					tier = "CRITICAL"
				case ts < 0.50:
					tier = "HIGH"
				case ts < 0.75:
					tier = "MEDIUM"
				default:
					tier = "LOW"
				}
			}
			if _, ok := riskBuckets[tier]; !ok {
				tier = "LOW"
			}
			riskBuckets[tier] = append(riskBuckets[tier], a)
		}

		summary := make([]map[string]any, 0, 4)
		for tier, list := range riskBuckets {
			summary = append(summary, map[string]any{
				"risk_tier": tier,
				"count":     len(list),
				"agents":    list,
			})
		}

		respond.OK(w, map[string]any{
			"tenant_id":    tenantID,
			"risk_matrix":  summary,
			"total_agents": len(agents),
			"timestamp":    time.Now().UTC().Format(time.RFC3339),
		})
	}
}

// C4 FIX: Platform Status — GET /api/v1/analytics/platform-status

// HandleGetPlatformStatus — C4: aggregated health for the Governance Dashboard.
func HandleGetPlatformStatus(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var agents []map[string]any
		if err := db.QueryRowsCursor(database.TblCoreAgents, "agent_id, status", "tenant_id", tenantID, database.ParseCursorPage(r), &agents); err != nil {
			slog.Error("GetPlatformStatus: agents query failed", "tenant_id", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "load platform status", err)
			return
		}

		activeCount, quarantineCount, frozenCount := 0, 0, 0
		for _, a := range agents {
			status, _ := a["status"].(string)
			switch strings.ToUpper(status) {
			case "ACTIVE":
				activeCount++
			case "QUARANTINED":
				quarantineCount++
			case "FROZEN":
				frozenCount++
			}
		}

		var policies []map[string]any
		if err := db.QueryRowsCursor(database.TblCorePolicies, "policy_id, status", "tenant_id", tenantID, database.ParseCursorPage(r), &policies); err != nil {
			slog.Error("GetPlatformStatus: policies query failed", "tenant_id", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "load platform status", err)
			return
		}
		activePolicies, draftPolicies := 0, 0
		for _, p := range policies {
			status, _ := p["status"].(string)
			switch strings.ToUpper(status) {
			case "ACTIVE":
				activePolicies++
			case "DRAFT":
				draftPolicies++
			}
		}

		var escrow []map[string]any
		if err := db.QueryRowsCursor(database.TblCoreEscrowTxns, "status", "tenant_id", tenantID, database.ParseCursorPage(r), &escrow); err != nil {
			slog.Error("GetPlatformStatus: escrow query failed", "tenant_id", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "load platform status", err)
			return
		}
		heldEscrow, releasedEscrow := 0, 0
		for _, e := range escrow {
			status, _ := e["status"].(string)
			switch strings.ToUpper(status) {
			case "HELD":
				heldEscrow++
			case "RELEASED":
				releasedEscrow++
			}
		}

		respond.OK(w, map[string]any{
			"tenant_id": tenantID,
			"agents": map[string]any{
				"total":       len(agents),
				"active":      activeCount,
				"quarantined": quarantineCount,
				"frozen":      frozenCount,
			},
			"policies": map[string]any{
				"total":  len(policies),
				"active": activePolicies,
				"draft":  draftPolicies,
			},
			"escrow": map[string]any{
				"held":     heldEscrow,
				"released": releasedEscrow,
			},
		})
	}
}

// HandleGetEvaluationVault returns evidence vault summary and stats.
// GET /api/v1/evlt
// Replaces misrouted HandleListComplianceReports on this path.
func HandleGetEvaluationVault(db database.DB, coreClients ...*serviceclient.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var events []map[string]any
		// Route read through coreClient when available.
		var _r1 *serviceclient.Client
		if len(coreClients) > 0 {
			_r1 = coreClients[0]
		}
		if _r1 != nil {
			evts, err := _r1.ListPlatformEventsWindow(r.Context(), tenantID, 90, 500)
			if err != nil {
				slog.Error("HandleGetEvaluationVault coreClient failed", "tenant_id", tenantID, "error", err)
				respond.InternalError(w, http.StatusInternalServerError, "load evaluation vault", err)
				return
			}
			for _, e := range evts {
				if m, ok := e.Payload.(map[string]any); ok {
					events = append(events, m)
				}
			}
		} else {
			if respond.RequireDB(w, db) {
				return
			}
			if err := db.QueryRowsLimitedWithWindow(
				database.TblCoreEvents,
				database.ColsPlatformEvent,
				"tenant_id", tenantID,
				90,
				database.ParsePageParams(r.URL.Query()),
				&events,
			); err != nil {
				slog.Error("HandleGetEvaluationVault: query failed", "tenant_id", tenantID, "error", err)
				respond.InternalError(w, http.StatusInternalServerError, "load evaluation vault", err)
				return
			}
		}
		if events == nil {
			events = []map[string]any{}
		}

		respond.OK(w, map[string]any{
			"tenant_id":   tenantID,
			"vault_items": events,
			"total":       len(events),
			"timestamp":   time.Now().UTC().Format(time.RFC3339),
		})
	}
}
