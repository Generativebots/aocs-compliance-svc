package reports

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
)

// ─── Nexus Analytics — Domain-Specific Handlers ───────────────────────────────
// Replaces the generic HandleGetAnalyticsQuery (which returned 501) on all
// /nexs/anly/* and /monitor/* routes in aocs-intel.
// Each handler queries the canonical table for its domain.

// HandleListNexusTrends returns daily activity trend from core_events.
// GET /api/v1/nexs/anly/trends
func HandleListNexusTrends(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized, "tenant context required")
			return
		}
		var events []map[string]any
		if _dbErr := db.QueryRowsWithin90Days(database.TblCoreEvents, "event_type,created_at", tenantID, &events); _dbErr != nil {
			slog.Error("QueryRowsWithin90Days failed", "error", _dbErr)
		}
		// Aggregate by day
		byDay := map[string]int{}
		for _, e := range events {
			if ts, ok := e["created_at"].(string); ok && len(ts) >= 10 {
				day := ts[:10]
				byDay[day]++
			}
		}
		trend := make([]map[string]any, 0, len(byDay))
		for day, count := range byDay {
			trend = append(trend, map[string]any{"date": day, "events": count})
		}
		respond.OK(w, map[string]any{"tenant_id": tenantID, "trend": trend, "total": len(events)})
	}
}

// HandleListNexusUsage returns resource usage summary.
// GET /api/v1/nexs/anly/usage
func HandleListNexusUsage(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized, "tenant context required")
			return
		}
		var escrow []map[string]any
		if _dbErr := db.QueryRowsWithin90Days(database.TblCoreEscrowTxns, "amount,status,created_at", tenantID, &escrow); _dbErr != nil {
			slog.Error("QueryRowsWithin90Days failed", "error", _dbErr)
		}
		var staking []map[string]any
		// nexus_staking_ledger → nexus_ledger (Wave-9 consolidation). entry_type replaces event_type.
		if _dbErr := db.QueryRowsCtx(r.Context(), database.TblSharLedger, "amount,entry_type,created_at", "tenant_id", tenantID, &staking); _dbErr != nil {
			slog.Error("QueryRows failed", "error", _dbErr)
		}
		totalEscrow, totalStaking := 0.0, 0.0
		for _, e := range escrow {
			if v, ok := e["token_amount"].(float64); ok {
				totalEscrow += v
			}
		}
		for _, e := range staking {
			if v, ok := e["token_amount"].(float64); ok {
				totalStaking += v
			}
		}
		respond.OK(w, map[string]any{
			"tenant_id":     tenantID,
			"escrow_total":  totalEscrow,
			"staking_total": totalStaking,
			"escrow_txns":   len(escrow),
			"staking_txns":  len(staking),
		})
	}
}

// HandleListNexusForecasts returns a projected forecast based on staking trend.
// GET /api/v1/nexs/anly/forecasts
func HandleListNexusForecasts(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized, "tenant context required")
			return
		}
		var ledger []map[string]any
		if _dbErr := db.QueryRowsWithin90Days(database.TblNexusStakingLedger, "amount,entry_type,created_at", tenantID, &ledger); _dbErr != nil {
			slog.Error("QueryRowsWithin90Days failed", "error", _dbErr)
		}
		total := 0.0
		for _, e := range ledger {
			if v, ok := e["token_amount"].(float64); ok {
				total += v
			}
		}
		// Simple linear 30-day projection from 90-day actual
		projected := total / 3.0
		respond.OK(w, map[string]any{
			"tenant_id":          tenantID,
			"actual_90d":         total,
			"projected_next_30d": projected,
			"confidence":         "low",
			"data_points":        len(ledger),
			"generated_at":       time.Now().UTC().Format(time.RFC3339),
		})
	}
}

// HandleListNexusBenchmarks returns agent behavioral benchmarks.
// GET /api/v1/nexs/anly/benchmarks
func HandleListNexusBenchmarks(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized, "tenant context required")
			return
		}
		var agents []map[string]any
		// M40: total_interactions is in core_agent_telemetry — use vw_agent_full.
		if _dbErr := db.QueryRowsCtx(r.Context(), database.TblAgentFullView,
			"agent_id,name,trust_score,behavioral_drift,risk_tier,total_interactions",
			"tenant_id", tenantID, &agents); _dbErr != nil {
			slog.Error("QueryRows failed", "error", _dbErr)
		}
		if agents == nil {
			agents = []map[string]any{}
		}
		avgDrift, avgTrust := 0.0, 0.0
		for _, a := range agents {
			if d, ok := a["behavioral_drift"].(float64); ok {
				avgDrift += d
			}
			if t, ok := a["trust_score"].(float64); ok {
				avgTrust += t
			}
		}
		if n := float64(len(agents)); n > 0 {
			avgDrift /= n
			avgTrust /= n
		}
		respond.OK(w, map[string]any{
			"tenant_id":       tenantID,
			"total_agents":    len(agents),
			"avg_trust_score": avgTrust,
			"avg_drift":       avgDrift,
			"agents":          agents,
		})
	}
}

// HandleStreamNexusRealtime returns recent platform events (last 15 min proxy).
// GET /api/v1/nexs/anly/realtime
func HandleStreamNexusRealtime(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized, "tenant context required")
			return
		}
		var events []map[string]any
		if _dbErr := db.QueryRowsCursor(database.TblCoreEvents,
			"event_type,action,severity,agent_id,created_at",
			"tenant_id", tenantID, database.ParseCursorPage(r), &events); _dbErr != nil {
			slog.Error("QueryRowsLimited failed", "error", _dbErr)
			respond.InternalError(w, http.StatusInternalServerError, "query_events_failed", nil)
			return
		}
		if events == nil {
			events = []map[string]any{}
		}
		respond.OK(w, map[string]any{
			"tenant_id": tenantID,
			"events":    events,
			"window":    "realtime",
			"count":     len(events),
			"as_of":     time.Now().UTC().Format(time.RFC3339),
		})
	}
}

// HandleGetMonitorGeoSpread returns event distribution by source IP/region.
// GET /api/v1/monitor/geo-spread
func HandleGetMonitorGeoSpread(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized, "tenant context required")
			return
		}
		// core_events has no top-level ip_address column — it lives in payload JSON.
		var events []map[string]any
		if _dbErr := db.QueryRowsWithin90Days(database.TblCoreEvents, "event_type,payload,created_at", tenantID, &events); _dbErr != nil {
			slog.Error("QueryRowsWithin90Days failed", "error", _dbErr)
		}
		byIP := map[string]int{}
		for _, e := range events {
			// Extract ip_address from payload JSON if present
			if payload, ok := e["payload"]; ok {
				switch p := payload.(type) {
				case map[string]any:
					if ip, ok2 := p["ip_address"].(string); ok2 && ip != "" {
						byIP[ip]++
					}
				}
			}
		}
		spread := make([]map[string]any, 0, len(byIP))
		for ip, count := range byIP {
			spread = append(spread, map[string]any{"source": ip, "count": count})
		}
		respond.OK(w, map[string]any{"tenant_id": tenantID, "geo_spread": spread})
	}
}

// HandleGetMonitorDecisionQuality returns HITL decision accuracy metrics.
// GET /api/v1/monitor/decision-quality
func HandleGetMonitorDecisionQuality(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized, "tenant context required")
			return
		}
		var decisions []map[string]any
		if _dbErr := db.QueryRowsCtx(r.Context(), database.TblCoreHitl, "decision_id,status,sla_breach_at,created_at", "tenant_id", tenantID, &decisions); _dbErr != nil {
			slog.Error("QueryRows failed", "error", _dbErr)
		}
		total := len(decisions)
		breached := 0
		for _, d := range decisions {
			if d["sla_breach_at"] != nil {
				breached++
			}
		}
		onTime := total - breached
		accuracy := 0.0
		if total > 0 {
			accuracy = float64(onTime) / float64(total) * 100
		}
		respond.OK(w, map[string]any{
			"tenant_id":       tenantID,
			"total_decisions": total,
			"on_time":         onTime,
			"sla_breached":    breached,
			"accuracy_pct":    accuracy,
		})
	}
}

// HandleSearchMonitor searches platform events by keyword/type.
// GET /api/v1/monitor/search?q=...&event_type=...
func HandleSearchMonitor(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized, "tenant context required")
			return
		}
		eventType := r.URL.Query().Get("event_type")
		var events []map[string]any
		if eventType != "" {
			if _dbErr := db.QueryRowsWithin90DaysCompound(database.TblCoreEvents,
				"event_type,action,severity,agent_id,created_at",
				tenantID, "event_type", eventType, &events); _dbErr != nil {
				slog.Error("QueryRowsWithin90DaysCompound failed", "error", _dbErr)
			}
		} else {
			if _dbErr := db.QueryRowsLimitedWithWindow(database.TblCoreEvents,
				"event_type,action,severity,agent_id,created_at",
				"tenant_id", tenantID, 90, database.PageParams{Limit: 100}, &events); _dbErr != nil {
				slog.Error("QueryRowsLimitedWithWindow failed", "error", _dbErr)
			}
		}
		if events == nil {
			events = []map[string]any{}
		}
		respond.OK(w, map[string]any{
			"tenant_id": tenantID,
			"results":   events,
			"count":     len(events),
			"filter":    map[string]string{"event_type": eventType},
		})
	}
}

// HandleListMonitorTrends returns alert and event trend over the past 90 days.
// GET /api/v1/monitor/trends
func HandleListMonitorTrends(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized, "tenant context required")
			return
		}
		var alerts []map[string]any
		if _dbErr := db.QueryRowsWithin90Days(database.TblSharAlerts, "alert_type,severity,created_at", tenantID, &alerts); _dbErr != nil {
			slog.Error("QueryRowsWithin90Days failed", "error", _dbErr)
		}
		byDay := map[string]int{}
		bySeverity := map[string]int{}
		for _, a := range alerts {
			if ts, ok := a["created_at"].(string); ok && len(ts) >= 10 {
				byDay[ts[:10]]++
			}
			if sev, ok := a["severity"].(string); ok {
				bySeverity[sev]++
			}
		}
		daily := make([]map[string]any, 0, len(byDay))
		for day, count := range byDay {
			daily = append(daily, map[string]any{"date": day, "count": count})
		}
		respond.OK(w, map[string]any{
			"tenant_id":   tenantID,
			"total":       len(alerts),
			"by_severity": bySeverity,
			"daily":       daily,
		})
	}
}

// HandleListIntelCategories returns policies grouped by category.
// GET /api/v1/intel/categories
func HandleListIntelCategories(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized, "tenant context required")
			return
		}
		var policies []map[string]any
		if _dbErr := db.QueryRowsCtx(r.Context(), database.TblQCorePolicies, "policy_id,category,name,status", "tenant_id", tenantID, &policies); _dbErr != nil {
			slog.Error("QueryRows failed", "error", _dbErr)
		}
		byCategory := map[string]int{}
		for _, p := range policies {
			cat := "uncategorized"
			if c, ok := p["category"].(string); ok && c != "" {
				cat = c
			}
			byCategory[cat]++
		}
		cats := make([]map[string]any, 0, len(byCategory))
		for cat, count := range byCategory {
			cats = append(cats, map[string]any{"category": cat, "policy_count": count})
		}
		respond.OK(w, map[string]any{
			"tenant_id":  tenantID,
			"categories": cats,
			"total":      len(policies),
		})
	}
}

// HandleGetIntelForecast returns a staking-based intelligence forecast.
// GET /api/v1/intel/forecast
func HandleGetIntelForecast(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized, "tenant context required")
			return
		}
		var ledger []map[string]any
		if _dbErr := db.QueryRowsWithin90Days(database.TblNexusStakingLedger, "amount,event_type,created_at", tenantID, &ledger); _dbErr != nil {
			slog.Error("QueryRowsWithin90Days failed", "error", _dbErr)
		}
		var verdicts []map[string]any
		if _dbErr := db.QueryRowsCtx(r.Context(), database.TblCoreVerdicts, "verdict_id,outcome,created_at", "tenant_id", tenantID, &verdicts); _dbErr != nil {
			slog.Error("QueryRows failed", "error", _dbErr)
		}
		total := 0.0
		for _, e := range ledger {
			if v, ok := e["token_amount"].(float64); ok {
				total += v
			}
		}
		respond.OK(w, map[string]any{
			"tenant_id":          tenantID,
			"staking_volume_90d": total,
			"verdict_count":      len(verdicts),
			"projected_30d":      total / 3,
			"generated_at":       time.Now().UTC().Format(time.RFC3339),
		})
	}
}
