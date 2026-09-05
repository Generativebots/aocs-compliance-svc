// Package handlers — Analytics, Reports, Dashboards, Export handlers.
//
// These are DB-backed implementations for analytics features. Reports and
// compliance reports use the compliance_reports table. Dashboards use
// platform_config for storage. Export jobs are computed at request time.
package reports

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
)

func HandleDeleteDashboard(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		dashID := mux.Vars(r)["id"]
		if dashID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}
		// Was returning {"status":"deleted"} without touching the DB.
		// Dashboards are stored in syst_governance_config keyed by (category, key).
		// category = "dashboard_<tenantID>", key = dashID (UUID set on create).
		if err := db.UpdateRowCompound(database.TblPlatformConfig,
			"category", "dashboard_"+tenantID,
			"key", dashID,
			map[string]any{"is_active": false}); err != nil {
			slog.Error("DeactivateDashboard failed", "dashboard_id", dashID, "tenant_id", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "failed to deactivate dashboard", nil)
			return
		}
		respond.OK(w, map[string]string{"status": "deactivated", "id": dashID})
	}
}

// ESC — Missing routes called by frontend

// HandleGetEscrowHistory — GET /api/v1/esc/history
// Returns escrow history scoped to the last 90 days by default.
// Pass ?start_date=RFC3339 to extend the window (triggers "refine search" UX on frontend).
// FK filters: ?agent_id= narrows by agent FK.
// No ?limit — the 90-day window is the boundary.
func HandleGetEscrowHistory(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		// FK filter: narrow by agent PK (not pagination)
		agentID := r.URL.Query().Get("agent_id")
		// Business range filters — not pagination
		startDate := r.URL.Query().Get("start_date")
		endDate := r.URL.Query().Get("end_date")

		rows, err := db.QueryEscrowHistory(tenantID, agentID, startDate, endDate)
		if err != nil {
			slog.Error("EscrowHistory query failed, falling back", "error", err)
			var fallback []map[string]any
			if _dbErr := db.QueryRowsWithin90Days(database.TblCoreEscrowTxns, database.ColsEscrowTransactions, tenantID, &fallback); _dbErr != nil {
				slog.Error("db operation failed", "method", "QueryRowsWithin90Days", "error", _dbErr)
				respond.InternalError(w, http.StatusInternalServerError, "escrow_query_failed", nil)
				return
			}
			if fallback == nil {
				fallback = []map[string]any{}
			}
			respond.OK(w, fallback)
			return
		}
		if rows == nil {
			rows = []map[string]any{}
		}
		respond.OK(w, map[string]any{
			"data": rows,
			"total": len(rows),
			"data_window": map[string]any{
				"days":       database.DefaultListWindowDays,
				"start_date": startDate,
				"end_date":   endDate,
			},
		})
	}
}

// HandleEscrowStats DELETED — architectural anti-pattern.
// Was: fetches core_escrow_txns → counts pending/released/blocked in Go.
// Frontend derives these from GET /esc/history which it already fetches.

// HandleValidateEscrow — POST /api/v1/esc/validate
func HandleValidateEscrow(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		var req struct {
			EscrowID string `json:"escrow_id"`
		}
		respond.LimitBody(r)
		if !validate.Bind(w, r, &req) {
			return
		}
		if req.EscrowID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "escrow_id is required")
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		// Check if esc entry exists and is releasable
		var rows []map[string]any
		if _dbErr := db.QueryRowsCtx(r.Context(), database.TblCoreEscrowTxns, "status,agent_id,tool_name,tenant_id", "transaction_id", req.EscrowID, &rows); _dbErr != nil {
			slog.Error("db operation failed", "method", "QueryRows", "error", _dbErr)
			respond.InternalError(w, http.StatusInternalServerError, "escrow_validate_query_failed", nil)
			return
		}
		if len(rows) == 0 {
			respond.OK(w, map[string]any{
				"valid":   false,
				"message": "Esc entry not found",
			})
			return
		}
		// Verify tenant ownership
		if rt, ok := rows[0]["tenant_id"].(string); ok && rt != tenantID && tenantID != "" {
			respond.OK(w, map[string]any{
				"valid":   false,
				"message": "Esc entry not found",
			})
			return
		}
		status, _ := rows[0]["status"].(string)
		releasable := status == "PENDING" || status == "HELD"
		respond.OK(w, map[string]any{
			"valid":     releasable,
			"escrow_id": req.EscrowID,
			"status":    status,
			"agent_id":  rows[0]["agent_id"],
			"tool_name": rows[0]["tool_name"],
			"message":   map[bool]string{true: "Esc entry is valid for release", false: "Esc entry is not in a releasable state"}[releasable],
		})
	}
}

// ─── Admin Economics Overview ─────────────────────────────────────────────────
// GET /admin/economics/overview
// Cross-table platform-wide summary from nexus_staking_ledger + core_escrow_txns.
// nolint:tenant_filter — SuperAdmin cross-tenant view; no tenant_id filter applied.
func HandleGetEconomicsOverview(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		var staking, escrow []map[string]any
		// nexus_staking_ledger → nexus_ledger (Wave-9 consolidation). entry_type replaces event_type.
		if _dbErr := db.QueryRowsCtx(r.Context(), database.TblSharLedger, "entry_id,tenant_id,amount,entry_type,created_at", "", "", &staking); _dbErr != nil {
			slog.Error("db operation failed", "method", "QueryRows", "error", _dbErr)
		}
		if _dbErr := db.QueryRowsCtx(r.Context(), database.TblCoreEscrowTxns, "transaction_id,tenant_id,amount,status,created_at", "", "", &escrow); _dbErr != nil {
			slog.Error("db operation failed", "method", "QueryRows", "error", _dbErr)
		}
		var stakingTotal, escrowTotal float64
		for _, e := range staking {
			v, _ := adminParseFloat(e["amount"])
			stakingTotal += v
		}
		for _, e := range escrow {
			v, _ := adminParseFloat(e["amount"])
			escrowTotal += v
		}
		respond.OK(w, map[string]any{
			"platform_staking_total": stakingTotal,
			"platform_escrow_total":  escrowTotal,
			"staking_entry_count":    len(staking),
			"escrow_entry_count":     len(escrow),
			"total_volume":           stakingTotal + escrowTotal,
		})
	}
}

// ─── Admin Economics Revenue ──────────────────────────────────────────────────
// GET /admin/economics/revenue
// Platform-wide revenue breakdown from nexus_staking_ledger grouped by event_type.
// nolint:tenant_filter — SuperAdmin cross-tenant view; no tenant_id filter applied.
func HandleGetEconomicsRevenue(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		var entries []map[string]any
		// nexus_staking_ledger → nexus_ledger (Wave-9). entry_type replaces event_type; peer_id replaces agent_id.
		if err := db.QueryRowsCtx(r.Context(), database.TblSharLedger,
			"entry_id,tenant_id,peer_id,amount,entry_type,properties,created_at",
			"", "", &entries); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "query revenue", err)
			return
		}
		byType := map[string]float64{}
		byTenant := map[string]float64{}
		var totalRevenue float64
		for _, e := range entries {
			amt, _ := adminParseFloat(e["amount"])
			evType, _ := e["event_type"].(string)
			tid, _ := e["tenant_id"].(string)
			if evType == "" {
				evType = "UNKNOWN"
			}
			byType[evType] += amt
			byTenant[tid] += amt
			totalRevenue += amt
		}
		typeBreakdown := make([]map[string]any, 0, len(byType))
		for k, v := range byType {
			typeBreakdown = append(typeBreakdown, map[string]any{"event_type": k, "total": v})
		}
		respond.OK(w, map[string]any{
			"total_revenue": totalRevenue,
			"total_entries": len(entries),
			"by_event_type": typeBreakdown,
			"tenant_count":  len(byTenant),
		})
	}
}

// adminParseFloat safely converts json.Number / float64 / nil to float64.
func adminParseFloat(v interface{}) (float64, error) {
	switch val := v.(type) {
	case float64:
		return val, nil
	case json.Number:
		return val.Float64()
	case nil:
		return 0, nil
	}
	return 0, nil
}
