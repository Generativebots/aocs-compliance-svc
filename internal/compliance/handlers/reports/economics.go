// Package handlers — Analytics, Reports, Dashboards, Export handlers.
//
// These are DB-backed implementations for analytics features. Reports and
// compliance reports use the compliance_reports table. Dashboards use
// platform_config for storage. Export jobs are computed at request time.
package reports

import (
	"encoding/json"
	"net/http"

	"github.com/ocx/shared/respond"

	"github.com/ocx/shared/infra/database"
)

// ESC — Missing routes called by frontend

// HandleEscrowStats DELETED — architectural anti-pattern.
// Frontend derives these from GET /esc/history which it already fetches.

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
			respond.InternalError(w, http.StatusServiceUnavailable, "query staking ledger", _dbErr)
			return
		}
		if _dbErr := db.QueryRowsCtx(r.Context(), database.TblCoreEscrowTxns, "transaction_id,tenant_id,amount,status,created_at", "", "", &escrow); _dbErr != nil {
			respond.InternalError(w, http.StatusServiceUnavailable, "query escrow transactions", _dbErr)
			return
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
			respond.InternalError(w, http.StatusServiceUnavailable, "query revenue", err)
			return
		}
		byType := map[string]float64{}
		byTenant := map[string]float64{}
		var totalRevenue float64
		for _, e := range entries {
			amt, _ := adminParseFloat(e["amount"])
			evType, _ := e["entry_type"].(string)
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
