package reports

import (
	"log/slog"
	"net/http"

	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/byid"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
)

// HandleGetNexsAnomaly — GET /analytics/anomalies/:id.
func HandleGetNexsAnomaly(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblAlerts, "anomaly_id")
}

// HandleGetNexsBenchmark — GET /analytics/benchmarks/:id.
func HandleGetNexsBenchmark(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblNexusComplianceReports, "benchmark_id")
}

// HandleGetNexsForecast — GET /analytics/forecasts/:id.
func HandleGetNexsForecast(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblNexusComplianceReports, "forecast_id")
}

// HandleGetNexsSegment — GET /analytics/segments/:id.
func HandleGetNexsSegment(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblNexusComplianceReports, "segment_id")
}

// HandleUpdateNexsSegment — PUT /analytics/segments/:id.
func HandleUpdateNexsSegment(db *database.SupabaseClient) http.HandlerFunc {
	return byid.UpdateByID(db, database.TblNexusComplianceReports, "segment_id")
}

// HandleDeleteNexsSegment — DELETE /analytics/segments/:id (soft-delete).
func HandleDeleteNexsSegment(db *database.SupabaseClient) http.HandlerFunc {
	return byid.DeleteByID(db, database.TblNexusComplianceReports, "segment_id")
}

// HandleGetNexsUsageRecord — GET /analytics/usage/:id.
func HandleGetNexsUsageRecord(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblQuotaUsage, "record_id")
}

// HandleGetIntelCategory — GET /analytics/intel-categories/:id.
func HandleGetIntelCategory(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblOntology, "category_id")
}

// HandleUpdateIntelCategory — PUT /analytics/intel-categories/:id.
func HandleUpdateIntelCategory(db *database.SupabaseClient) http.HandlerFunc {
	return byid.UpdateByID(db, database.TblOntology, "category_id")
}

// HandleGetIntelForecastItem — GET /analytics/intel-forecasts/:id.
func HandleGetIntelForecastItem(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblNexusComplianceReports, "forecast_id")
}

// HandleGetMarketSignal — GET /analytics/market-signals/:id.
func HandleGetMarketSignal(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblMarketplaceListings, "signal_id")
}

// HandleGetThreat — GET /analytics/threats/:id.
func HandleGetThreat(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblAlerts, "threat_id")
}

// HandleGetAgentUsageRecord — GET /analytics/agent-usage/:id.
func HandleGetAgentUsageRecord(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblQuotaUsage, "record_id")
}

// HandleGetIntentUsageRecord — GET /analytics/intent-usage/:id.
func HandleGetIntentUsageRecord(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblQuotaUsage, "record_id")
}

// HandleGetUsageProjection — GET /analytics/usage-projections/:id.
func HandleGetUsageProjection(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblNexusComplianceReports, "forecast_id")
}

// HandleGetRevenueStream — GET /analytics/revenue-streams/:id.
func HandleGetRevenueStream(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblNexusLedger, "stream_id")
}

// HandleGetStakingPosition — GET /analytics/staking-positions/:id.
func HandleGetStakingPosition(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblNexusStakingLedger, "entry_id")
}

// HandleGetStakingReward — GET /analytics/staking-rewards/:id.
func HandleGetStakingReward(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblNexusStakingLedger, "entry_id")
}

// HandleGetStakingLedgerEntry — GET /analytics/staking-ledger/:id.
func HandleGetStakingLedgerEntry(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblNexusStakingLedger, "entry_id")
}

// HandleListStakingLedger — GET /staking/ledger
//
// (list) but only the /{id} endpoint existed — causing 404/405 in production.
// This handler returns all staking ledger entries for the requesting tenant,
// scoped by tenant_id and paginated.
func HandleListStakingLedger(db *database.SupabaseClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var rows []map[string]any
		if err := db.QueryRowsCursor(
			database.TblNexusStakingLedger, "*",
			"tenant_id", tenantID,
			database.ParseCursorPage(r),
			&rows,
		); err != nil {
			slog.Error("HandleListStakingLedger: query failed", "tenant_id", tenantID, "err", err)
			respond.ErrorWithCode(w, http.StatusInternalServerError, respond.ErrCodeInternal,
				"failed to query staking ledger")
			return
		}
		if rows == nil {
			rows = []map[string]any{}
		}
		respond.OK(w, rows)
	}
}

// HandleGetTransactionSummary — GET /analytics/transactions/:id.
func HandleGetTransactionSummary(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblLedger, "transaction_id")
}

// HandleGetAttackSurfaceItem — GET /analytics/attack-surface/:id.
func HandleGetAttackSurfaceItem(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblAttackSurfaceItems, "item_id")
}

// HandleGetIDSEvent — GET /analytics/ids-events/:id.
func HandleGetIDSEvent(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.ViewIDSEvents, "event_id")
}

// HandleGetTenantUsageRecord — GET /analytics/tenant-usage/:id.
func HandleGetTenantUsageRecord(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblQuotaUsage, "record_id")
}

// HandleUpdateTenantUsageRecord — PUT /analytics/tenant-usage/:id.
func HandleUpdateTenantUsageRecord(db *database.SupabaseClient) http.HandlerFunc {
	return byid.UpdateByID(db, database.TblQuotaUsage, "record_id")
}

// HandleGetTrustTaxClaim — GET /analytics/trust-tax-claims/:id.
func HandleGetTrustTaxClaim(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblTokenWalletLedger, "ledger_id")
}

// HandleUpdateTrustTaxClaim — PUT /analytics/trust-tax-claims/:id.
func HandleUpdateTrustTaxClaim(db *database.SupabaseClient) http.HandlerFunc {
	return byid.UpdateByID(db, database.TblTokenWalletLedger, "ledger_id")
}

// HandleGetComplianceReport — GET /analytics/compliance-reports/:id.
func HandleGetComplianceReport(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblNexusComplianceReports, "report_id")
}
