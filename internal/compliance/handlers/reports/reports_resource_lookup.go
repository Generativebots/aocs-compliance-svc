package reports

import (
	"log/slog"
	"net/http"

	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/byid"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
)

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

// HandleGetTenantUsageRecord — GET /analytics/tenant-usage/:id.
func HandleGetTenantUsageRecord(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblQuotaUsage, "tenant_resource_usage_id")
}

// HandleUpdateTenantUsageRecord — PUT /analytics/tenant-usage/:id.
func HandleUpdateTenantUsageRecord(db *database.SupabaseClient) http.HandlerFunc {
	return byid.UpdateByID(db, database.TblQuotaUsage, "tenant_resource_usage_id")
}

// HandleGetTrustTaxClaim — GET /analytics/trust-tax-claims/:id.
func HandleGetTrustTaxClaim(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblTokenWalletLedger, "entry_id")
}

// HandleUpdateTrustTaxClaim — PUT /analytics/trust-tax-claims/:id.
func HandleUpdateTrustTaxClaim(db *database.SupabaseClient) http.HandlerFunc {
	return byid.UpdateByID(db, database.TblTokenWalletLedger, "entry_id")
}

// HandleGetComplianceReport — GET /analytics/compliance-reports/:id.
func HandleGetComplianceReport(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblSharComplianceReports, "compliance_report_id")
}
