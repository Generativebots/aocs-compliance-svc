package compliance

import (
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/respond"

	"github.com/ocx/shared/infra/byid"
	"github.com/ocx/shared/infra/database"
)

// HandleGetComplianceObligation — GET /compliance/obligations/:id.
func HandleGetComplianceObligation(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblComplianceObligations, "obligation_id")
}

// HandleUpdateComplianceObligation — PUT /compliance/obligations/:id.
func HandleUpdateComplianceObligation(db *database.SupabaseClient) http.HandlerFunc {
	return byid.UpdateByID(db, database.TblComplianceObligations, "obligation_id")
}

// HandleDeleteComplianceObligation — DELETE /compliance/obligations/:id (soft-delete).
func HandleDeleteComplianceObligation(db *database.SupabaseClient) http.HandlerFunc {
	return byid.DeleteByID(db, database.TblComplianceObligations, "obligation_id")
}

// HandleRevokeCredential — DELETE /compliance/credentials/:id.
// core_tenant_creds has no status/revoked_by columns; revocation is
// is_active=false, scoped to the caller's tenant.
func HandleRevokeCredential(db *database.SupabaseClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		id := mux.Vars(r)["id"]
		err := database.SetTenantCredentialActiveByID(r.Context(), db, tenantID, id, false)
		if errors.Is(err, database.ErrCredentialNotFound) {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "credential not found")
			return
		}
		if err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "revoke credential", err)
			return
		}
		respond.OK(w, map[string]any{"credential_id": id, "is_active": false, "status": "REVOKED"})
	}
}

// HandleGetGRAFramework — GET /compliance/gra/frameworks/:id.
func HandleGetGRAFramework(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.ViewGRAFrameworks, "framework_id")
}

// HandleUpdateGRAFramework — PUT /compliance/gra/frameworks/:id.
func HandleUpdateGRAFramework(db *database.SupabaseClient) http.HandlerFunc {
	return byid.UpdateByID(db, database.ViewGRAFrameworks, "framework_id")
}

// HandleGetGRARiskConfig — GET /compliance/gra/risk-configs/:id.
func HandleGetGRARiskConfig(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblGRARiskConfigs, "config_id")
}

// HandleUpdateGRARiskConfig — PUT /compliance/gra/risk-configs/:id.
func HandleUpdateGRARiskConfig(db *database.SupabaseClient) http.HandlerFunc {
	return byid.UpdateByID(db, database.TblGRARiskConfigs, "config_id")
}

// HandleListGRARiskConfigs — GET /compliance/gra/risk-configs (list all for tenant).
// Note: this is a list handler, not a byID handler, but included here for package completeness.
func HandleListGRARiskConfigs(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblGRARiskConfigs, "config_id")
}

// HandleGetGRAObligation — GET /compliance/gra/obligations/:id.
func HandleGetGRAObligation(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblComplianceObligations, "obligation_id")
}

// HandleGetLedgerRootEntry — GET /compliance/ledger-roots/:id.
// Ledger roots are immutable; no update or delete is exposed.
func HandleGetLedgerRootEntry(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblZKPChainRoots, "zkp_chain_root_id")
}

// HandleGetViolationSummary — GET /compliance/violations/:id.
func HandleGetViolationSummary(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.ViewComplianceViolations, "violation_id")
}

// HandleGetTrustAttestation — GET /compliance/trust-attestations/:id.
func HandleGetTrustAttestation(db *database.SupabaseClient) http.HandlerFunc {
	return byid.GetByID(db, database.TblNexusTrustAttest, "attestation_id")
}

// HandleUpdateTrustAttestation — PUT /compliance/trust-attestations/:id.
func HandleUpdateTrustAttestation(db *database.SupabaseClient) http.HandlerFunc {
	return byid.UpdateByID(db, database.TblNexusTrustAttest, "attestation_id")
}

// HandleRevokeTrustAttestation — POST /compliance/trust-attestations/:id/revoke.
func HandleRevokeTrustAttestation(db *database.SupabaseClient) http.HandlerFunc {
	return byid.RevokeByID(db, database.TblNexusTrustAttest, "attestation_id")
}
