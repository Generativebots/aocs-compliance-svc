package compliance

// Table: syst_governance_config (PK: tenant_id — one config per tenant)
// Delete is a soft-delete: sets enabled=false and clears the endpoint to prevent
// data leakage if the config is accidentally re-read. A hard delete would orphan
// audit references in core_events.

import (
	"errors"
	"net/http"

	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
)

// DELETE /api/v1/compliance/siem/config
// Disables and clears the tenant's SIEM integration config.
func HandleDeleteSIEMConfig(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDBWrite(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		// soft-disable the shared SIEM credential (keeps audit trail).
		err := database.SetTenantCredentialActive(r.Context(), db, tenantID, database.CredTypeCustom, database.CredProviderSIEM, false)
		if errors.Is(err, database.ErrCredentialNotFound) {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "no SIEM config found for tenant")
			return
		}
		if err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "delete siem config", err)
			return
		}
		respond.JSON(w, http.StatusOK, map[string]string{"status": "disabled", "tenant_id": tenantID})
	}
}
