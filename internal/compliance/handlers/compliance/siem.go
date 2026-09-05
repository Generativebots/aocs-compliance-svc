package compliance

// Table: syst_governance_config (PK: tenant_id — one config per tenant)
// Delete is a soft-delete: sets enabled=false and clears the endpoint to prevent
// data leakage if the config is accidentally re-read. A hard delete would orphan
// audit references in core_events.

import (
	"net/http"

	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
)

// DELETE /api/v1/compliance/siem/config
// Disables and clears the tenant's SIEM integration config.
func HandleDeleteSIEMConfig(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		// Check config exists first
		var existing []map[string]any
		if dbErr := db.QueryRowsCtx(r.Context(), database.TblCoreTenantCreds, database.ColsSiemConfigs, "tenant_id", tenantID, &existing); dbErr != nil || len(existing) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "no SIEM config found for tenant")
			return
		}
		// Soft-delete: disable without removing the audit record
		updates := map[string]any{
			"enabled":          false,
			"webhook_endpoint": "",
		}
		if dbErr := db.UpdateRow(database.TblSIEMConfigs, "tenant_id", tenantID, updates); dbErr != nil {
			respond.InternalError(w, http.StatusInternalServerError, "delete siem config", dbErr)
			return
		}
		respond.JSON(w, http.StatusOK, map[string]string{"status": "disabled", "tenant_id": tenantID})
	}
}
