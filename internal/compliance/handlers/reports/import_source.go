package reports

// Import Source by-ID handlers
// Table: core_resource_import_sources
// Fills GET/{id}, PUT/{id}, DELETE/{id} gaps from CRUD audit.

import (
	"net/http"
	"strings"

	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)


// PUT /import-sources/{id}
func HandleUpdateImportSource(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		id, idOk := respond.MustGetPathParam(w, r, "id")
		if !idOk {
			return
		}
		respond.LimitBody(r)
		var req UpdateImportSourceRequest
	// GATE-06 FIX (BATCH): removed duplicate LimitBody — double-wrapping halves max body size
		if !validate.Bind(w, r, &req) {
			return
		}
		updates := map[string]any{}
		if req.Name != "" {
			updates["name"] = req.Name
		}
		if req.SourceType != "" {
			updates["tool_type"] = req.SourceType
		}
		if req.Config != nil {
			updates["credential_config"] = req.Config
		}
		if req.Status != "" {
			if !validate.IsValidStatus("import_sources", strings.ToUpper(req.Status)) {
				respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "invalid status value")
				return
			}
			updates["status"] = strings.ToUpper(req.Status)
		}
		if len(updates) == 0 {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "no fields to update")
			return
		}
		// Scope update to calling tenant to prevent cross-tenant write.
		if dbErr := db.UpdateRowCompound(database.TblExtcCatalog, "catalog_id", id, "tenant_id", tenantID, updates); dbErr != nil {
			respond.InternalError(w, http.StatusInternalServerError, "update import source", dbErr)
			return
		}
		respond.JSON(w, http.StatusOK, map[string]any{"id": id, "updated": true})
	}
}

