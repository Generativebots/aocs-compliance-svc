// helpers.go — local request helpers for the security handler package.
package security

import (
	"net/http"

	"github.com/ocx/shared/infra/auth"
)

// tenantFromRequest extracts the tenant ID from the JWT context using fail-closed semantics.
// SEC-5+SEC-6 FIX: Removed IsDevelopment() header bypass — JWT context is the sole
// source of truth. Any missing tenant causes a 401; no header override allowed on any env.
//
// Usage:
//
//	tenantID, ok := tenantFromRequest(w, r)
//	if !ok { return }
func tenantFromRequest(w http.ResponseWriter, r *http.Request) (string, bool) {
	tenantID, ok := auth.MustGetTenantID(w, r)
	if !ok {
		return "", false
	}
	return tenantID, true
}
