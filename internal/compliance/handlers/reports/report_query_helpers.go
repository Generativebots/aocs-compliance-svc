// Package analytics — local request helpers.
//
// tenantFromRequest is the single entrypoint for tenant extraction in this package.
// All analytics handlers MUST use this function — never call auth.GetTenantID directly.
package reports

// tenantFromRequest extracts the tenant ID from the request context using fail-closed semantics.
// SEC-5+SEC-6 FIX: Removed IsDevelopment() header bypass — JWT context is the sole
// source of truth. Any missing tenant causes a 401; no header override allowed.
//
// Usage:
//
//	tenantID, ok := tenantFromRequest(w, r)
//	if !ok { return }
// tenantFromRequestOrDefault returns the tenant from context without failing —
// suitable for super-admin list endpoints that may operate cross-tenant.
// SEC-5 FIX: Returns empty string from context only — no header fallback.
// Caller must handle the empty-string case explicitly.