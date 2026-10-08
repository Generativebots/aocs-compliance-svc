// Package adm — Consolidated CRUD handlers for all OCX data tables
//
// Single source of truth for all CRUD endpoint handlers.
// Organized by domain using generic DRY factory helpers.
//
// Phase L additions (2026-04-06):
//   - EBCL Contracts CRUD (ia_ebcl_contracts)
//   - GRA Risk Assessments CRUD (gra_cases)
//   - Policy Extractions CRUD (core_policies)
//   - APE Read-Side Go handlers (ia_authority_gaps, ia_parsed_documents,
//     ia_authority_contracts) — removed Python proxy dependency
//   - Ops Fleet Deployments CRUD (aocs_ops_fleet_deployments)
//   - Marketplace Installations CRUD (extc_installs)
//   - Agent App Bindings corrected → ia_agent_application_bindings
package gra

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ocx/shared/respond"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/serviceclient"
)

// HandleAdminGetFederationPeer — GET /federation/peers/{id}
func HandleAdminGetFederationPeer(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		row, err := database.GetFedPeer(r.Context(), db, tenantID, database.FedPeerKindPeer, mux.Vars(r)["id"])
		if err != nil {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "federation peer not found")
			return
		}
		respond.JSON(w, http.StatusOK, row)
	}
}

// Superadmin Cross-Tenant Views
// These use crudListAllHandler (TenantScoped: false) — bypass tenant_id filter.
// Route registration enforces sysadmin RBAC at the RequireAccess middleware level.

// HandleListAllAuditLog — GET /admin/platform/audit-log — all platform events across tenants.
//
// Supports optional query params:
//   - ?event_type=AGENT_REGISTERED   — exact match on event_type
//   - ?entity_type=agent             — prefix match on event_type (e.g. "agent" matches AGENT_*)
//   - ?tenant_id=<uuid>              — scope to a specific tenant
//   - ?agent_id=<uuid>               — scope to a specific agent
//
// database.TblCoreEvents (the canonical audit event store).
//
// TENANT ISOLATION (defense in depth):
//
//	SuperAdmin: ?tenant_id= filters to a specific tenant; omit for all-tenant scan.
//	Tenant user: JWT tenant_id ALWAYS overrides any ?tenant_id= query param.
//	            A tenant can never read another tenant's audit events.
//	This check is enforced HERE regardless of what the route guard says.
func HandleListAllAuditLog(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		// ── SECURITY: Resolve tenant scope from JWT, not from query param ──────
		// auth.MustGetTenantID enforces JWT is present and valid. isSuperAdmin is
		// read from the JWT app_metadata claim — no DB roundtrip.
		// Non-superadmin callers are ALWAYS scoped to their JWT tenant_id
		// regardless of any ?tenant_id= param they supply.
		// D2: session tenant; a named tenant only with an audited platform
		// grant (TargetTenant); a cross-tenant scan only with ?scope=all and
		// the audited audit:read platform grant (AllTenantsScope).
		tenantFilter := ""
		if r.URL.Query().Get("scope") == "all" {
			var ok bool
			if r, ok = auth.AllTenantsScope(w, r, "audit"); !ok {
				return
			}
		} else {
			tid, r2, ok := auth.TargetTenant(w, r)
			if !ok {
				return
			}
			r, tenantFilter = r2, tid
		}

		eventType := r.URL.Query().Get("event_type")
		entityType := r.URL.Query().Get("entity_type")
		agentFilter := r.URL.Query().Get("agent_id")

		var result []map[string]any
		var err error

		// Use the most selective compound filter available; all paths use 90-day window.
		switch {
		case eventType != "" && tenantFilter != "":
			err = db.QueryRowsWithin90DaysCompound(database.TblCoreEvents, database.ColsPlatformEvent,
				tenantFilter, "event_type", eventType, &result)
		case agentFilter != "" && tenantFilter != "":
			err = db.QueryRowsWithin90DaysCompound(database.TblCoreEvents, database.ColsPlatformEvent,
				tenantFilter, "agent_id", agentFilter, &result)
		case tenantFilter != "":
			err = db.QueryRowsWithin90Days(database.TblCoreEvents, database.ColsPlatformEvent,
				tenantFilter, &result)
		case r.URL.Query().Get("scope") == "all": // AllTenantsScope granted above
			// SuperAdmin full scan — 90-day window.
			err = db.QueryRowsGlobalWithin90Days(r.Context(), database.TblCoreEvents, database.ColsPlatformEvent, &result)
		default:
			// Should never reach here — tenantFilter is always set for non-superadmins above.
			respond.ErrorWithCode(w, http.StatusForbidden, respond.ErrCodeForbidden,
				"tenant_id could not be resolved from JWT")
			return
		}

		if err != nil {
			slog.Error("HandleListAllAuditLog: query failed", "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "list audit log", err)
			return
		}

		// Client-side filter for entity_type prefix match (e.g. "agent" → AGENT_REGISTERED, AGENT_FROZEN)
		if entityType != "" && eventType == "" {
			prefix := strings.ToUpper(entityType) + "_"
			filtered := make([]map[string]any, 0, len(result))
			for _, row := range result {
				if et, ok := row["event_type"].(string); ok && strings.HasPrefix(et, prefix) {
					filtered = append(filtered, row)
				}
			}
			result = filtered
		}

		if result == nil {
			result = []map[string]any{}
		}
		respond.OK(w, map[string]any{
			"events": result,
			"total":  len(result),
		})
	}
}

// GRA: REGULATORY FRAMEWORKS — GET /gra/regulatory-frameworks
//
// ER MODEL (enforced here and in SQL):
//   gra_frameworks is PLATFORM-LEVEL ONLY. Seeded by superadmin.
//   It is read-only for all tenants. No tenant "owns" a framework.
//
//   gra_cases.tenant_id = X           → always tenant-scoped (never platform-level)
//   gra_tenant_status.tenant_id = X   → always tenant-scoped
//
// Frameworks are returned filtered by:
//   1. jurisdiction matching tenant's country_of_operation (from syst_tenants)
//   2. OR jurisdiction is empty (global, applies everywhere)

func HandleListGRARegulatoryFrameworks(db database.DB, coreClient *serviceclient.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		// 1. Get tenant's country of operation via ocx-core-svc API (boundary enforcement)
		country := ""
		if coreClient != nil {
			if tenant, err := coreClient.GetTenant(r.Context(), tenantID); err == nil && tenant != nil {
				country = tenant.CountryOfOperation
			}
		} else {
			// Fallback for test/offline mode
			var tRows []map[string]any
			if _dbErr := db.QueryRowsCursor(database.TblSystTenants, "country_of_operation", "tenant_id", tenantID, database.ParseCursorPage(r), &tRows); _dbErr != nil {
				slog.Error("db operation failed", "method", "QueryRows", "error", _dbErr)
			}
			if len(tRows) > 0 {
				if c, ok := tRows[0]["country_of_operation"].(string); ok {
					country = c
				}
			}
		}

		// 2. Fetch all active platform frameworks
		// ListGRAFrameworks routes through typed DB interface (pgx-first).
		allRows, err := db.ListGRAFrameworks(r.Context(), tenantID, database.ColsGraFrameworks)
		if err != nil {
			slog.Error("ListGRARegulatoryFrameworks query failed", "error", err)
			allRows = []map[string]any{}
		}

		// 3. Filter to match jurisdiction.
		// Rule: if tenant has a known country, only show global (jur=="") + matching rows.
		// If country is not yet configured, show ALL frameworks — the operator needs to see
		// what applies before they can configure their country_of_operation.
		// This is consistent with HandleListGRAComplianceObligations (line 323).
		results := make([]map[string]any, 0)
		for _, row := range allRows {
			// lv_gra_frameworks lives in syst_tenant_settings: only this tenant's rows.
			if tid, _ := row["tenant_id"].(string); tid != "" && tid != tenantID {
				continue
			}
			jur, _ := row["jurisdiction"].(string)
			if country == "" || jur == "" || jur == country {
				results = append(results, row)
			}
		}

		respond.JSON(w, http.StatusOK, map[string]any{
			"frameworks": results,
			"total":      len(results),
			"country":    country,
		})
	}
}

// GRA: COMPLIANCE OBLIGATIONS — GET /gra/compliance-obligations
// No separate table exists or is needed.
// Obligations are derived from gra_frameworks.templates (JSONB[]): each entry
// in a framework's templates array IS a compliance obligation (intent/action/
// suggestion/next-step template the tenant must fulfil under that framework).
//
// Each obligation record is returned enriched with:
//   framework_id, framework_name, enforcement_level, jurisdiction, category
//
// The endpoint filters to the tenant's active framework set (same jurisdiction
// logic as HandleListGRARegulatoryFrameworks).

func HandleListGRAComplianceObligations(db database.DB, coreClient *serviceclient.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		// 1. Get tenant country via ocx-core-svc API (boundary enforcement)
		country := ""
		if coreClient != nil {
			if tenant, err := coreClient.GetTenant(r.Context(), tenantID); err == nil && tenant != nil {
				country = tenant.CountryOfOperation
			}
		} else {
			// Fallback for test/offline mode
			var tRows []map[string]any
			if _dbErr := db.QueryRowsCursor(database.TblSystTenants, "country_of_operation", "tenant_id", tenantID, database.ParseCursorPage(r), &tRows); _dbErr != nil {
				slog.Error("db operation failed", "method", "QueryRows", "error", _dbErr)
			}
			if len(tRows) > 0 {
				if c, ok := tRows[0]["country_of_operation"].(string); ok {
					country = c
				}
			}
		}

		// 2. Fetch all active frameworks
		// Use ColsGRAFramework — the actual DB columns are: framework_id, tenant_id, name, version,
		// jurisdiction, region_code, description, status, etc. There is NO id/enforcement_level/category/templates column.
		frameworks, err := db.ListGRAFrameworks(r.Context(), tenantID, database.ColsGRAFramework)
		if err != nil {
			slog.Error("ListGRAComplianceObligations: frameworks query failed", "error", err)
			respond.OK(w, []interface{}{})
			return
		}

		// 3. Expand each framework into obligation records
		obligations := make([]map[string]any, 0)
		for _, fw := range frameworks {
			// Filter by jurisdiction: only apply when the tenant has a known country.
			jur, _ := fw["jurisdiction"].(string)
			if country != "" && jur != "" && jur != country {
				continue
			}

			// Use framework_id as the canonical PK ("id" column does not exist in aocs_gra_frameworks).
			fwID := fw["framework_id"]
			fwName, _ := fw["name"].(string)
			// enforcement_level and category are not present in the table; default to empty string.
			enfLevel, _ := fw["enforcement_level"].(string)
			category, _ := fw["category"].(string)

			// templates JSONB may or may not exist; treat nil/absent as empty
			templates, _ := fw["templates"].([]interface{})
			for i, tmpl := range templates {
				ob := map[string]any{
					"id":                fmt.Sprintf("%v-ob-%d", fwID, i),
					"framework_id":      fwID,
					"framework_name":    fwName,
					"enforcement_level": enfLevel,
					"category":          category,
					"jurisdiction":      jur,
					"obligation":        tmpl,
				}
				obligations = append(obligations, ob)
			}

			// If no templates, emit one record for the framework itself
			if len(templates) == 0 {
				obligations = append(obligations, map[string]any{
					"id":                fmt.Sprintf("%v-ob-0", fwID),
					"framework_id":      fwID,
					"framework_name":    fwName,
					"enforcement_level": enfLevel,
					"category":          category,
					"jurisdiction":      jur,
					"obligation":        map[string]any{"description": "Comply with " + fwName},
				})
			}
		}

		respond.OK(w, obligations)
	}
}

// JURY POOL MODELS — GET /pool-models, GET /pool-model
// Returns the AI model registry used to populate the HITL jury.
// Table: aocs_jury_pools (id, tenant_id, name, pool_type, config, model_data, is_active)
// model_data JSONB contains: provider, model_name, role, weight, api_key_field, enabled
// Flattened into top-level fields for frontend JuryPoolModel interface compatibility.
