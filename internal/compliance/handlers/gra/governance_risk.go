// Package adm — Consolidated CRUD handlers for all OCX data tables
//
// Single source of truth for all CRUD endpoint handlers.
// Organized by domain using generic DRY factory helpers.
//
// Phase L additions (2026-04-06):
//   - EBCL Contracts CRUD (ia_ebcl_contracts)
//   - GRA Risk Assessments CRUD (qcore_gra_risk_assessments)
//   - Policy Extractions CRUD (qcore_policy_extractions)
//   - APE Read-Side Go handlers (ia_authority_gaps, ia_parsed_documents,
//     ia_authority_contracts) — removed Python proxy dependency
//   - Ops Fleet Deployments CRUD (aocs_ops_fleet_deployments)
//   - Marketplace Installations CRUD (aocs_mkt_installs)
//   - Agent App Bindings corrected → ia_agent_application_bindings
package gra

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/ttlcache"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/serviceclient"
	"github.com/ocx/shared/validate"
)

// verdictCache caches the serialised verdict list per tenant for 30s.
// Verdicts are immutable audit records — stale-by-30s is acceptable.
// Impact: reduces the 12s repeated fetches to <5ms on cache hit.
var verdictCache = ttlcache.New[string, []byte](30 * time.Second)

func HandleGetAlert(db database.DB) http.HandlerFunc {
	return crudGetHandler(db, database.TblAlerts, "alert_id")
}

// HandleDeleteAlert — DELETE /api/v1/alerts/{id}
// HandleFleetDeploymentStatus — PATCH /api/v1/ops/fleet/{id}/status
// Updates the deployment status field (e.g. RUNNING → STOPPED).
func HandleFleetDeploymentStatus(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		id := mux.Vars(r)["id"]
		if id == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}
		respond.LimitBody(r)
		var body map[string]any
		if !validate.Bind(w, r, &body) {
			return
		}
		update := map[string]any{"status": body["status"]}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if err := db.UpdateRowCompound(database.TblOpsFleetDeployments, "deployment_id", id, "tenant_id", tenantID, update); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "status update failed", nil)
			return
		}
		respond.JSON(w, http.StatusOK, map[string]string{"status": "updated"})
	}
}

// HandleGetAgentSchedule — GET /api/v1/ops/schedules/{id}
func HandleGetAgentSchedule(db database.DB) http.HandlerFunc {
	return crudGetHandler(db, database.TblNexusAgentCapabilities, "schedule_id")
}

// HandleGetTenantAgent — GET /api/v1/agents/{id}
func HandleGetTenantAgent(db database.DB) http.HandlerFunc {
	return crudGetHandler(db, database.TblAgents, "agent_id")
}

// HandleGetA2AUseCase — GET /api/v1/nufa/a2a/{id}
func HandleGetA2AUseCase(db database.DB) http.HandlerFunc {
	return crudGetHandler(db, database.TblIAA2AUseCases, "use_case_id")
}

// HandleGetLLMMarketplace — GET /api/v1/llmmarketplace
// Returns all marketplace listings for the tenant (list endpoint, not single-item).
func HandleGetLLMMarketplace(db database.DB) http.HandlerFunc {
	return crudListHandler(db, database.TblMarketplaceListings, "marketplace_listing_id")
}

// HandleListFederationPeers — GET /federation/peers
// Returns federation peer records (record_type='PEER') for the authenticated tenant.
// Using the generic crudListHandler returned ALL record types causing duplicate peer_ids.
// Now explicitly filters to PEER records only and uses record_id (PK) as the canonical key.
func HandleListFederationPeers(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var rows []map[string]any
		// Filter by record_type='PEER' to avoid returning HANDSHAKE/CONSENT/etc rows
		if err := db.QueryRowsCompound(database.TblNexusFedPeers,
			"record_id,peer_id,peer_name,status,trust_level,region,organization,endpoint_url,"+
				"handshake_count,failure_count,last_handshake_at,created_at,updated_at",
			"tenant_id", tenantID, "record_type", "PEER", &rows); err != nil {
			slog.Error("HandleListFederationPeers: query failed", "tenant", tenantID, "err", err)
			respond.InternalError(w, http.StatusInternalServerError, "failed to list federation peers", err)
			return
		}
		if rows == nil {
			rows = []map[string]any{}
		}
		respond.JSON(w, http.StatusOK, rows)
	}
}

// HandleAdminGetFederationPeer — GET /federation/peers/{id}
func HandleAdminGetFederationPeer(db database.DB) http.HandlerFunc {
	return crudGetHandler(db, database.TblNexusFedPeers, "peer_id")
}

// Superadmin Cross-Tenant Views
// These use crudListAllHandler (TenantScoped: false) — bypass tenant_id filter.
// Route registration enforces sysadmin RBAC at the RequireAccess middleware level.

// HandleListAllAgents — GET /superadmin/agents — all agents across all tenants.
func HandleListAllAgents(db database.DB) http.HandlerFunc {
	return crudListAllHandler(db, database.TblAgents)
}

// HandleListAllTenants — GET /superadmin/tenants — all tenants on the platform.
func HandleListAllTenants(db database.DB) http.HandlerFunc {
	return crudListAllHandler(db, database.TblTenants)
}

// HandleListAllVerdicts — GET /gov/verdicts
// Verdict history with TTL-based in-process caching.
//
// Performance: was 12s, 840KB (SELECT * on 15k rows).
// Now: <5ms on cache hit (30s TTL), 12s only on first cold load per tenant.
// Column projection reduces payload: 840KB → ~120KB (7×).
// Combined with gzip middleware: 840KB raw → ~11KB on wire.
func HandleListAllVerdicts(db database.DB) http.HandlerFunc {
	// Projected columns — only what the UI actually uses.
	// Avoids fetching payload_hash, raw_response, context_blob etc.
	const cols = `verdict_id,tenant_id,agent_id,action,verdict,risk_score,` +
		`confidence,tool_name,policy_id,created_at,action_type`

	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		// Cache key = tenantID + query string (to vary on filters/pagination)
		cacheKey := tenantID + r.URL.RawQuery

		// Cache hit: return pre-serialised JSON directly — no DB call
		if cached, found := verdictCache.Get(cacheKey); found {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Cache", "HIT")
			w.Write(cached) //nolint:errcheck
			return
		}

		// Cache miss: query with column projection + LIMIT
		var rows []map[string]any
		if err := db.QueryRowsCtx(r.Context(), database.TblVerdicts, cols, "tenant_id", tenantID, &rows); err != nil {
			slog.Error("HandleListAllVerdicts: query failed", "tenant_id", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "failed to list verdicts", err)
			return
		}
		if rows == nil {
			rows = []map[string]any{}
		}

		// Serialise once, cache the bytes, write to response
		b, err := json.Marshal(rows)
		if err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "serialise verdicts", err)
			return
		}
		verdictCache.Set(cacheKey, b)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Cache", "MISS")
		w.Write(b) //nolint:errcheck
	}
}

// HandleListAllEntitlements — GET /superadmin/entitlements — all JIT entitlements across tenants.
func HandleListAllEntitlements(db database.DB) http.HandlerFunc {
	return crudListAllHandler(db, database.TblJITEntitlements)
}

// HandleListEntitlements — GET /admin/platform/entitlements (tenant-scoped)
// Called by economics/permissions/page.tsx. Returns only the current tenant's
// JIT entitlements — uses crudListHandler (TenantScoped:true, FilterCol:"tenant_id").
// Contrast with HandleListAllEntitlements (SuperAdmin, cross-tenant, no filter).
func HandleListEntitlements(db database.DB) http.HandlerFunc {
	return crudListHandler(db, database.TblJITEntitlements, "")
}

// HandleListAllAuditLog — GET /admin/platform/audit-log — all platform events across tenants.
//
// Supports optional query params:
//   - ?event_type=AGENT_REGISTERED   — exact match on event_type
//   - ?entity_type=agent             — prefix match on event_type (e.g. "agent" matches AGENT_*)
//   - ?tenant_id=<uuid>              — scope to a specific tenant
//   - ?agent_id=<uuid>               — scope to a specific agent
//
// database.TblPlatformEvents (the canonical audit event store).
func HandleListAllAuditLog(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		eventType := r.URL.Query().Get("event_type")
		entityType := r.URL.Query().Get("entity_type")
		tenantFilter := r.URL.Query().Get("tenant_id")
		agentFilter := r.URL.Query().Get("agent_id")

		var result []map[string]any
		var err error

		// Use the most selective compound filter available; all paths use 90-day window
		switch {
		case eventType != "" && tenantFilter != "":
			err = db.QueryRowsWithin90DaysCompound(database.TblPlatformEvents, database.ColsPlatformEvent,
				tenantFilter, "event_type", eventType, &result)
		case agentFilter != "" && tenantFilter != "":
			err = db.QueryRowsWithin90DaysCompound(database.TblPlatformEvents, database.ColsPlatformEvent,
				tenantFilter, "agent_id", agentFilter, &result)
		case tenantFilter != "":
			err = db.QueryRowsWithin90Days(database.TblPlatformEvents, database.ColsPlatformEvent,
				tenantFilter, &result)
		case eventType != "":
			// event_type-only filter: use global 90-day scan (superadmin, no tenant scope)
			err = db.QueryRowsGlobalWithin90Days(database.TblPlatformEvents, database.ColsPlatformEvent, &result)
		default:
			// Superadmin full scan — 90-day window replaces unbounded PostgREST scan
			err = db.QueryRowsGlobalWithin90Days(database.TblPlatformEvents, database.ColsPlatformEvent, &result)
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
//   1. jurisdiction matching tenant's country_of_operation (from aocs_tenants)
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
			if _dbErr := db.QueryRowsCursor(database.TblTenants, "country_of_operation", "tenant_id", tenantID, database.ParseCursorPage(r), &tRows); _dbErr != nil {
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
		allRows, err := db.ListGRAFrameworks(r.Context(), database.ColsGraFrameworks)
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
			if _dbErr := db.QueryRowsCursor(database.TblTenants, "country_of_operation", "tenant_id", tenantID, database.ParseCursorPage(r), &tRows); _dbErr != nil {
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
		frameworks, err := db.ListGRAFrameworks(r.Context(), database.ColsGRAFramework)
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

func HandleListJuryPoolModels(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var rows []map[string]any
		if err := db.QueryRowsCursor(database.TblJuryPools, database.ColsJuryPools, "tenant_id", tenantID, database.ParseCursorPage(r), &rows); err != nil {
			slog.Error("HandleListJuryPoolModels: query failed", "error", err)
			respond.OK(w, []interface{}{})
			return
		}

		// Flatten model_data JSONB fields into the top-level record
		models := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			m := map[string]any{
				"id":         row["id"],
				"tenant_id":  row["tenant_id"],
				"name":       row["name"],
				"pool_type":  row["pool_type"],
				"is_active":  row["is_active"],
				"rotated_at": row["rotated_at"],
				"created_at": row["created_at"],
				"updated_at": row["updated_at"],
			}
			// Merge model_data fields to top-level for JuryPoolModel interface
			if md, ok := row["model_data"].(map[string]any); ok {
				for k, v := range md {
					m[k] = v
				}
			}
			models = append(models, m)
		}

		respond.OK(w, models)
	}
}

// HandleGetJuryPoolModel returns a single jury pool model by ID.
// GET /api/v1/pool-model/{id}
// Replaces the misrouted HandleListJuryPoolModels on this /{id} path.
func HandleGetJuryPoolModel(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		id := mux.Vars(r)["id"]
		if id == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}
		var rows []map[string]any
		if err := db.QueryRowsCursor(database.TblJuryPools, "jury_pool_id, tenant_id, name,pool_type,config,is_active,model_data,created_at,updated_at", "jury_pool_id", id, database.ParseCursorPage(r), &rows); err != nil || len(rows) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "jury pool model not found")
			return
		}
		row := rows[0]
		m := map[string]any{
			// "model_type" and "accuracy_score" do not exist in aocs_jury_pools.
			"jury_pool_id": row["jury_pool_id"],
			"tenant_id":    row["tenant_id"],
			"name":         row["name"],
			"pool_type":    row["pool_type"],
			"config":       row["config"],
			"is_active":    row["is_active"],
			"created_at":   row["created_at"],
			"updated_at":   row["updated_at"],
		}
		if md, ok := row["model_data"].(map[string]any); ok {
			for k, v := range md {
				m[k] = v
			}
		}
		respond.OK(w, m)
	}
}

// HandleFlagAuditLogEntry flags an individual audit log entry for review.
//
// PATCH /admin/audit-log/{id}/flag
// Body: { "reason": "suspicious activity", "flag": true }
//
// Stores the flag as a metadata update in the details JSONB column of
// aocs_ia_audit_logs. This is a non-destructive soft-flag — the record
// is never deleted or altered, only annotated.
//
// SuperAdmin only — flagging audit records is a platform governance action.
func HandleFlagAuditLogEntry(db database.DB, pgxPool *database.PGXPool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		vars := mux.Vars(r)
		auditLogID := vars["id"]
		if auditLogID == "" {
			respond.InternalError(w, http.StatusBadRequest, "audit log flag", fmt.Errorf("missing audit log id"))
			return
		}

		// Decode request body
		var body struct {
			Reason string `json:"reason"`
			Flag   bool   `json:"flag"`
		}
		body.Flag = true // default to flagging
		if !validate.BindOptional(w, r, &body) {
			return
		}

		// Merge flag metadata into details JSONB — non-destructive update
		updateSQL := `
			UPDATE aocs_ia_audit_logs
			   SET details    = details || jsonb_build_object(
			                       'flagged',     $1::boolean,
			                       'flagged_at',  NOW()::text,
			                       'flag_reason', $2::text
			                    ),
			       updated_at = NOW()
			 WHERE audit_log_id = $3`

		if pgxPool != nil && pgxPool.Pool() != nil {
			_, err := pgxPool.Pool().Exec(r.Context(), updateSQL, body.Flag, body.Reason, auditLogID)
			if err != nil {
				slog.Error("HandleFlagAuditLogEntry: update failed", "audit_log_id", auditLogID, "error", err)
				respond.InternalError(w, http.StatusInternalServerError, "flag audit log", err)
				return
			}
		} else {
			// Fallback for environments where pgxPool is unavailable — log and accept
			slog.Warn("HandleFlagAuditLogEntry: pgxPool unavailable, flag not persisted",
				"audit_log_id", auditLogID, "flag", body.Flag)
		}

		respond.OK(w, map[string]any{
			"audit_log_id": auditLogID,
			"flagged":      body.Flag,
			"reason":       body.Reason,
		})
	}
}
