// Package analytics — read handlers for system/infrastructure tables.
//
// These 15 tables exist in Go models and Supabase but previously had no HTTP
// API exposure. They are written by background workers, domain engines, and
// internal goroutines. These handlers surface them for observability, admin
// monitoring, and tenant-scoped dashboards.
//
// All handlers are:
//   - Tenant-scoped (require valid JWT with tenant_id)
//   - Paginated (limit/offset via parseLimit helper)
//   - Read-only (GET only)
//
// Routes registered in routes_analytics.go:
//
//	Infrastructure:
//	  GET /api/v1/system/cron-locks              → HandleListCronLocks
//	  GET /api/v1/system/nonces                  → HandleListNonces
//	  GET /api/v1/system/used-nonces             → HandleListUsedNonces
//
//	Ghost State:
//	  GET /api/v1/system/ghost-states            → HandleListGhostStates
//	  GET /api/v1/system/ghost-state-drops       → HandleListGhostStateDrops
//	  GET /api/v1/system/ghost-state-drop-events → HandleListGhostStateDropEvents
//
//	Telemetry/Metrics:
//	  GET /api/v1/system/cvic-welford            → HandleListCVICWelfordState
//	  GET /api/v1/system/quota-snapshots         → HandleListQuotaSnapshots
//
//	Background Workers:
//	  GET /api/v1/system/export-history          → HandleListExportHistory
//	  GET /api/v1/system/kill-switches           → HandleListKillSwitchEntries
//	  GET /api/v1/system/activity-executions     → HandleListActivityExecutions
//
//	IA Sub-system:
//	  GET /api/v1/ia/activities                  → HandleListIAActivities
//	  GET /api/v1/system/mcp-server-sessions     → HandleListMCPServerSessions
//	  GET /api/v1/system/mcp-tenant-configs      → HandleListMCPTenantConfigs
package reports

import (
	"log/slog"
	"net/http"

	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
)

// sysListHandler is a generic helper for simple tenant-scoped list endpoints.
func sysListHandler(tbl, cols string, db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		pp := parseLimit(r, 50, 200)
		var rows []map[string]any
		if err := db.QueryRowsLimited(tbl, cols, "tenant_id", tenantID, pp, &rows); err != nil {
			slog.Error("sysListHandler: query failed", "table", tbl, "tenant_id", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, tbl+" query failed", err)
			return
		}
		if rows == nil {
			rows = []map[string]any{}
		}
		respond.OK(w, map[string]any{"data": rows, "table": tbl, "count": len(rows)})
	}
}

// ─── Infrastructure / Locks ───────────────────────────────────────────────────

// ─── Ghost State System ───────────────────────────────────────────────────────

// ─── Telemetry / Metrics ─────────────────────────────────────────────────────

// HandleListExportHistory — declared in export.go as alias for HandleExportHistory.
// Route: GET /api/v1/system/export-history

// ─── Background Workers ───────────────────────────────────────────────────────

// ─── IA Sub-system ────────────────────────────────────────────────────────────
