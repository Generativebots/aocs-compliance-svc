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

// HandleListCronLocks — GET /api/v1/system/cron-locks
// Lists active distributed cron locks for the tenant. Used to monitor which
// background jobs are currently locked (preventing double-execution).
func HandleListCronLocks(db database.DB) http.HandlerFunc {
	return sysListHandler(database.TblCoreCronLocks, "*", db)
}

// HandleListNonces — GET /api/v1/system/nonces
// Lists active (unconsumed) MFA/replay-prevention nonces for the tenant.
func HandleListNonces(db database.DB) http.HandlerFunc {
	return sysListHandler(database.TblCoreNonces, "*", db)
}

// HandleListUsedNonces — GET /api/v1/system/used-nonces
// Lists consumed nonce replay log entries. Used for security auditing.
func HandleListUsedNonces(db database.DB) http.HandlerFunc {
	return sysListHandler(database.TblUsedNonces, "*", db)
}

// ─── Ghost State System ───────────────────────────────────────────────────────

// HandleListGhostStates — GET /api/v1/system/ghost-states
// Lists ghost states — stale agent state snapshots flagged for cleanup.
// Written by the ghost-state detector goroutine in aocs-gate.
func HandleListGhostStates(db database.DB) http.HandlerFunc {
	return sysListHandler(database.TblGhostStates, "*", db)
}

// HandleListGhostStateDrops — GET /api/v1/system/ghost-state-drops
// Lists ghost state drop counter records (aggregated drop counts by agent).
func HandleListGhostStateDrops(db database.DB) http.HandlerFunc {
	return sysListHandler(database.TblGhostStateDropCounter, "*", db)
}

// HandleListGhostStateDropEvents — GET /api/v1/system/ghost-state-drop-events
// Lists individual ghost state drop events (one row per drop action).
func HandleListGhostStateDropEvents(db database.DB) http.HandlerFunc {
	return sysListHandler(database.TblGhostStateDropEvents, "*", db)
}

// ─── Telemetry / Metrics ─────────────────────────────────────────────────────

// HandleListCVICWelfordState — GET /api/v1/system/cvic-welford
// Lists CVIC (Continuous Value & Integrity Checker) Welford online
// variance state records. Used for statistical anomaly detection.
func HandleListCVICWelfordState(db database.DB) http.HandlerFunc {
	return sysListHandler(database.TblCVICWelfordState, "*", db)
}

// HandleListQuotaSnapshots — GET /api/v1/system/quota-snapshots
// Lists hourly/daily quota snapshot records for the tenant.
// Written by the quota enforcement goroutine.
func HandleListQuotaSnapshots(db database.DB) http.HandlerFunc {
	return sysListHandler(database.TblQuotaSnapshotLog, "*", db)
}

// HandleListExportHistory — declared in export.go as alias for HandleExportHistory.
// Route: GET /api/v1/system/export-history

// ─── Background Workers ───────────────────────────────────────────────────────

// HandleListKillSwitchEntries — GET /api/v1/system/kill-switches
// Lists active kill switch entries. Kill switches immediately halt specific
// agent actions or API paths without a deployment.
func HandleListKillSwitchEntries(db database.DB) http.HandlerFunc {
	return sysListHandler(database.TblCoreKillSwitch, "*", db)
}

// HandleListActivityExecutions — GET /api/v1/system/activity-executions
// Lists IA activity execution records — each run of an intent activity step.
func HandleListActivityExecutions(db database.DB) http.HandlerFunc {
	return sysListHandler(database.TblActivityExecutions, "*", db)
}

// ─── IA Sub-system ────────────────────────────────────────────────────────────

// HandleListIAActivities — GET /api/v1/ia/activities
// Lists Intent Architecture activity definitions for the tenant.
func HandleListIAActivities(db database.DB) http.HandlerFunc {
	return sysListHandler(database.TblCoreDispatches, "*", db)
}

// HandleListMCPServerSessions — GET /api/v1/system/mcp-server-sessions
// Lists active MCP server sessions. Each session represents an active
// connection between an agent and a connected MCP tool server.
func HandleListMCPServerSessions(db database.DB) http.HandlerFunc {
	return sysListHandler(database.TblMCPServerSessions, "*", db)
}

// HandleListMCPTenantConfigs — GET /api/v1/system/mcp-tenant-configs
// Lists per-tenant MCP configuration overrides (rate limits, allowed tools, etc).
func HandleListMCPTenantConfigs(db database.DB) http.HandlerFunc {
	return sysListHandler(database.TblMCPTenantConfigs, "*", db)
}
