// Package handlers — Resource Graph API for the JARVIS Mind-Map Dashboard.
//
// Integration-first architecture:
//   import_sources (KB/BPM/SOP refs) → core_tenant_docs → intent_mappings → resource_relationships
//   GRA trust_attestations govern intents and agt.

package reports

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
)

// getResourceTenantID extracts tenant ID from JWT context only.
// Removed URL-param tenant_id fallback — JWT context is sole source of truth.
// Returns empty string if not authenticated (callers must check and reject).
func getResourceTenantID(r *http.Request) string {
	tenantID, _ := auth.GetTenantID(r.Context())
	return tenantID
}
func HandleListImportSources(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID := getResourceTenantID(r)
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "tenant context required")
			return
		}

		var sources []map[string]any
		if err := db.QueryRowsCtx(r.Context(), database.TblCoreTenantDocs, database.ColsImportSource, "tenant_id", tenantID, &sources); err != nil {
			slog.Error("ListImportSources failed", "error", err, "tenant_id", tenantID)
			respond.InternalError(w, http.StatusInternalServerError, "failed to list import sources", err)
			return
		}
		if sources == nil {
			sources = []map[string]any{}
		}

		respond.OK(w, map[string]any{"sources": sources, "total": len(sources)})
	}
}

// HandleSyncConnectorDocuments performs an inline sync for a specific drive connector.
// Supports: google_drive, sharepoint, s3. Runs async (responds 202 immediately).
// POST /api/v1/resources/documents/sync/{connector_id}
func HandleSyncConnectorDocuments(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID := getResourceTenantID(r)
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "tenant context required")
			return
		}
		connectorID := mux.Vars(r)["connector_id"]
		if connectorID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "connector_id required")
			return
		}

		// Load connector record
		var connectors []map[string]any
		if err := db.QueryRowsCtx(r.Context(), database.TblConrRagSources,
			"connector_id,connector_type,display_name,config,auth_config,status",
			"tenant_id", tenantID, &connectors); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "failed to load connectors", err)
			return
		}
		var connector map[string]any
		for _, c := range connectors {
			if id, _ := c["connector_id"].(string); id == connectorID {
				connector = c
				break
			}
		}
		if connector == nil {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "connector not found or not installed")
			return
		}

		connType, _ := connector["connector_type"].(string)
		displayName, _ := connector["display_name"].(string)

		// Industry practice: capture all values needed by the goroutine before launch.
		// context.WithoutCancel: detach from request lifetime (response will be sent
		// before sync completes) but preserve service shutdown signals.
		syncCtx := context.WithoutCancel(r.Context())
		go func(ctx context.Context, tid, cid, cType, cName string, conn map[string]any) {
			defer func() {
				if rec := recover(); rec != nil {
					slog.Error("sync panic recovered", "connector_id", cid, "panic", rec)
				}
			}()
			var synced int
			var syncErr error
			switch cType {
			case "google_drive":
				synced, syncErr = syncGoogleDrive(ctx, db, tid, cid, conn)
			case "sharepoint":
				synced, syncErr = syncSharePoint(ctx, db, tid, cid, conn)
			case "s3":
				synced, syncErr = syncS3(ctx, db, tid, cid, conn)
			default:
				slog.Warn("Unknown connector type — sync skipped", "type", cType)
				return
			}
			status := "synced"
			if syncErr != nil {
				status = "error"
				slog.Error("Connector sync failed", "connector_id", cid, "type", cType, "error", syncErr)
			} else {
				slog.Info("Connector sync complete", "connector_id", cid, "type", cType, "synced", synced)
			}
			// Repository pattern: update connector status via typed method, never raw SQL in handlers
			if _wErr := db.UpdateRowCompound(
				database.TblConrRagSources,
				"connector_id", cid,
				"tenant_id", tid,
				map[string]any{
					"last_sync_status": status,
					"documents_synced": synced,
				},
			); _wErr != nil {
				slog.Error("db write failed: UpdateRowCompound",
					"table", database.TblConrRagSources, "file", "reports/resource_graph.go", "err", _wErr)
			}
		}(syncCtx, tenantID, connectorID, connType, displayName, connector)

		respond.JSON(w, http.StatusAccepted, map[string]any{
			"status":         "sync_started",
			"connector_id":   connectorID,
			"connector_type": connType,
			"connector_name": displayName,
			"message":        "Sync started — documents will appear as they are indexed",
		})
	}
}

// Canonical name alias — HandleCreateConnectorSyncJob is the Enterprise AIP standard name.
// Handle{Verb}{Noun} where Verb ∈ {Create, Get, List, Update, Delete}.
// HandleSyncConnectorDocuments kept for backward compatibility; new code should use HandleCreateConnectorSyncJob.
var HandleCreateConnectorSyncJob = HandleSyncConnectorDocuments
