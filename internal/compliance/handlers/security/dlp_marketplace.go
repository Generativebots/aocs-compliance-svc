// Package handlers — DLP Integration & Marketplace Endpoints
//
// Implements:
//   - POST /api/v1/dlp/scan          — Scan payload for PII/code/secrets
//   - GET  /api/v1/dlp/status         — Current DLP configuration and stats
//   - POST /api/v1/dlp/monitor-pid    — Register a PID for eBPF DLP monitoring
//   - POST /api/v1/dlp/webhook        — Receive results from enterprise DLP tools
//   - GET  /api/v1/dlp/integrations   — List configured enterprise DLP integrations
//   - POST /api/v1/dlp/integrations   — Register a new enterprise DLP integration
//   - DELETE /api/v1/dlp/integrations/{id} — Remove an integration
//   - GET  /api/v1/marketplace/dlp    — Marketplace catalog of available DLP connectors
//
// Human Browser Monitoring:
//
//	eBPF hooks are attached to AGT PROCESSES only. Human browser PIDs are NOT
//	monitored by default. Use POST /api/v1/dlp/monitor-pid to extend coverage.
//	This is explicitly logged in every DLP status response.
package security

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/ocx/shared/respond"

	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
)

func HandleListTenantIntegrations(store *DLPStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if store == nil || respond.RequireDB(w, store.db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		// Collect tenant's activated integrations via ocx-core-svc API
		var integrations []DLPIntegration
		if store.coreClient != nil {
			coreIntgs, err := store.coreClient.ListDLPIntegrations(r.Context(), tenantID)
			if err != nil {
				slog.Error("HandleListTenantIntegrations ocx-core-svc call failed", "error", err, "tenant_id", tenantID)
				respond.InternalError(w, http.StatusInternalServerError, "failed to list tenant integrations", nil)
				return
			}
			for _, ri := range coreIntgs {
				createdAt, _ := time.Parse(time.RFC3339, ri.CreatedAt)
				lastEventAt, _ := time.Parse(time.RFC3339, ri.LastEventAt)
				integrations = append(integrations, DLPIntegration{
					ID:          ri.ID,
					TenantID:    ri.TenantID,
					Name:        ri.Name,
					Provider:    ri.Provider,
					Enabled:     ri.Enabled,
					CreatedAt:   createdAt,
					LastEventAt: lastEventAt,
					EventCount:  ri.EventCount,
				})
			}
		} else if err := store.db.QueryRowsCtx(r.Context(), database.TblSentiDLPIntegrations, database.ColsSentiDLPIntegration, "tenant_id", tenantID, &integrations); err != nil {
			slog.Error("HandleListTenantIntegrations DB query failed", "error", err, "tenant_id", tenantID)
			respond.InternalError(w, http.StatusInternalServerError, "failed to list tenant integrations", nil)
			return
		}

		var active []map[string]any
		for _, intg := range integrations {
			active = append(active, map[string]any{
				"id":            intg.ID,
				"name":          intg.Name,
				"provider":      intg.Provider,
				"enabled":       intg.Enabled,
				"created_at":    intg.CreatedAt,
				"last_event_at": intg.LastEventAt,
				"event_count":   intg.EventCount,
			})
		}

		// Match active integrations with marketplace catalog for enrichment
		catalog := getDLPMarketplaceCatalog()
		catalogMap := make(map[string]MarketplaceDLPConnector)
		for _, c := range catalog {
			catalogMap[c.Provider] = c
		}

		// Enrich active integrations with marketplace metadata
		for i, a := range active {
			provider, _ := a["provider"].(string)
			if mc, ok := catalogMap[provider]; ok {
				active[i]["tab"] = mc.Tab
				active[i]["category"] = mc.Category
				active[i]["icon"] = mc.Icon
				active[i]["docs_url"] = mc.DocsURL
			}
		}

		respond.OK(w, map[string]any{
			"tenant_id":    tenantID,
			"integrations": active,
			"count":        len(active),
		})
	}
}
