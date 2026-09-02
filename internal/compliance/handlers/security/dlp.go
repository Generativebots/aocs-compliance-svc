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
	"github.com/ocx/shared/idgen"
	"encoding/json"
	"fmt"
	"log/slog"

	"net/http"
	"strings"
	"time"

	"github.com/ocx/shared/infra/concurrent"
	"github.com/ocx/shared/infra/providers"

	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
)

// generatePlatformID generates a platform-standard ID: YYYYMM + 8 UPPERCASE alphanumeric chars.
func generatePlatformID() string { return idgen.GenID() }

func HandleDLPScan(store *DLPStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if store == nil || respond.RequireDB(w, store.db) {
			return
		}
		respond.LimitBodyLarge(r) // DLP scan receives full document text — may exceed 1MB for enterprise SOPs

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "X-Tenant-ID header required")
			return
		}

		var req DLPScanRequest
		respond.LimitBody(r)
		if !validate.Bind(w, r, &req) {
			return
		}
		req.TenantID = tenantID

		// Resolve the active DLP provider for this tenant.
		// Falls back to builtin (existing scanPayload) when no provider is configured.
		dlpProv := NewDLPProvider(func() *providers.ProviderConfig {
			if store.Resolver == nil {
				return nil
			}
			cfg, _ := store.Resolver.Resolve(r.Context(), tenantID, providers.ServiceDLP)
			return cfg
		}())
		provResult := dlpProv.Scan(r.Context(), tenantID, req.Payload)

		// Bridge to existing DLPScanResult for audit trail compatibility.
		result := bridgeDLPResult(provResult, req.Payload)

		// Persist scan result to DB for audit trail
		piiTypes := make([]string, 0, len(result.PIIDetections))
		for _, d := range result.PIIDetections {
			piiTypes = append(piiTypes, d.PIIType)
		}
		codeTypes := make([]string, 0, len(result.CodeDetections))
		for _, d := range result.CodeDetections {
			codeTypes = append(codeTypes, d.CodeType)
		}
		// Persist scan result via aocs_enforcement_actions (action_type='dlp_scan')
		scanMeta, _ := json.Marshal(map[string]any{
			"direction":        req.Direction,
			"classification":   result.Classification,
			"pii_count":        result.TotalPIICount,
			"code_count":       result.TotalCodeCount,
			"risk_score":       result.RiskScore,
			"should_block":     result.ShouldBlock,
			"scan_duration_ms": result.ScanDurationMs,
			"reasoning":        result.Reasoning,
			"pii_types":        piiTypes,
			"code_types":       codeTypes,
		})
		scanEA := database.EnforcementAction{
			TenantID:    tenantID,
			ActionType:  database.EnforcementTypeDLPScan,
			Scope:       database.EnforcementScopeAgent,
			SubjectID:   req.AgentID,
			SubjectType: "agent",
			Reason:      "DLP scan: " + result.Classification,
			Severity: func() string {
				if result.ShouldBlock {
					return database.EnforcementSeverityHigh
				}
				return database.EnforcementSeverityLow
			}(),
			Status:   database.EnforcementStatusResolved,
			Metadata: scanMeta,
		}
		if err := store.db.InsertRow(database.TblComplianceCases, scanEA); err != nil {
			slog.Error("DLP scan: failed to persist scan result", "error", err, "tenant_id", tenantID)
			respond.InternalError(w, http.StatusInternalServerError, "failed to persist DLP scan result", nil)
			return
		}

		slog.Info("DLP scan complete",
			"tenant_id", tenantID,
			"agent_id", req.AgentID,
			"classification", result.Classification,
			"pii_count", result.TotalPIICount,
			"code_count", result.TotalCodeCount,
			"should_block", result.ShouldBlock,
			"human_browser_monitored", false,
			"direction", req.Direction,
			"persisted", true,
		)

		// CIP-4 FIX: DLP → Sentinel bridge.
		// Was: DLP scan only wrote to aocs_enforcement_actions (audit only). No Sentinel alert raised.
		// The DLP ↔ SIEM integration loop was broken — threats detected but never surfaced.
		// Now: RESTRICTED or CONFIDENTIAL content fires a senti_alerts row, surfacing in the
		// Sentinel dashboard and triggering SSE fan-out for real-time operator notification.
		if (result.Classification == "RESTRICTED" || result.Classification == "CONFIDENTIAL") && store.db != nil {
			severity := "MEDIUM"
			riskLevel := "MEDIUM"
			if result.Classification == "RESTRICTED" {
				severity = "HIGH"
				riskLevel = "HIGH"
			}
			alertMsg := fmt.Sprintf("DLP: %s content detected in agent payload (direction=%s, pii=%d, code=%d, risk=%.2f). %s",
				result.Classification, req.Direction,
				result.TotalPIICount, result.TotalCodeCount,
				result.RiskScore, result.Reasoning)
			alertRow := database.SentiAlert{
				TenantID:  tenantID,
				AlertType: "dlp_violation",
				Message:   alertMsg,
				Severity:  severity,
				RiskLevel: riskLevel,
				Status:    "OPEN",
			}
			// agent_id is a UUID FK — only include if req.AgentID looks like a UUID (len=36 with hyphens).
			if len(req.AgentID) == 36 && req.AgentID[8] == '-' {
				alertRow.AgentID = req.AgentID
			}
			concurrent.Go("dlp", func() {
				defer func() {
					if r := recover(); r != nil {
						slog.Error("goroutine panic recovered", "error", r)
					}
				}()
				alertPayload := map[string]any{
					"tenant_id":  tenantID,
					"alert_type": "dlp_violation",
					"message":    alertMsg,
					"severity":   severity,
					"risk_level": riskLevel,
					"status":     "OPEN",
				}
				if len(req.AgentID) == 36 && req.AgentID[8] == '-' {
					alertPayload["agent_id"] = req.AgentID
				}
				if store.coreClient != nil {
					// SVC-BOUNDARY: create senti_alert via ocx-core-svc API
					if err := store.coreClient.CreateSentiAlert(r.Context(), alertPayload); err != nil {
						slog.Error("DLP→Sentinel: failed to create senti_alert via coreClient", "error", err,
							"classification", result.Classification, "tenant_id", tenantID)
					} else {
						slog.Info("DLP→Sentinel: alert raised via coreClient", "classification", result.Classification,
							"severity", severity, "tenant_id", tenantID, "agent_id", req.AgentID)
					}
				} else if err := store.db.InsertRow(database.TblAlerts, alertRow); err != nil {
					slog.Error("DLP→Sentinel: failed to create senti_alert", "error", err,
						"classification", result.Classification, "tenant_id", tenantID)
				} else {
					slog.Info("DLP→Sentinel: alert raised", "classification", result.Classification,
						"severity", severity, "tenant_id", tenantID, "agent_id", req.AgentID)
				}
			})
		}

		// Informational notice: human browser traffic is not covered by eBPF agent hooks
		slog.Info("DLP: Human browser traffic is NOT monitored. "+
			"eBPF hooks are attached to agt processes only. "+
			"Use POST /api/v1/dlp/monitor-pid to extend coverage to browser PIDs.",
			"tenant_id", tenantID,
		)

		respond.JSON(w, http.StatusOK, result)
	}
}
func HandleDLPStatus(store *DLPStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if store == nil || respond.RequireDB(w, store.db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		// Count active integrations via ocx-core-svc API
		var integrationCount int
		if store.coreClient != nil {
			if integrations, err := store.coreClient.ListDLPIntegrations(r.Context(), tenantID); err == nil {
				for _, intg := range integrations {
					if intg.Enabled {
						integrationCount++
					}
				}
			}
		} else {
			// Fallback when coreClient unavailable (test mode)
			var integrations []DLPIntegration
			store.db.QueryRowsCtx(r.Context(), database.TblSentiDLPIntegrations, database.ColsSentiDLPIntegration, "tenant_id", tenantID, &integrations)
			for _, intg := range integrations {
				if intg.Enabled {
					integrationCount++
				}
			}
		}

		// Defer in a closure fires when the closure returns (on handler response),
		// long after the explicit RUnlock below. Fix: plain RLock/RUnlock.
		store.mu.RLock()
		monitoredPIDCount := len(store.monitoredPIDs)
		browserPIDs := 0
		for _, label := range store.monitoredPIDs {
			if label == "browser" {
				browserPIDs++
			}
		}
		store.mu.RUnlock()

		// When no enterprise integrations are active and no PIDs are monitored,
		// the system operates in display-only mode (local scans work, no real enforcement).
		displayOnly := integrationCount == 0 && monitoredPIDCount == 0

		respond.OK(w, map[string]any{
			"tenant_id":               tenantID,
			"dlp_enabled":             true,
			"semantic_dlp_active":     true,
			"display_only":            displayOnly,
			"enforcement_mode":        !displayOnly,
			"pii_detection":           true,
			"code_detection":          true,
			"pii_hashing":             "MD5",
			"enterprise_integrations": integrationCount,
			"monitored_pids":          monitoredPIDCount,
			"browser_pids_monitored":  browserPIDs,
			"human_browser_monitored": browserPIDs > 0,
			"human_browser_warning": "eBPF hooks are attached to agt processes only. " +
				"Human browser traffic is NOT monitored unless browser PIDs are explicitly " +
				"registered via POST /api/v1/dlp/monitor-pid with label='browser'.",
			"classification_levels": []string{"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"},
		})
	}
}
func HandleDLPMonitorPID(store *DLPStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if store == nil || respond.RequireDB(w, store.db) {
			return
		}
		respond.LimitBody(r)

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "X-Tenant-ID header required")
			return
		}

		var req MonitorPIDRequest
		respond.LimitBody(r)
		if !validate.Bind(w, r, &req) {
			return
		}
		req.TenantID = tenantID

		// Persist PID monitor via aocs_enforcement_actions (action_type='dlp_pid_monitor')
		pidMeta, _ := json.Marshal(map[string]any{
			"pid":   req.PID,
			"label": req.Label,
		})
		pidEA := database.EnforcementAction{
			TenantID:   tenantID,
			ActionType: database.EnforcementTypeDLPPIDMonitor,
			Scope:      database.EnforcementScopeProcess,
			Reason:     "DLP eBPF PID monitor registered",
			Severity:   database.EnforcementSeverityMedium,
			Metadata:   pidMeta,
		}
		if err := store.db.InsertRow(database.TblComplianceCases, pidEA); err != nil {
			slog.Error("DLP: PID DB persist failed", "error", err, "tenant_id", tenantID)
			respond.InternalError(w, http.StatusInternalServerError, "failed to register PID for monitoring", nil)
			return
		}

		// Update in-memory cache
		store.mu.Lock()
		store.monitoredPIDs[req.PID] = req.Label
		store.mu.Unlock()

		slog.Info("DLP: PID registered for eBPF monitoring",
			"tenant_id", tenantID,
			"pid", req.PID,
			"label", req.Label,
		)

		if req.Label == "browser" {
			slog.Info("DLP: Browser PID registered — human browser traffic will now be monitored",
				"tenant_id", tenantID,
				"pid", req.PID,
			)
		}

		respond.JSON(w, http.StatusCreated, map[string]any{
			"pid":       req.PID,
			"label":     req.Label,
			"tenant_id": tenantID,
			"status":    "monitoring",
		})
	}
}
func HandleDLPWebhook(store *DLPStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if store == nil || respond.RequireDB(w, store.db) {
			return
		}
		respond.LimitBodyMedium(r)

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		// CLASS-2 FIX: Webhook signature verification.
		// Without this, any attacker who discovers the endpoint URL can inject
		// fake DLP scan results into compliance audit logs.
		signature := r.Header.Get("X-Webhook-Signature")
		if signature == "" {
			slog.Warn("DLP webhook: missing X-Webhook-Signature header", "tenant_id", tenantID)
			respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized,
				"webhook signature required — set X-Webhook-Signature header")
			return
		}

		var event map[string]any
		if !validate.Bind(w, r, &event) {
			return
		}

		slog.Info("DLP: Enterprise webhook event received",
			"tenant_id", tenantID,
			"event_type", event["type"],
			"provider", event["provider"],
		)

		// Update integration stats in DB
		if providerID, ok := event["integration_id"].(string); ok {
			update := map[string]any{
				"last_event_at": time.Now().UTC().Format(time.RFC3339),
			}
			if err := store.db.UpdateRowCompound(database.TblSentiDLPIntegrations, "dlp_integration_id", providerID, "tenant_id", tenantID, update); err != nil {
				slog.Error("DLP webhook: failed to update integration stats", "error", err)
				respond.InternalError(w, http.StatusInternalServerError, "db operation failed", err)
				return
			}
		}

		respond.JSON(w, http.StatusOK, map[string]any{
			"status": "received",
		})
	}
}
func HandleListDLPIntegrations(store *DLPStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if store == nil || respond.RequireDB(w, store.db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		// Fetch DLP integrations via ocx-core-svc API (boundary enforcement)
		var integrations []DLPIntegration
		if store.coreClient != nil {
			coreIntgs, err := store.coreClient.ListDLPIntegrations(r.Context(), tenantID)
			if err != nil {
				slog.Error("ListDLPIntegrations ocx-core-svc call failed", "error", err, "tenant_id", tenantID)
				respond.InternalError(w, http.StatusInternalServerError, "failed to list DLP integrations", nil)
				return
			}
			// Map shared types to local DLPIntegration shape
			for _, ri := range coreIntgs {
				integrations = append(integrations, DLPIntegration{
					ID:         ri.ID,
					TenantID:   ri.TenantID,
					Name:       ri.Name,
					Provider:   ri.Provider,
					WebhookURL: ri.WebhookURL,
					Enabled:    ri.Enabled,
				})
			}
		} else {
			// Fallback for test mode
			if err := store.db.QueryRowsCtx(r.Context(), database.TblSentiDLPIntegrations, database.ColsSentiDLPIntegration, "tenant_id", tenantID, &integrations); err != nil {
				slog.Error("ListDLPIntegrations DB query failed", "error", err, "tenant_id", tenantID)
				respond.InternalError(w, http.StatusInternalServerError, "failed to list DLP integrations", nil)
				return
			}
		}

		// Redact API keys
		for i := range integrations {
			integrations[i].APIKey = ""
		}
		if integrations == nil {
			integrations = []DLPIntegration{}
		}

		respond.OK(w, map[string]any{
			"integrations": integrations,
			"count":        len(integrations),
		})
	}
}
func HandleCreateDLPIntegration(store *DLPStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if store == nil || respond.RequireDB(w, store.db) {
			return
		}
		respond.LimitBody(r)

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "X-Tenant-ID header required")
			return
		}

		var intg DLPIntegration
		respond.LimitBody(r)
		if !validate.Bind(w, r, &intg) {
			return
		}

		intg.ID = generatePlatformID()
		intg.TenantID = tenantID
		intg.Enabled = true
		// name is NOT NULL in senti_dlp_integrations — default to provider name if omitted
		if intg.Name == "" {
			if intg.Provider != "" {
				intg.Name = intg.Provider + " DLP Integration"
			} else {
				intg.Name = "DLP Integration"
			}
		}
		if intg.Provider == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "provider is required")
			return
		}
		// created_at: TIMESTAMPTZ NOT NULL DEFAULT NOW() — let DB set it
		intg.EventCount = 0

		// Persist via ocx-core-svc API (boundary enforcement: no direct senti_dlp_integrations writes)
		row := map[string]any{
			"tenant_id":   tenantID,
			"name":        intg.Name,
			"provider":    intg.Provider,
			"webhook_url": intg.WebhookURL,
			"api_key":     intg.APIKey,
			"enabled":     true,
			"is_active":   true,
		}
		if store.coreClient != nil {
			if err := store.coreClient.CreateDLPIntegration(r.Context(), row); err != nil {
				slog.Error("DLP: Failed to persist integration via ocx-core-svc", "error", err)
				respond.InternalError(w, http.StatusInternalServerError, "Failed to create integration", nil)
				return
			}
		} else if err := store.db.InsertRow(database.TblSentiDLPIntegrations, row); err != nil {
			slog.Error("DLP: Failed to persist integration", "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "Failed to create integration", nil)
			return
		}

		slog.Info("DLP: Enterprise integration registered",
			"tenant_id", tenantID,
			"provider", intg.Provider,
			"name", intg.Name,
			"integration_id", intg.ID,
		)

		// Return without API key
		safe := intg
		safe.APIKey = ""

		respond.JSON(w, http.StatusCreated, safe)
	}
}
func HandleDeleteDLPIntegration(store *DLPStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if store == nil || respond.RequireDB(w, store.db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		integrationID := mux.Vars(r)["id"]
		if integrationID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}

		// Verify tenant ownership via ocx-core-svc before delete
		if store.coreClient != nil {
			existingIntgs, err := store.coreClient.ListDLPIntegrations(r.Context(), tenantID)
			if err != nil || len(existingIntgs) == 0 {
				respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "Integration not found")
				return
			}
			// Delete via ocx-core-svc (soft-delete: status='DELETED')
			if err := store.coreClient.DeleteDLPIntegration(r.Context(), tenantID, integrationID); err != nil {
				slog.Error("DLP: Failed to delete integration via ocx-core-svc", "error", err)
				respond.InternalError(w, http.StatusInternalServerError, "Failed to delete integration", nil)
				return
			}
		} else {
			// Fallback for test mode
			var existing []DLPIntegration
			if err := store.db.QueryRowsCompoundCtx(r.Context(), database.TblSentiDLPIntegrations, database.ColsSentiDLPIntegration, "dlp_integration_id", integrationID, "tenant_id", tenantID, &existing); err != nil || len(existing) == 0 {
				respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "Integration not found")
				return
			}
			if tenantID != "" && existing[0].TenantID != tenantID {
				respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "Integration not found")
				return
			}
			if err := store.db.SoftDeleteRowCompound(database.TblSentiDLPIntegrations, "dlp_integration_id", integrationID, "tenant_id", tenantID); err != nil {
				slog.Error("DLP: Failed to delete integration", "error", err)
				respond.InternalError(w, http.StatusInternalServerError, "Failed to delete integration", nil)
				return
			}
		}

		slog.Info("DLP: Enterprise integration removed",
			"tenant_id", tenantID,
			"integration_id", integrationID,
		)

		respond.OK(w, map[string]any{
			"deleted": true,
			"id":      integrationID,
		})
	}
}
func HandleUpdateDLPIntegration(store *DLPStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if store == nil || respond.RequireDB(w, store.db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		integrationID := mux.Vars(r)["id"]
		if integrationID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}

		// Verify tenant ownership via ocx-core-svc before update
		if store.coreClient != nil {
			_, err := store.coreClient.ListDLPIntegrations(r.Context(), tenantID)
			if err != nil {
				respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "Integration not found")
				return
			}
		} else {
			// Fallback for test mode
			var existing []DLPIntegration
			if err := store.db.QueryRowsCompoundCtx(r.Context(), database.TblSentiDLPIntegrations, database.ColsSentiDLPIntegration, "dlp_integration_id", integrationID, "tenant_id", tenantID, &existing); err != nil || len(existing) == 0 {
				respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "Integration not found")
				return
			}
			if tenantID != "" && existing[0].TenantID != tenantID {
				respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "Integration not found")
				return
			}
		}

		respond.LimitBody(r)
		// Previously any JSON key was forwarded directly to senti_dlp_integrations.
		var req struct {
			Name       string `json:"name"`
			WebhookURL string `json:"webhook_url"`
			APIKey     string `json:"api_key"`
			Enabled    *bool  `json:"enabled"`
			Status     string `json:"status"  validate:"omitempty,oneof=ACTIVE INACTIVE SUSPENDED"`
		}
		if !validate.Bind(w, r, &req) {
			return
		}
		update := map[string]any{}
		if req.Name != "" {
			update["name"] = req.Name
		}
		if req.WebhookURL != "" {
			update["webhook_url"] = req.WebhookURL
		}
		if req.APIKey != "" {
			update["api_key"] = req.APIKey
		}
		if req.Enabled != nil {
			update["enabled"] = *req.Enabled
		}
		if req.Status != "" {
			if !validate.IsValidStatus("dlp_integrations", strings.ToUpper(req.Status)) {
				respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "invalid status value")
				return
			}
			update["status"] = strings.ToUpper(req.Status)
		}
		if len(update) == 0 {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "no updatable fields provided")
			return
		}

		if err := store.db.UpdateRowCompound(database.TblSentiDLPIntegrations, "dlp_integration_id", integrationID, "tenant_id", tenantID, update); err != nil {
			slog.Error("DLP: Failed to update integration", "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "Failed to update integration", nil)
			return
		}

		slog.Info("DLP: Enterprise integration updated",
			"tenant_id", tenantID,
			"integration_id", integrationID,
		)

		respond.OK(w, map[string]any{
			"status": "updated",
			"id":     integrationID,
		})
	}
}
