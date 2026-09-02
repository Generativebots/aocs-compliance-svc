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
	"sync"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/concurrent"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

// getResourceTenantID extracts tenant ID from JWT context only.
// SEC-5 FIX: Removed URL-param tenant_id fallback — JWT context is sole source of truth.
// Returns empty string if not authenticated (callers must check and reject).
func getResourceTenantID(r *http.Request) string {
	tenantID, _ := auth.GetTenantID(r.Context())
	return tenantID
}
func mapStr(m map[string]any, key string) string {
	if v, ok := m[key]; ok && v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
func HandleGetResourceGraph(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID := getResourceTenantID(r)
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "tenant context required")
			return
		}

		var (
			nodes []GraphNode
			edges []GraphEdge
			mu    sync.Mutex
			wg    sync.WaitGroup
			errCh = make(chan error, 9)
		)

		wg.Add(9)

		// 1. Import Sources → nodes
		concurrent.Go("resource_graph", func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("goroutine panic recovered", "error", r)
				}
			}()
			defer func() {
				if r := recover(); r != nil {
					slog.Error("goroutine panic recovered", "panic", r)
				}
			}()
			defer wg.Done()
			var imports []map[string]any
			// core_tenant_docs actual cols (verified 2026-05-27): document_id, source_id, source_type,
			// name (NOT title), document_type (NOT doc_type), status, description, created_at
			if err := db.QueryRowsCtx(r.Context(), database.TblCoreTenantDocs, "document_id,source_id,source_type,name,status,document_type,description", "tenant_id", tenantID, &imports); err != nil {
				slog.Error("HandleGetResourceGraph: QueryRows import_sources failed", "error", err)
				errCh <- err
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, imp := range imports {
				nodes = append(nodes, GraphNode{
					ID: mapStr(imp, "source_id"), Type: "IMPORT", Label: mapStr(imp, "name"), Status: mapStr(imp, "status"),
					Metadata: map[string]string{"source_type": mapStr(imp, "source_type"), "doc_type": mapStr(imp, "document_type")},
				})
			}
		})

		// 2. Documents → nodes
		concurrent.Go("resource_graph", func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("goroutine panic recovered", "error", r)
				}
			}()
			defer func() {
				if r := recover(); r != nil {
					slog.Error("goroutine panic recovered", "panic", r)
				}
			}()
			defer wg.Done()
			var docs []map[string]any
			// core_tenant_docs actual cols (verified 2026-05-27): name (NOT file_name),
			// document_type (NOT file_type), status — parse_status, extracted_intents, ai_model_used do NOT exist
			if err := db.QueryRowsCtx(r.Context(), database.TblCoreTenantDocs, "document_id,name,document_type,status,mime_type,file_size,source_type", "tenant_id", tenantID, &docs); err != nil {
				slog.Error("HandleGetResourceGraph: QueryRows core_tenant_docs failed", "error", err)
				errCh <- err
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, doc := range docs {
				nodes = append(nodes, GraphNode{
					ID: mapStr(doc, "document_id"), Type: "DOCUMENT", Label: mapStr(doc, "name"), Status: mapStr(doc, "status"),
					Metadata: map[string]any{"file_type": mapStr(doc, "document_type"), "mime_type": mapStr(doc, "mime_type")},
				})
			}
		})

		// 3. Intents → nodes
		concurrent.Go("resource_graph", func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("goroutine panic recovered", "error", r)
				}
			}()
			defer func() {
				if r := recover(); r != nil {
					slog.Error("goroutine panic recovered", "panic", r)
				}
			}()
			defer wg.Done()
			var intents []map[string]any
			// T.IAProcessIntents maps to core_process_intents (junction table, no name col).
			if err := db.QueryRowsCtx(r.Context(), database.TblCoreIntents, "intent_id,name,description,status,bound_rules,created_at", "tenant_id", tenantID, &intents); err != nil {
				slog.Error("HandleGetResourceGraph: QueryRows ia_intents failed (non-fatal)", "error", err)
				// Non-fatal: continue without intent nodes
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, intent := range intents {
				nodes = append(nodes, GraphNode{
					ID: mapStr(intent, "intent_id"), Type: "INTENT", Label: mapStr(intent, "name"), Status: mapStr(intent, "status"),
					Metadata: map[string]any{"description": mapStr(intent, "description"), "bound_rules": intent["bound_rules"]},
				})
			}
		})

		// 4. Agt → nodes
		concurrent.Go("resource_graph", func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("goroutine panic recovered", "error", r)
				}
			}()
			defer func() {
				if r := recover(); r != nil {
					slog.Error("goroutine panic recovered", "panic", r)
				}
			}()
			defer wg.Done()
			var agt []map[string]any
			if err := db.QueryRowsCtx(r.Context(), database.TblCoreAgents, "agent_id,name,role,status", "tenant_id", tenantID, &agt); err != nil {
				slog.Error("HandleGetResourceGraph: QueryRows agents failed", "error", err)
				errCh <- err
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, agt := range agt {
				nodes = append(nodes, GraphNode{
					ID: mapStr(agt, "agent_id"), Type: "AGT", Label: mapStr(agt, "name"), Status: mapStr(agt, "status"),
					Metadata: map[string]string{"role": mapStr(agt, "role")},
				})
			}
		})

		// 5. GRA Attestations → nodes
		concurrent.Go("resource_graph", func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("goroutine panic recovered", "error", r)
				}
			}()
			defer func() {
				if r := recover(); r != nil {
					slog.Error("goroutine panic recovered", "panic", r)
				}
			}()
			defer wg.Done()
			var attestations []map[string]any
			if err := db.QueryRowsCtx(r.Context(), database.TblNexusTrustAttest, "attestation_id,attestation_type,outcome,attester_id", "tenant_id", tenantID, &attestations); err != nil {
				slog.Error("HandleGetResourceGraph: QueryRows trust_attestations failed", "error", err)
				errCh <- err
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, att := range attestations {
				nodes = append(nodes, GraphNode{
					ID: mapStr(att, "attestation_id"), Type: "GRA", Label: mapStr(att, "attestation_type"), Status: mapStr(att, "outcome"),
				})
			}
		})

		// 6. Relationships → edges
		concurrent.Go("resource_graph", func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("goroutine panic recovered", "error", r)
				}
			}()
			defer func() {
				if r := recover(); r != nil {
					slog.Error("goroutine panic recovered", "panic", r)
				}
			}()
			defer wg.Done()
			var rels []map[string]any
			// Query using the actual PK column and alias it as "id" for mapStr compatibility.
			if err := db.QueryRowsCtx(r.Context(), database.TblConrDocumentConnectors, "document_connector_id AS id,connector_type,display_name,status", "tenant_id", tenantID, &rels); err != nil {
				slog.Error("HandleGetResourceGraph: QueryRows resource_relationships failed (non-fatal)", "error", err)
				// Non-fatal — continue without relationship edges
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, rel := range rels {
				// Add connector as a node; edges built from ia_agent_application_bindings
				nodes = append(nodes, GraphNode{
					ID: mapStr(rel, "id"), Type: "CONNECTOR", Label: mapStr(rel, "display_name"), Status: mapStr(rel, "status"),
					Metadata: map[string]string{"connector_type": mapStr(rel, "connector_type")},
				})
			}
		})

		concurrent.Go("resource_graph", func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("goroutine panic recovered", "error", r)
				}
			}()
			defer func() {
				if r := recover(); r != nil {
					slog.Error("goroutine panic recovered", "panic", r)
				}
			}()
			defer wg.Done()
			var policies []map[string]any
			// tier→category, trigger_intent→name, source_name→name, is_active→status (remapped to existing cols)
			if err := db.QueryRowsCtx(r.Context(), database.TblCorePolicies, "policy_id,name,category,status,scope,agent_id", "tenant_id", tenantID, &policies); err != nil {
				slog.Error("HandleGetResourceGraph: QueryRows policies failed", "error", err)
				errCh <- err
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, pol := range policies {
				nodes = append(nodes, GraphNode{
					ID: mapStr(pol, "policy_id"), Type: "POLICY", Label: mapStr(pol, "name"), Status: mapStr(pol, "status"),
					Metadata: map[string]string{"category": mapStr(pol, "category"), "scope": mapStr(pol, "scope")},
				})
			}
		})

		// 8. Agt ↔ Policy binding edges (FROM core_policies)
		concurrent.Go("resource_graph", func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("goroutine panic recovered", "error", r)
				}
			}()
			defer func() {
				if r := recover(); r != nil {
					slog.Error("goroutine panic recovered", "panic", r)
				}
			}()
			defer wg.Done()
			var policyBindings []map[string]any
			// binding_type→scope (existing col). Gets agent→policy binding via agent_id on core_policies
			if err := db.QueryRowsCtx(r.Context(), database.TblCorePolicies, "agent_id,policy_id,scope", "tenant_id", tenantID, &policyBindings); err != nil {
				slog.Error("HandleGetResourceGraph: QueryRows agent_policy_bindings failed", "error", err)
				errCh <- err
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, pb := range policyBindings {
				edges = append(edges, GraphEdge{
					Source: mapStr(pb, "agent_id"), Target: mapStr(pb, "policy_id"),
					Type: "BOUND_BY_POLICY", Weight: 1.0,
				})
			}
		})

		// 9. Intent ↔ Agt binding edges (from ia_intent_agent_bindings)
		concurrent.Go("resource_graph", func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("goroutine panic recovered", "error", r)
				}
			}()
			defer func() {
				if r := recover(); r != nil {
					slog.Error("goroutine panic recovered", "panic", r)
				}
			}()
			defer wg.Done()
			var intentBindings []map[string]any
			if err := db.QueryRowsCtx(r.Context(), database.TblIAAgentBindings, "intent_id,agent_id,enforcement_mode", "tenant_id", tenantID, &intentBindings); err != nil {
				slog.Error("HandleGetResourceGraph: ia_intent_agent_bindings query failed (non-fatal, continuing)", "error", err)
				// Non-fatal: serve partial graph without intent bindings
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, ib := range intentBindings {
				edges = append(edges, GraphEdge{
					Source: mapStr(ib, "intent_id"), Target: mapStr(ib, "agent_id"),
					Type: "GOVERNS_AGENT", Weight: 1.0,
				})
			}
		})

		wg.Wait()
		close(errCh)

		// Best-effort: log any DB errors but still serve whatever data loaded.
		// A partial graph is better than a 500 that blocks the entire dashboard.
		if err := <-errCh; err != nil {
			slog.Error("HandleGetResourceGraph: some DB queries failed, serving partial graph", "error", err)
		}

		if nodes == nil {
			nodes = []GraphNode{}
		}
		if edges == nil {
			edges = []GraphEdge{}
		}

		respond.OK(w, map[string]any{
			"nodes":       nodes,
			"edges":       edges,
			"total_nodes": len(nodes),
			"total_edges": len(edges),
		})
	}
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
			respond.InternalError(w, http.StatusInternalServerError, "failed to list import sources", nil)
			return
		}
		if sources == nil {
			sources = []map[string]any{}
		}

		respond.OK(w, map[string]any{"sources": sources, "total": len(sources)})
	}
}
func HandleCreateImportSource(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID := getResourceTenantID(r)
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "tenant context required")
			return
		}

		respond.LimitBody(r)
		var req struct {
			SourceType string         `json:"source_type" validate:"required"`
			Name       string         `json:"name"`
			URL        string         `json:"url"`
			Config     map[string]any `json:"config"`
		}
		if !validate.Bind(w, r, &req) {
			return
		}
		row := map[string]any{
			"tenant_id":   tenantID,
			"source_type": req.SourceType,
			"name":        req.Name,
			"url":         req.URL,
			"config":      req.Config,
		}
		// created_at DEFAULT NOW() — DB handles
		if err := db.InsertRow(database.TblCoreTenantDocs, row); err != nil {
			slog.Error("CreateImportSource failed", "error", err, "tenant_id", tenantID)
			respond.InternalError(w, http.StatusInternalServerError, "failed to create import source", nil)
			return
		}
		respond.JSON(w, http.StatusCreated, map[string]any{"status": "created"})
	}
}
func HandleListDocuments(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID := getResourceTenantID(r)
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "tenant context required")
			return
		}

		// Fetch documents indexed from all connected drives
		var docs []map[string]any
		if err := db.QueryRowsCtx(r.Context(), database.TblCoreTenantDocs, database.ColsTenantDocument, "tenant_id", tenantID, &docs); err != nil {
			slog.Error("ListDocuments failed", "error", err, "tenant_id", tenantID)
			respond.InternalError(w, http.StatusInternalServerError, "failed to list documents", nil)
			return
		}
		if docs == nil {
			docs = []map[string]any{}
		}

		// Fetch installed connectors to enrich document rows and power empty states
		var connectors []map[string]any
		// X-21 FIX: was _ = (silent drop) — security teams saw empty graph on DB failure
		// and believed no connected data sources existed, skipping critical reviews.
		var dataUnavailable bool
		if connErr := db.QueryRowsCtx(r.Context(), database.TblConrDocumentConnectors,
			"document_connector_id,connector_type,display_name,status,last_sync_at,documents_synced,sync_enabled",
			"tenant_id", tenantID, &connectors); connErr != nil {
			slog.Error("X-21: resource graph connector query FAILED — graph will show empty connectors. Security teams may skip connector review.",
				"tenant_id", tenantID, "err", connErr)
			dataUnavailable = true
		}
		if connectors == nil {
			connectors = []map[string]any{}
		}

		// Build connector lookup: connector_id -> connector row
		connMap := make(map[string]map[string]any, len(connectors))
		for _, c := range connectors {
			if id, ok := c["document_connector_id"].(string); ok && id != "" {
				connMap[id] = c
			}
		}

		// Enrich each document with connector display name + type for UI badges
		for i, doc := range docs {
			cid, _ := doc["connector_id"].(string)
			if cid != "" {
				if conn, ok := connMap[cid]; ok {
					docs[i]["connector_display_name"] = conn["display_name"]
					docs[i]["connector_type"] = conn["connector_type"]
					docs[i]["connector_status"] = conn["status"]
				}
			}
		}

		respond.OK(w, map[string]any{
			"documents":        docs,
			"connectors":       connectors,
			"total":            len(docs),
			"data_unavailable": dataUnavailable,
		})
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
		if err := db.QueryRowsCtx(r.Context(), database.TblConrDocumentConnectors,
			"document_connector_id,connector_type,display_name,config,auth_config,status",
			"tenant_id", tenantID, &connectors); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "failed to load connectors", nil)
			return
		}
		var connector map[string]any
		for _, c := range connectors {
			if id, _ := c["document_connector_id"].(string); id == connectorID {
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
				database.TblConrDocumentConnectors,
				"document_connector_id", cid,
				"tenant_id", tid,
				map[string]any{
					"last_sync_status": status,
					"documents_synced": synced,
				},
			); _wErr != nil {
				slog.Error("SILENT_DROP_FIXED: UpdateRowCompound",
					"table", database.TblConrDocumentConnectors, "file", "aocs-intel/handlers/analytics/resource_graph.go", "err", _wErr)
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

// HANDLER-1 FIX: Canonical name alias — HandleCreateConnectorSyncJob is the Enterprise AIP standard name.
// Handle{Verb}{Noun} where Verb ∈ {Create, Get, List, Update, Delete}.
// HandleSyncConnectorDocuments kept for backward compatibility; new code should use HandleCreateConnectorSyncJob.
var HandleCreateConnectorSyncJob = HandleSyncConnectorDocuments
