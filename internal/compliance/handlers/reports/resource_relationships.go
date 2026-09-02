// Package handlers — Resource Graph API for the JARVIS Mind-Map Dashboard.
//
// Integration-first architecture:
//   import_sources (KB/BPM/SOP refs) → aocs_tenant_documents → intent_mappings → resource_relationships
//   GRA trust_attestations govern intents and agt.

package reports

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/concurrent"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
	"github.com/ocx/shared/infra/config"
)

func HandleGetDocument(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID := getResourceTenantID(r)
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "tenant context required")
			return
		}
		docID := mux.Vars(r)["id"]
		if docID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "document id required")
			return
		}

		// F-ADMIN-02 FIX: was QueryRowsCtx with only document_id — any tenant knowing a
		// document_id could read another tenant's document. Added tenant_id compound filter.
		var docs []map[string]any
		if err := db.QueryRowsCompound(database.TblTenantDocuments, database.ColsTenantDocument,
			"document_id", docID, "tenant_id", tenantID, &docs); err != nil || len(docs) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "document not found")
			return
		}

		// Also get intents extracted from this document
		var intents []map[string]any
		if err := db.QueryRowsCtx(r.Context(), database.TblIAProcessIntents, database.ColsIAIntent, "tenant_id", tenantID, &intents); err != nil {
			slog.Error("GetDocument: failed to load extracted intents", "document_id", docID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "failed to load extracted intents", nil)
			return
		}
		if intents == nil {
			intents = []map[string]any{}
		}

		respond.OK(w, map[string]any{"document": docs[0], "extracted_intents": intents})
	}
}
func HandleListRelationships(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID := getResourceTenantID(r)
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "tenant context required")
			return
		}

		var rels []map[string]any
		if err := db.QueryRowsCtx(r.Context(), database.TblDocumentConnectors, database.ColsIAResourceRel, "tenant_id", tenantID, &rels); err != nil {
			slog.Error("ListRelationships failed", "error", err, "tenant_id", tenantID)
			respond.InternalError(w, http.StatusInternalServerError, "failed to list relationships", nil)
			return
		}
		if rels == nil {
			rels = []map[string]any{}
		}

		respond.OK(w, map[string]any{"relationships": rels, "total": len(rels)})
	}
}
func HandleCreateRelationship(db database.DB) http.HandlerFunc {
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
			SourceType       string `json:"source_type"       validate:"required"`
			SourceID         string `json:"source_id"         validate:"required"`
			TargetType       string `json:"target_type"       validate:"required"`
			TargetID         string `json:"target_id"         validate:"required"`
			RelationshipType string `json:"relationship_type"`
			Label            string `json:"label"`
		}
		if !validate.Bind(w, r, &req) {
			return
		}
		if req.RelationshipType == "" {
			req.RelationshipType = "RELATED"
		}
		row := map[string]any{
			"tenant_id":         tenantID,
			"source_type":       req.SourceType,
			"source_id":         req.SourceID,
			"target_type":       req.TargetType,
			"target_id":         req.TargetID,
			"relationship_type": req.RelationshipType,
			"label":             req.Label,
		}
		// created_at DEFAULT NOW() — DB handles
		if err := db.InsertRow(database.TblDocumentConnectors, row); err != nil {
			slog.Error("CreateRelationship failed", "error", err, "tenant_id", tenantID)
			respond.InternalError(w, http.StatusInternalServerError, "failed to create relationship", nil)
			return
		}
		respond.JSON(w, http.StatusCreated, map[string]any{"status": "created"})
	}
}

func HandleBindPolicy(db database.DB) http.HandlerFunc {
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
		var body BindPolicyRequest
		respond.LimitBody(r)
		if !validate.Bind(w, r, &body) {
			return
		}
		if body.AgentID == "" || body.PolicyID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "agent_id and policy_id are required")
			return
		}
		if body.BindingType == "" {
			body.BindingType = "ENFORCED"
		}
		if body.PolicyVersion == 0 {
			body.PolicyVersion = 1
		}

		row := map[string]any{
			"tenant_id":      tenantID,
			"agent_id":       body.AgentID,  // UUID FK — agent selector
			"policy_id":      body.PolicyID, // UUID FK — policy selector
			"policy_version": body.PolicyVersion,
			"binding_type":   body.BindingType,
			"bound_by":       body.BoundBy,
			"status":         "ACTIVE",
			// bound_at / created_at DEFAULT NOW() — DB handles
		}
		// Write to qcore_policy_bindings (agent↔policy junction), NOT qcore_policies.
		// Previously this wrote to qcore_policies (the policy definition table), so no binding
		// was ever created and the gate's policy lookup found zero bindings for every agent.
		if err := db.InsertRow(database.TblQCorePolicyBindings, row); err != nil {
			slog.Error("BindPolicy failed", "error", err, "tenant_id", tenantID)
			respond.InternalError(w, http.StatusInternalServerError, "failed to bind policy", nil)
			return
		}

		slog.Info("Policy bound to agt", "agent_id", body.AgentID, "policy_id", body.PolicyID, "tenant_id", tenantID)
		respond.JSON(w, http.StatusCreated, map[string]any{"enabled": true, "binding_type": body.BindingType})
	}
}
func HandleUnbindPolicy(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID := getResourceTenantID(r)
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "tenant context required")
			return
		}

		agentID := r.URL.Query().Get("agent_id")
		policyID := r.URL.Query().Get("policy_id")
		if agentID == "" || policyID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "agent_id and policy_id query params required")
			return
		}

		if err := db.UpdateRowCompound(database.TblQCorePolicies,
			"agent_id", agentID,
			"tenant_id", tenantID,
			map[string]any{"is_active": false}); err != nil {
			slog.Error("UnbindPolicy soft-delete failed", "error", err, "tenant_id", tenantID)
			respond.InternalError(w, http.StatusInternalServerError, "failed to unbind policy", nil)
			return
		}
		respond.OK(w, map[string]any{"unbound": true})
	}
}
func HandleImportSourceExtract(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID := getResourceTenantID(r)
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "tenant context required")
			return
		}

		sourceID := mux.Vars(r)["source_id"]
		if sourceID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "sourceId is required")
			return
		}

		// 1. Look up the import source
		// F-ADMIN-02 FIX: was QueryRowsCtx with only source_id — cross-tenant access possible.
		var sources []map[string]any
		if err := db.QueryRowsCompound(database.TblTenantDocuments, database.ColsImportSource,
			"source_id", sourceID, "tenant_id", tenantID, &sources); err != nil || len(sources) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "import source not found")
			return
		}
		src := sources[0]

		externalSystem := mapStr(src, "external_system")
		externalRef := mapStr(src, "external_ref")
		title := mapStr(src, "title")

		if externalRef == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "import source has no external_ref URL")
			return
		}

		// 2. Update sync status to IN_PROGRESS
		if err := db.UpdateRowCompound(database.TblTenantDocuments, "source_id", sourceID, "tenant_id", tenantID, map[string]any{
			"status":            "IN_PROGRESS",
			"status_changed_at": time.Now().UTC().Format(time.RFC3339),
		}); err != nil {
			slog.Error("Failed to update sync_status", "source_id", sourceID, "error", err)
		}

		// 3. Fire async extraction (connector reads doc → APE extracts intents)
		extractionID := "extract-" + sourceID[:8]
		concurrent.Go("resource_relationships", func() {
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
			setStatus := func(status, errMsg string) {
				if db == nil {
					return
				}
				upd := map[string]any{"status": status}
				if errMsg != "" {
					upd["sync_error"] = errMsg
				}
				if err := db.UpdateRowCompound(database.TblTenantDocuments, "source_id", sourceID, "tenant_id", tenantID, upd); err != nil {
					slog.Error("Failed to update import source status",
						"source_id", sourceID, "status", status, "error", err)
				}
			}

			slog.Info("APE extraction started",
				"extraction_id", extractionID,
				"source_id", sourceID,
				"external_system", externalSystem,
				"external_ref", externalRef,
				"tenant_id", tenantID,
			)

			// via the externalRef URL and POST them to the APE HTTP service for
			// ML-based intent extraction. This satisfies CIP patent §4.3.1.
			// When OCX_APE_HTTP_URL is NOT set, fall back to metadata-only
			// extraction so existing tenants without APE are not broken.
			//
			// Zero data-residency guarantee: raw document bytes are NEVER
			// written to DB or disk; they exist only in memory during this call.
			apeURL := os.Getenv("OCX_APE_HTTP_URL")
				if apeURL != "" && externalRef != "" {
				// Step 1: Fetch the document bytes in-memory via the external ref URL.
				// Timeout driven by EXTERNAL_HTTP_TIMEOUT_SEC (default 30s) — consistent with
				// the http.Client timeout below and tunable without a redeploy.
				fetchTimeoutSec := config.Get().Services.ExternalHTTPTimeoutSec
				if fetchTimeoutSec <= 0 {
					fetchTimeoutSec = 30
				}
				fetchCtx, fetchCancel := context.WithTimeout(r.Context(), time.Duration(fetchTimeoutSec)*time.Second)
				defer fetchCancel()
				fetchReq, _ := http.NewRequestWithContext(fetchCtx, http.MethodGet, externalRef, nil)
				fetchClient := &http.Client{Timeout: time.Duration(config.Get().Services.ExternalHTTPTimeoutSec) * time.Second}
				docResp, fetchErr := fetchClient.Do(fetchReq)
				if fetchErr != nil {
					slog.Error("APE: failed to fetch document bytes",
						"extraction_id", extractionID, "external_ref", externalRef, "error", fetchErr)
					setStatus("FAILED", fmt.Sprintf("document fetch failed: %v", fetchErr))
					return
				}
				defer docResp.Body.Close()
				docBytes, readErr := io.ReadAll(io.LimitReader(docResp.Body, 10*1024*1024)) // 10 MB cap
				if readErr != nil {
					slog.Error("APE: failed to read document bytes",
						"extraction_id", extractionID, "error", readErr)
					setStatus("FAILED", fmt.Sprintf("document read failed: %v", readErr))
					return
				}

				// Step 2: POST bytes to OCX_APE_HTTP_URL/extract as JSON.
				apePayload, _ := json.Marshal(map[string]any{
					"extraction_id":   extractionID,
					"tenant_id":       tenantID,
					"source_id":       sourceID,
					"external_system": externalSystem,
					"external_ref":    externalRef,
					"title":           title,
					"content":         string(docBytes), // UTF-8 assumption; APE decodes
				})
				apeEndpoint := strings.TrimRight(apeURL, "/") + "/extract"
				apeReq, _ := http.NewRequestWithContext(r.Context(), http.MethodPost,
					apeEndpoint, bytes.NewReader(apePayload))
				apeReq.Header.Set("Content-Type", "application/json")
				apeReq.Header.Set("X-Tenant-ID", tenantID)
				apeReq.Header.Set("X-Extraction-ID", extractionID)

				apeHTTPClient := &http.Client{Timeout: time.Duration(config.Get().Services.ExternalHTTPTimeoutSec*2) * time.Second}
				apeResp, apeErr := apeHTTPClient.Do(apeReq)
				if apeErr != nil {
					slog.Error("APE: HTTP call failed",
						"extraction_id", extractionID, "ape_url", apeEndpoint, "error", apeErr)
					setStatus("FAILED", fmt.Sprintf("APE service call failed: %v", apeErr))
					return
				}
				defer apeResp.Body.Close()

				if apeResp.StatusCode >= 200 && apeResp.StatusCode < 300 {
					// Step 3: Decode APE response → []IntentMapping
					var apeResult struct {
						Intents []map[string]any `json:"intents"`
					}
					if decErr := json.NewDecoder(apeResp.Body).Decode(&apeResult); decErr != nil {
						slog.Error("APE: response decode failed — falling back to metadata extraction",
							"extraction_id", extractionID, "error", decErr)
					} else {
						// Step 4: Insert each intent into intent_mappings
						for _, intent := range apeResult.Intents {
							intent["tenant_id"] = tenantID
							intent["source_id"] = sourceID
							intent["extraction_id"] = extractionID
							if insErr := db.InsertRow(database.TblIAProcessIntents, intent); insErr != nil {
								slog.Error("APE: intent insert failed", "extraction_id", extractionID, "error", insErr)
							}
						}
						setStatus("SYNCED", "")
						slog.Info("APE extraction completed via external APE service",
							"extraction_id", extractionID, "intent_count", len(apeResult.Intents))
						return // APE path done — skip metadata fallback below
					}
				} else {
					respBody, _ := io.ReadAll(io.LimitReader(apeResp.Body, 4096))
					slog.Error("APE: service returned error",
						"extraction_id", extractionID, "status", apeResp.StatusCode, "body", string(respBody))
					setStatus("FAILED", fmt.Sprintf("APE service HTTP %d: %s", apeResp.StatusCode, string(respBody)))
					return
				}
			}

			// Fallback: metadata-only policy extraction (when OCX_APE_HTTP_URL not configured).
			// Satisfies CIP patent requirement: APE extraction → qcore_policies (DRAFT)
			// → aocs_selfheal_proposals (PENDING) for operator review before anything goes live.
			setStatus("SYNCED", "")

			policyName := title
			if policyName == "" {
				policyName = "APE Extracted Policy — " + extractionID
			}
			policyRow := map[string]any{
				"tenant_id":         tenantID,
				"name":              policyName,
				"description":       "Auto-extracted by APE engine from document source: " + externalSystem + "/" + externalRef,
				"policy_type":       "EXTRACTED",
				"enforcement_level": "INFO",
				"status":            "DRAFT",
				"source":            "APE_EXTRACTED",
				"extraction_id":     extractionID,
				"created_at":        "now()",
			}
			if insertErr := db.InsertRow(database.TblQCorePolicies, policyRow); insertErr != nil {
				slog.Error("APE: failed to persist extracted policy",
					"extraction_id", extractionID, "error", insertErr)
				// Non-fatal: document is SYNCED, policy write failure is logged for retry
			} else {
				proposalJSON, _ := json.Marshal(map[string]any{
					"action":          "review_ape_extracted",
					"extraction_id":   extractionID,
					"source_document": externalSystem + "/" + externalRef,
					"policy_name":     policyName,
				})
				proposal := database.PolicySelfHealProposal{
					TenantID:              tenantID,
					PolicyID:              "", // Operator completes link post-review
					TriggerViolationCount: 0,
					Status:                "PENDING",
					ProposedChange:        json.RawMessage(proposalJSON),
				}
				if propErr := db.InsertPolicySelfHealProposal(r.Context(), &proposal); propErr != nil {
					slog.Error("APE: self-heal proposal creation failed",
						"extraction_id", extractionID, "error", propErr)
				}
				slog.Info("APE extraction completed — policy persisted and self-heal proposal created",
					"extraction_id", extractionID,
					"source_id", sourceID,
					"title", title,
					"policy_name", policyName,
				)
			}

		})

		respond.JSON(w, http.StatusAccepted, map[string]any{
			"extraction_id":   extractionID,
			"source_id":       sourceID,
			"external_system": externalSystem,
			"status":          "IN_PROGRESS",
			"message":         "APE extraction started. Document will be read in-memory via connector — never stored.",
		})
	}
}
