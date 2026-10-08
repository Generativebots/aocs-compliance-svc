package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	dcompliance "github.com/ocx/compliance/internal/compliance/domain/compliance"
	"github.com/ocx/compliance/internal/compliance/handlers/security"
	"github.com/ocx/shared/idgen"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/providers"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

// OpenAI Chat Completion Data Models for Universal Agent Interception

type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
	Name    string `json:"name,omitempty"`
}

type ChatCompletionRequest struct {
	Model       string        `json:"model"`
	Messages    []ChatMessage `json:"messages"`
	Temperature float64       `json:"temperature,omitempty"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	Stream      bool          `json:"stream,omitempty"`
}

type ChatChoice struct {
	Index        int         `json:"index"`
	Message      ChatMessage `json:"message"`
	FinishReason string      `json:"finish_reason"`
}

type ChatUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type GovernanceAuditMeta struct {
	EvidenceID   string `json:"evidence_id"`
	ChainHash    string `json:"chain_hash"`
	PrevHash     string `json:"prev_hash"`
	DLPStatus    string `json:"dlp_status"`
	PolicyPassed bool   `json:"policy_passed"`
	ScanDuration int64  `json:"scan_duration_ms"`
}

type ChatCompletionResponse struct {
	ID         string              `json:"id"`
	Object     string              `json:"object"`
	Created    int64               `json:"created"`
	Model      string              `json:"model"`
	Choices    []ChatChoice        `json:"choices"`
	Usage      ChatUsage           `json:"usage"`
	Governance GovernanceAuditMeta `json:"aocs_governance"`
}

// HandleUniversalAgentChatProxy acts as an OpenAI-compatible reverse proxy and control plane.
// Any AI agent in the enterprise (LangGraph, AutoGen, LlamaIndex, OpenAI SDK, SAP Joule, Copilot)
// points its OPENAI_BASE_URL to this endpoint.
//
// Pipeline:
// 1. Authenticates tenant & extracts Agent ID.
// 2. Pre-flight DLP analysis of user prompt / conversation messages.
// 3. Blocks prompt if critical data exfiltration (SSN, credit card, API secrets) is detected.
// 4. Proxies request to upstream LLM (or executes compliant response if mock/loopback).
// 5. Post-flight egress DLP analysis of LLM response.
// 6. Cryptographically seals the entire interaction into the Patent P-03 Merkle chain (compl_evidence).
func HandleUniversalAgentChatProxy(db database.DB, dlpStore *security.DLPStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok || tenantID == "" {
			respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized, "unauthorized agent execution")
			return
		}

		agentID := r.Header.Get("X-Agent-ID")
		if agentID == "" {
			agentID = "enterprise-universal-agent"
		}

		var req ChatCompletionRequest
		if !validate.Bind(w, r, &req) {
			return
		}

		// Concatenate all messages for ingress DLP scan
		var promptBuilder strings.Builder
		for _, m := range req.Messages {
			promptBuilder.WriteString(m.Role)
			promptBuilder.WriteString(": ")
			promptBuilder.WriteString(m.Content)
			promptBuilder.WriteString("\n")
		}
		promptText := promptBuilder.String()

		// Execute Ingress DLP Scan
		dlpProv := security.NewDLPProvider(func() *providers.ProviderConfig {
			if dlpStore != nil && dlpStore.Resolver != nil {
				cfg, _ := dlpStore.Resolver.Resolve(r.Context(), tenantID, providers.ServiceDLP)
				return cfg
			}
			return nil
		}())

		provIngressResult := dlpProv.Scan(r.Context(), tenantID, promptText)
		ingressScan := security.BridgeDLPResult(provIngressResult, promptText)

		if ingressScan.ShouldBlock {
			slog.Warn("UniversalAgentProxy: Ingress prompt blocked by DLP guard",
				"tenant_id", tenantID, "agent_id", agentID, "reason", ingressScan.Reasoning)

			// Record violation in database — non-fatal but MUST be logged on failure.
			// Silent drop = no audit trail for a BLOCKED DLP violation (SOC2 CC6.1 gap).
			if db != nil {
				if vErr := db.InsertRow(database.TblComplPolicyViolations, map[string]any{
					"violation_id":   idgen.GenID(),
					"tenant_id":      tenantID,
					"agent_id":       agentID,
					"policy_name":    "Ingress Enterprise DLP Exfiltration Guard",
					"violation_type": dcompliance.ViolationTypeDLPExfiltration,
					"severity":       "HIGH",
					"status":         "OPEN",
					"description":    fmt.Sprintf("Agent %s attempted prompt violating DLP: %s", agentID, ingressScan.Reasoning),
					"details":        map[string]any{"direction": "ingress", "reasoning": ingressScan.Reasoning},
					"detected_at":    time.Now().UTC().Format(time.RFC3339),
					"created_at":     time.Now().UTC().Format(time.RFC3339),
				}); vErr != nil {
					slog.Error("UniversalAgentProxy: DLP violation record insert failed — audit gap",
						"tenant_id", tenantID, "agent_id", agentID, "error", vErr)
				}
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"message": fmt.Sprintf("AOCS Policy Violation: %s", ingressScan.Reasoning),
					"type":    "dlp_exfiltration_blocked",
					"code":    "aocs_dlp_ingress_violation",
					"param":   "messages",
				},
			})
			return
		}

		// Forward to Upstream LLM or generate compliant response
		upstreamURL := os.Getenv("UPSTREAM_OPENAI_URL")
		if upstreamURL == "" {
			upstreamURL = os.Getenv("LLM_UPSTREAM_URL")
		}

		var assistantReply string
		var promptTokens int
		var completionTokens int

		if upstreamURL != "" {
			// Forward to real upstream LLM provider
			bodyBytes, _ := json.Marshal(req)
			upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upstreamURL, strings.NewReader(string(bodyBytes))) // #nosec G704 -- base URL comes from deployment configuration, not request input
			if err == nil {
				upstreamReq.Header.Set("Content-Type", "application/json")
				// Never forward the caller's AOCS JWT to a third-party provider.
				if key := os.Getenv("UPSTREAM_OPENAI_API_KEY"); key != "" {
					upstreamReq.Header.Set("Authorization", "Bearer "+key)
				}
				client := &http.Client{Timeout: 60 * time.Second}
				resp, err := client.Do(upstreamReq) // #nosec G704 -- base URL comes from deployment configuration, not request input
				if err == nil {
					defer func() { _ = resp.Body.Close() }()
					if resp.StatusCode == http.StatusOK {
						var upResp ChatCompletionResponse
						if decErr := json.NewDecoder(resp.Body).Decode(&upResp); decErr == nil && len(upResp.Choices) > 0 {
							assistantReply = upResp.Choices[0].Message.Content
							promptTokens = upResp.Usage.PromptTokens
							completionTokens = upResp.Usage.CompletionTokens
						}
					}
				}
			}
			if assistantReply == "" {
				// A configured upstream that fails must not be answered with a
				// fabricated "compliant" reply.
				slog.Error("UniversalAgentProxy: upstream LLM call failed", "tenant_id", tenantID, "agent_id", agentID)
				respond.ErrorWithCode(w, http.StatusBadGateway, "UPSTREAM_LLM_UNAVAILABLE", "upstream LLM provider did not return a completion")
				return
			}
		}

		// Placeholder response only when no upstream is configured (local/dev).
		if assistantReply == "" {
			assistantReply = "AOCS Enterprise Control Plane: Agent request processed, audited, and cryptographically verified under Patent P-03."
			promptTokens = len(promptText) / 4
			if promptTokens == 0 {
				promptTokens = 10
			}
			completionTokens = len(assistantReply) / 4
		}

		// Egress DLP Scan on assistant reply
		provEgressResult := dlpProv.Scan(r.Context(), tenantID, assistantReply)
		egressScan := security.BridgeDLPResult(provEgressResult, assistantReply)

		dlpStatus := "CLEAN"
		if egressScan.ShouldBlock {
			dlpStatus = "EGRESS_REDACTED"
			slog.Warn("UniversalAgentProxy: Egress reply blocked by DLP guard",
				"tenant_id", tenantID, "agent_id", agentID, "reason", egressScan.Reasoning)
			assistantReply = "[REDACTED: Output contained sensitive data blocked by AOCS Enterprise DLP Guard]"
		}

		// Commit to Merkle Evidence Ledger (compl_evidence) under Patent P-03.
		// The governed reply is only released once its evidence is recorded:
		// an unaudited completion would break the tamper-evidence guarantee.
		h := sha256.New()
		h.Write([]byte(promptText + "::" + assistantReply))
		contentHash := hex.EncodeToString(h.Sum(nil))

		receipt, evErr := appendEvidence(r.Context(), db, evidenceEntry{
			TenantID:     tenantID,
			AgentID:      agentID,
			ActionType:   "llm_chat_completion",
			EvidenceType: "API_RESPONSE",
			Title:        "LLM chat completion",
			ContentHash:  contentHash,
			Metadata: map[string]any{
				"model":             req.Model,
				"prompt_tokens":     promptTokens,
				"completion_tokens": completionTokens,
				"ingress_dlp_risk":  ingressScan.RiskScore,
				"egress_dlp_risk":   egressScan.RiskScore,
				"dlp_status":        dlpStatus,
			},
		})
		if evErr != nil {
			slog.Error("UniversalAgentProxy: evidence ledger write failed — reply withheld",
				"tenant_id", tenantID, "agent_id", agentID, "error", evErr)
			respond.ErrorWithCode(w, http.StatusServiceUnavailable, respond.ErrCodeUnavailable,
				"evidence ledger unavailable; request not completed")
			return
		}
		evidenceID, chainHash, prevHash := receipt.EvidenceID, receipt.ChainHash, receipt.PrevHash

		scanDuration := time.Since(start).Milliseconds()

		respObj := ChatCompletionResponse{
			ID:      "chatcmpl-" + uuid.NewString(),
			Object:  "chat.completion",
			Created: time.Now().Unix(),
			Model:   req.Model,
			Choices: []ChatChoice{
				{
					Index: 0,
					Message: ChatMessage{
						Role:    "assistant",
						Content: assistantReply,
					},
					FinishReason: "stop",
				},
			},
			Usage: ChatUsage{
				PromptTokens:     promptTokens,
				CompletionTokens: completionTokens,
				TotalTokens:      promptTokens + completionTokens,
			},
			Governance: GovernanceAuditMeta{
				EvidenceID:   evidenceID,
				ChainHash:    chainHash,
				PrevHash:     prevHash,
				DLPStatus:    dlpStatus,
				PolicyPassed: true,
				ScanDuration: scanDuration,
			},
		}

		w.Header().Set("X-AOCS-Evidence-ID", evidenceID)
		w.Header().Set("X-AOCS-Chain-Hash", chainHash)
		respond.JSON(w, http.StatusOK, respObj)
	}
}

// OTLP OpenTelemetry Span Ingestion Data Models

type OTLPKeyValue struct {
	Key   string         `json:"key"`
	Value map[string]any `json:"value"`
}

type OTLPSpan struct {
	TraceID    string         `json:"traceId"`
	SpanID     string         `json:"spanId"`
	Name       string         `json:"name"`
	Kind       int            `json:"kind"`
	StartTime  string         `json:"startTimeUnixNano"`
	EndTime    string         `json:"endTimeUnixNano"`
	Attributes []OTLPKeyValue `json:"attributes"`
}

type OTLPScopeSpan struct {
	Spans []OTLPSpan `json:"spans"`
}

type OTLPResourceSpan struct {
	ScopeSpans []OTLPScopeSpan `json:"scopeSpans"`
}

type OTLPTraceRequest struct {
	ResourceSpans []OTLPResourceSpan `json:"resourceSpans"`
}

// HandleOTelTraceIngress handles standard OpenTelemetry GenAI spans.
// POST /api/v1/compliance/otlp/v1/traces
// Receives traces from LangTrace, OpenLLMetry, Arize Phoenix, and native OTel SDKs.
// Every span is verified, Merkle-hashed, and stored in compl_evidence.
func HandleOTelTraceIngress(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok || tenantID == "" {
			respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized, "unauthorized otlp telemetry")
			return
		}

		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 5<<20)) // 5MB limit
		if err != nil {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "failed to read trace body")
			return
		}

		var traceReq OTLPTraceRequest
		if err := json.Unmarshal(bodyBytes, &traceReq); err != nil {
			slog.Warn("OTelTraceIngress: Non-standard OTLP payload received", "error", err)
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "invalid OTLP/JSON trace payload")
			return
		}

		spanCount, failed := 0, 0
		for _, rs := range traceReq.ResourceSpans {
			for _, ss := range rs.ScopeSpans {
				for _, span := range ss.Spans {
					spanCount++
					agentID := "external-otel-agent"
					actionType := span.Name
					if actionType == "" {
						actionType = "otel_genai_span"
					}

					attrMap := make(map[string]any)
					for _, kv := range span.Attributes {
						for _, val := range kv.Value {
							attrMap[kv.Key] = val
							if kv.Key == "gen_ai.system" || kv.Key == "agent.id" {
								agentID = fmt.Sprintf("%v", val)
							}
						}
					}

					h := sha256.New()
					h.Write([]byte(fmt.Sprintf("%s:%s:%s", span.TraceID, span.SpanID, span.Name)))
					contentHash := hex.EncodeToString(h.Sum(nil))
					if _, spErr := appendEvidence(r.Context(), db, evidenceEntry{
						TenantID:     tenantID,
						AgentID:      agentID,
						ActionType:   actionType,
						EvidenceType: "AUDIT_LOG",
						Title:        "OTel span: " + actionType,
						ContentHash:  contentHash,
						Metadata:     attrMap,
					}); spErr != nil {
						failed++
						slog.Error("OTelTraceIngress: span evidence insert failed",
							"span", span.Name, "tenant_id", tenantID, "error", spErr)
					}
				}
			}
		}

		slog.Info("OTelTraceIngress: Processed spans into compliance ledger",
			"tenant_id", tenantID, "span_count", spanCount, "failed", failed)

		if failed > 0 {
			// OTLP partial success: tell the exporter how many spans were
			// rejected so it can retry, instead of claiming all were audited.
			status := http.StatusOK
			if failed == spanCount {
				status = http.StatusServiceUnavailable
			}
			respond.JSON(w, status, map[string]any{
				"partialSuccess": map[string]any{
					"rejectedSpans": failed,
					"errorMessage":  "evidence ledger write failed",
				},
				"spans_audited": spanCount - failed,
			})
			return
		}
		respond.JSON(w, http.StatusOK, map[string]any{
			"partialSuccess": map[string]any{},
			"spans_audited":  spanCount,
		})
	}
}
