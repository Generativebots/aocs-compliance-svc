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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/serviceclient"
)

// NewDLPStore creates a DLPStore backed by the given database.
// coreClient is used for ocx-core-svc-crossing calls (enforcement actions, DLP integrations).
func NewDLPStore(db database.DB, coreClient *serviceclient.Client) *DLPStore {
	s := &DLPStore{
		db:            db,
		coreClient:      coreClient,
		monitoredPIDs: make(map[int]string),
	}
	// Hydrate in-memory PID map from DB on startup so monitored PIDs
	// survive pod restarts. Non-fatal: errors are logged and ignored.
	s.LoadFromDB()
	return s
}

// LoadFromDB repopulates the monitoredPIDs map from ocx-core-svc enforcement actions
// where action_type = 'dlp_pid_monitor'. Called once at startup.
func (s *DLPStore) LoadFromDB() {
	if s.db == nil {
		return
	}
	var rows []struct {
		Metadata []byte `json:"metadata"`
	}
	// Fetch via ocx-core-svc internal API (boundary enforcement: no direct core_enforcement_actions access)
	if s.coreClient != nil {
		actions, err := s.coreClient.ListEnforcementActionsByType(context.Background(), "dlp_pid_monitor")
		if err != nil {
			// Non-fatal: PID map starts empty; registered PIDs will be added on next POST
			return
		}
		for _, a := range actions {
			rows = append(rows, struct{ Metadata []byte `json:"metadata"` }{Metadata: a.Metadata})
		}
	} else {
		// Fallback: direct DB access only when coreClient is unavailable (e.g. test mode)
		// nolint:tenant_filter — startup hydration: load ALL tenant PID monitors
		if err := s.db.QueryRowsCtx(context.Background(), database.TblEnforcementActions, "metadata", "action_type", "dlp_pid_monitor", &rows); err != nil {
			return
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	loaded := 0
	for _, r := range rows {
		var meta struct {
			PID   int    `json:"pid"`
			Label string `json:"label"`
		}
		if err := json.Unmarshal(r.Metadata, &meta); err != nil {
			continue
		}
		if meta.PID > 0 {
			s.monitoredPIDs[meta.PID] = meta.Label
			loaded++
		}
	}
	if loaded > 0 {
		slog.Info("hydrated monitored PIDs from DB", "count", loaded)
	}
}

// sha256Hash returns the SHA-256 hex digest of s.
func sha256Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
func redactContext(text string, start, end int) string {
	window := 30
	ctxStart := start - window
	if ctxStart < 0 {
		ctxStart = 0
	}
	ctxEnd := end + window
	if ctxEnd > len(text) {
		ctxEnd = len(text)
	}
	return text[ctxStart:start] + "[REDACTED]" + text[end:ctxEnd]
}
func scanPayload(payload string) *DLPScanResult {
	start := time.Now().UTC()

	var piiDetections []PIIDetection
	var codeDetections []CodeDetection
	seenHashes := make(map[string]bool)

	// PII scan
	for _, p := range piiPatterns {
		matches := p.Regex.FindAllStringIndex(payload, -1)
		for _, loc := range matches {
			value := payload[loc[0]:loc[1]]
			hash := sha256Hash(value)
			if seenHashes[hash] {
				continue
			}
			seenHashes[hash] = true
			piiDetections = append(piiDetections, PIIDetection{
				PIIType:    p.Type,
				SHA256Hash: hash,
				Confidence: p.Confidence,
				Context:    redactContext(payload, loc[0], loc[1]),
			})
		}
	}

	// Code/secret scan
	for _, c := range codePatterns {
		matches := c.Regex.FindAllStringIndex(payload, -1)
		for _, loc := range matches {
			snippet := payload[loc[0]:loc[1]]
			hash := sha256Hash(snippet)
			if seenHashes[hash] {
				continue
			}
			seenHashes[hash] = true
			codeDetections = append(codeDetections, CodeDetection{
				CodeType:    c.Type,
				SnippetHash: hash,
				Language:    c.Language,
				Confidence:  c.Confidence,
			})
		}
	}

	// Classification
	classification := classifyDetections(piiDetections, codeDetections)

	// Risk score
	riskScore := calculateRisk(piiDetections, codeDetections, classification)

	// Block decision
	shouldBlock := classification == "RESTRICTED"

	// Reasoning
	reasoning := buildReasoning(piiDetections, codeDetections, classification)

	duration := time.Since(start).Milliseconds()

	return &DLPScanResult{
		Classification:        classification,
		PIIDetections:         piiDetections,
		CodeDetections:        codeDetections,
		TotalPIICount:         len(piiDetections),
		TotalCodeCount:        len(codeDetections),
		RiskScore:             riskScore,
		ShouldBlock:           shouldBlock,
		Reasoning:             reasoning,
		HumanBrowserMonitored: false,
		ScanDurationMs:        duration,
	}
}
func classifyDetections(pii []PIIDetection, code []CodeDetection) string {
	restricted := map[string]bool{"ssn": true, "credit_card": true, "iban": true}
	restrictedCode := map[string]bool{"private_key": true, "aws_access_key": true, "connection_string": true}
	confidential := map[string]bool{"email": true, "phone_us": true}
	confidentialCode := map[string]bool{"api_key": true, "openai_key": true, "github_token": true, "jwt_token": true}

	for _, m := range pii {
		if restricted[m.PIIType] {
			return "RESTRICTED"
		}
	}
	for _, m := range code {
		if restrictedCode[m.CodeType] {
			return "RESTRICTED"
		}
	}
	for _, m := range pii {
		if confidential[m.PIIType] {
			return "CONFIDENTIAL"
		}
	}
	for _, m := range code {
		if confidentialCode[m.CodeType] {
			return "CONFIDENTIAL"
		}
	}
	for _, m := range code {
		if m.CodeType == "sql_query" || m.CodeType == "source_code" {
			return "INTERNAL"
		}
	}
	return "PUBLIC"
}
func calculateRisk(pii []PIIDetection, code []CodeDetection, classification string) float64 {
	base := map[string]float64{
		"PUBLIC": 0.0, "INTERNAL": 0.3, "CONFIDENTIAL": 0.6, "RESTRICTED": 0.9,
	}
	score := base[classification]
	for _, m := range pii {
		score = min64(1.0, score+0.05*m.Confidence)
	}
	for _, m := range code {
		score = min64(1.0, score+0.03*m.Confidence)
	}
	return score
}
func min64(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
func buildReasoning(pii []PIIDetection, code []CodeDetection, classification string) string {
	var parts []string
	parts = append(parts, "Classification: "+classification)

	if len(pii) > 0 {
		types := make(map[string]bool)
		for _, m := range pii {
			types[m.PIIType] = true
		}
		var typeList []string
		for t := range types {
			typeList = append(typeList, t)
		}
		parts = append(parts, fmt.Sprintf("PII: %s (%d total, all SHA-256 hashed)", strings.Join(typeList, ", "), len(pii)))
	}

	if len(code) > 0 {
		types := make(map[string]bool)
		for _, m := range code {
			types[m.CodeType] = true
		}
		var typeList []string
		for t := range types {
			typeList = append(typeList, t)
		}
		parts = append(parts, fmt.Sprintf("Code/Secrets: %s (%d total)", strings.Join(typeList, ", "), len(code)))
	}

	return strings.Join(parts, " | ")
}
func getDLPMarketplaceCatalog() []MarketplaceDLPConnector {
	return []MarketplaceDLPConnector{
		// TAB 1: SECURITY INTEGRATIONS

		// ── Enterprise DLP ────────────────────────────────────────────
		{ID: "dlp-symantec", Name: "Symantec DLP", Provider: "symantec", Tab: "security_integrations", Category: "enterprise_dlp", Icon: "🔒",
			Description: "Enterprise DLP with content-aware detection, policy enforcement, and incident management.",
			SetupURL:    "/api/v1/dlp/integrations", Pricing: "bring_your_own_license", Certified: true, DocsURL: "https://docs.ocx.ai/integrations/symantec-dlp",
			Features: []string{"content_inspection", "policy_enforcement", "incident_management", "ocr_detection", "fingerprinting"}},
		{ID: "dlp-forcepoint", Name: "Forcepoint DLP", Provider: "forcepoint", Tab: "security_integrations", Category: "enterprise_dlp", Icon: "🛡️",
			Description: "Risk-adaptive DLP that adjusts protection based on user behavior. Covers endpoints, network, cloud, and email.",
			SetupURL:    "/api/v1/dlp/integrations", Pricing: "bring_your_own_license", Certified: true, DocsURL: "https://docs.ocx.ai/integrations/forcepoint-dlp",
			Features: []string{"risk_adaptive", "endpoint_dlp", "email_dlp", "network_dlp", "behavioral_analytics"}},
		{ID: "dlp-microsoft-purview", Name: "Microsoft Purview DLP", Provider: "microsoft", Tab: "security_integrations", Category: "enterprise_dlp", Icon: "🪟",
			Description: "Native DLP for Microsoft 365, Teams, SharePoint, and Exchange. Integrated with Azure Information Protection.",
			SetupURL:    "/api/v1/dlp/integrations", Pricing: "bring_your_own_license", Certified: true, DocsURL: "https://docs.ocx.ai/integrations/purview-dlp",
			Features: []string{"m365_native", "teams_dlp", "sharepoint_dlp", "aip_integration", "sensitivity_labels"}},
		{ID: "dlp-google-cloud", Name: "Google Cloud DLP", Provider: "google", Tab: "security_integrations", Category: "enterprise_dlp", Icon: "🔍",
			Description: "Serverless DLP API for discovering, classifying, and redacting sensitive data. 150+ built-in infoTypes.",
			SetupURL:    "/api/v1/dlp/integrations", Pricing: "bring_your_own_license", Certified: true, DocsURL: "https://docs.ocx.ai/integrations/google-cloud-dlp",
			Features: []string{"150_infotypes", "auto_redaction", "de_identification", "risk_analysis", "serverless"}},
		{ID: "dlp-trellix", Name: "Trellix DLP", Provider: "trellix", Tab: "security_integrations", Category: "enterprise_dlp", Icon: "🔥",
			Description: "Formerly McAfee DLP. Unified data protection across endpoint, network, and cloud with advanced classification.",
			SetupURL:    "/api/v1/dlp/integrations", Pricing: "bring_your_own_license", Certified: true, DocsURL: "https://docs.ocx.ai/integrations/trellix-dlp",
			Features: []string{"endpoint_dlp", "network_dlp", "cloud_dlp", "advanced_classification", "unified_policies"}},

		// ── CASB ───────────────────────────────────────────────────────
		{ID: "dlp-netskope", Name: "Netskope DLP", Provider: "netskope", Tab: "security_integrations", Category: "casb", Icon: "☁️",
			Description: "Cloud-native DLP with real-time inspection of SaaS, IaaS, and web traffic. ML-powered data classification.",
			SetupURL:    "/api/v1/dlp/integrations", Pricing: "bring_your_own_license", Certified: true, DocsURL: "https://docs.ocx.ai/integrations/netskope-dlp",
			Features: []string{"cloud_dlp", "saas_monitoring", "ml_classification", "real_time_alerts", "api_protection"}},
		{ID: "dlp-zscaler", Name: "Zscaler Data Protection", Provider: "zscaler", Tab: "security_integrations", Category: "casb", Icon: "🌐",
			Description: "Inline DLP via Zero Trust Exchange. Inspects all traffic including TLS without agt.",
			SetupURL:    "/api/v1/dlp/integrations", Pricing: "bring_your_own_license", Certified: true, DocsURL: "https://docs.ocx.ai/integrations/zscaler-data",
			Features: []string{"inline_inspection", "zero_trust", "edm", "idm", "tls_inspection"}},

		// ── SIEM ───────────────────────────────────────────────────────
		{ID: "siem-splunk", Name: "Splunk SIEM", Provider: "splunk", Tab: "security_integrations", Category: "siem", Icon: "📊",
			Description: "Forward AOCS agt gov events to Splunk for correlation, alerting, and compliance reporting.",
			SetupURL:    "/api/v1/dlp/integrations", Pricing: "bring_your_own_license", Certified: true, DocsURL: "https://docs.ocx.ai/integrations/splunk-siem",
			Features: []string{"event_forwarding", "correlation", "dashboards", "compliance_reports", "alert_rules"}},
		{ID: "siem-datadog", Name: "Datadog Security", Provider: "datadog", Tab: "security_integrations", Category: "siem", Icon: "🐕",
			Description: "Stream AOCS events to Datadog for unified agt observability, threat detection, and compliance dashboards.",
			SetupURL:    "/api/v1/dlp/integrations", Pricing: "bring_your_own_license", Certified: true, DocsURL: "https://docs.ocx.ai/integrations/datadog-security",
			Features: []string{"event_streaming", "threat_detection", "agent_observability", "log_analytics", "custom_dashboards"}},
		{ID: "siem-sentinel", Name: "Microsoft Sentinel", Provider: "microsoft", Tab: "security_integrations", Category: "siem", Icon: "🔷",
			Description: "Cloud-native SIEM/SOAR. Forward AOCS events via Azure Event Hub for AI-powered threat detection.",
			SetupURL:    "/api/v1/dlp/integrations", Pricing: "bring_your_own_license", Certified: true, DocsURL: "https://docs.ocx.ai/integrations/sentinel",
			Features: []string{"azure_native", "ai_threat_detection", "kusto_queries", "automated_playbooks", "multi_tenant"}},
		{ID: "siem-elastic", Name: "Elastic Security", Provider: "elastic", Tab: "security_integrations", Category: "siem", Icon: "🔎",
			Description: "Open-platform SIEM with AOCS event ingestion, anomaly detection, and threat hunting.",
			SetupURL:    "/api/v1/dlp/integrations", Pricing: "bring_your_own_license", Certified: true, DocsURL: "https://docs.ocx.ai/integrations/elastic-security",
			Features: []string{"event_ingestion", "anomaly_detection", "threat_hunting", "kibana_dashboards", "ml_analytics"}},

		// ── SOAR ───────────────────────────────────────────────────────
		{ID: "soar-palo-xsoar", Name: "Palo Alto XSOAR", Provider: "paloalto", Tab: "security_integrations", Category: "soar", Icon: "⚡",
			Description: "SOAR integration for automated incident response on AOCS events. Auto-create tickets, block agt, notify teams.",
			SetupURL:    "/api/v1/dlp/integrations", Pricing: "bring_your_own_license", Certified: true, DocsURL: "https://docs.ocx.ai/integrations/xsoar",
			Features: []string{"automated_response", "playbooks", "ticket_creation", "agent_blocking", "slack_notify"}},
		{ID: "soar-tines", Name: "Tines SOAR", Provider: "tines", Tab: "security_integrations", Category: "soar", Icon: "🔄",
			Description: "No-code SOAR with visual workflow builder. Automate BLOCK/ESC responses with drag-and-drop playbooks.",
			SetupURL:    "/api/v1/dlp/integrations", Pricing: "bring_your_own_license", Certified: true, DocsURL: "https://docs.ocx.ai/integrations/tines",
			Features: []string{"no_code", "visual_workflows", "api_actions", "conditional_logic", "webhook_triggers"}},

		// ── IAM / Identity ────────────────────────────────────────────
		{ID: "iam-okta", Name: "Okta Identity", Provider: "okta", Tab: "security_integrations", Category: "iam", Icon: "🔑",
			Description: "Verify agt operator identity via Okta SSO/MFA. Map agt entitlements to Okta groups and SCIM attributes.",
			SetupURL:    "/api/v1/dlp/integrations", Pricing: "bring_your_own_license", Certified: true, DocsURL: "https://docs.ocx.ai/integrations/okta",
			Features: []string{"sso_saml", "mfa_enforcement", "scim_provisioning", "group_mapping", "session_management"}},
		{ID: "iam-entra-id", Name: "Microsoft Entra ID", Provider: "microsoft", Tab: "security_integrations", Category: "iam", Icon: "🆔",
			Description: "Azure AD integration for agt identity, conditional access policies, and tenant isolation.",
			SetupURL:    "/api/v1/dlp/integrations", Pricing: "bring_your_own_license", Certified: true, DocsURL: "https://docs.ocx.ai/integrations/entra-id",
			Features: []string{"azure_ad", "conditional_access", "pim", "app_registrations", "tenant_isolation"}},

		// ── GRC ───────────────────────────────────────────────────────
		{ID: "grc-servicenow", Name: "ServiceNow GRC", Provider: "servicenow", Tab: "security_integrations", Category: "grc", Icon: "📋",
			Description: "Map AOCS policies to regulatory frameworks (SOX, SOC2, HIPAA). Auto-generate compliance evlt.",
			SetupURL:    "/api/v1/dlp/integrations", Pricing: "bring_your_own_license", Certified: true, DocsURL: "https://docs.ocx.ai/integrations/servicenow-grc",
			Features: []string{"policy_mapping", "control_testing", "risk_register", "compliance_evidence", "framework_support"}},
		{ID: "grc-onetrust", Name: "OneTrust", Provider: "onetrust", Tab: "security_integrations", Category: "grc", Icon: "🏛️",
			Description: "Privacy and data gov integration. Map PII detections from AOCS DLP to OneTrust data maps.",
			SetupURL:    "/api/v1/dlp/integrations", Pricing: "bring_your_own_license", Certified: true, DocsURL: "https://docs.ocx.ai/integrations/onetrust",
			Features: []string{"privacy_management", "dsar_automation", "data_mapping", "consent_tracking", "vendor_risk"}},

		// ── Notifications & Ticketing ──────────────────────────────────
		{ID: "notify-slack", Name: "Slack", Provider: "slack", Tab: "security_integrations", Category: "notifications", Icon: "💬",
			Description: "Real-time AOCS alerts to Slack channels. BLOCK/ESC events, HITL approval requests, daily digests.",
			SetupURL:    "/api/v1/dlp/integrations", Pricing: "free", Certified: true, DocsURL: "https://docs.ocx.ai/integrations/slack",
			Features: []string{"real_time_alerts", "interactive_approvals", "channel_routing", "daily_digests", "thread_replies"}},
		{ID: "notify-teams", Name: "Microsoft Teams", Provider: "microsoft", Tab: "security_integrations", Category: "notifications", Icon: "👥",
			Description: "AOCS event notifications and HITL approval workflows via Teams adaptive cards.",
			SetupURL:    "/api/v1/dlp/integrations", Pricing: "free", Certified: true, DocsURL: "https://docs.ocx.ai/integrations/teams",
			Features: []string{"adaptive_cards", "approval_workflows", "severity_routing", "teams_channels", "bot_commands"}},
		{ID: "notify-pagerduty", Name: "PagerDuty", Provider: "pagerduty", Tab: "security_integrations", Category: "notifications", Icon: "🚨",
			Description: "Escalate critical AOCS events (BLOCK, high-risk ESC) to PagerDuty on-call incident management.",
			SetupURL:    "/api/v1/dlp/integrations", Pricing: "bring_your_own_license", Certified: true, DocsURL: "https://docs.ocx.ai/integrations/pagerduty",
			Features: []string{"incident_creation", "severity_mapping", "escalation_policies", "on_call_routing", "auto_resolve"}},
		{ID: "ticket-jira", Name: "Jira Service Management", Provider: "atlassian", Tab: "security_integrations", Category: "ticketing", Icon: "🎫",
			Description: "Auto-create Jira tickets for HITL review requests, ESC approvals, and policy violations.",
			SetupURL:    "/api/v1/dlp/integrations", Pricing: "bring_your_own_license", Certified: true, DocsURL: "https://docs.ocx.ai/integrations/jira",
			Features: []string{"ticket_creation", "custom_fields", "workflow_triggers", "sla_tracking", "approval_chains"}},

		// ── Vault / Secrets ────────────────────────────────────────────
		{ID: "vault-hashicorp", Name: "HashiCorp Vault", Provider: "hashicorp", Tab: "security_integrations", Category: "vault", Icon: "🔐",
			Description: "Manage agt credentials, eBPF certificates, and tenant API keys via HashiCorp Vault.",
			SetupURL:    "/api/v1/dlp/integrations", Pricing: "bring_your_own_license", Certified: true, DocsURL: "https://docs.ocx.ai/integrations/vault",
			Features: []string{"dynamic_secrets", "auto_rotation", "pki_certificates", "transit_encryption", "audit_logging"}},

		// TAB 2: AGT CONNECTORS

		// ── MCP (Model Context Protocol) ──────────────────────────────
		{ID: "agt-mcp-server", Name: "AOCS MCP Server", Provider: "ocx", Tab: "agent_connectors", Category: "mcp", Icon: "🔌",
			Description: "Run AOCS as an MCP tool-server. Any MCP-compatible agt routes tool-calls through AOCS for gov.",
			SetupURL:    "/api/v1/tenant/integrations", Pricing: "included", Certified: true, DocsURL: "https://docs.ocx.ai/connectors/mcp-server",
			Features: []string{"mcp_protocol", "tool_interception", "zero_config", "auto_policy_enforcement", "real_time_audit"}},

		// ── Framework SDKs ──────────────────────────────────────────
		{ID: "agt-langchain", Name: "LangChain Callback", Provider: "ocx", Tab: "agent_connectors", Category: "sdk", Icon: "🦜",
			Description: "Drop-in LangChain callback handler. 3 lines of code to route all tool-calls through AOCS gov.",
			SetupURL:    "/api/v1/tenant/integrations", Pricing: "included", Certified: true, DocsURL: "https://docs.ocx.ai/connectors/langchain",
			Features: []string{"callback_handler", "chain_tracing", "tool_interception", "streaming_support", "async_compatible"}},
		{ID: "agt-crewai", Name: "CrewAI Middleware", Provider: "ocx", Tab: "agent_connectors", Category: "sdk", Icon: "👨‍✈️",
			Description: "Middleware plugin for CrewAI multi-agt pipelines. Intercept inter-agt communication and tool execution.",
			SetupURL:    "/api/v1/tenant/integrations", Pricing: "included", Certified: true, DocsURL: "https://docs.ocx.ai/connectors/crewai",
			Features: []string{"crew_middleware", "inter_agent_governance", "task_interception", "delegation_policies", "crew_audit_trail"}},
		{ID: "agt-autogen", Name: "AutoGen Guard", Provider: "ocx", Tab: "agent_connectors", Category: "sdk", Icon: "🤖",
			Description: "Microsoft AutoGen integration for multi-agt conversation gov and tool-use monitoring.",
			SetupURL:    "/api/v1/tenant/integrations", Pricing: "included", Certified: true, DocsURL: "https://docs.ocx.ai/connectors/autogen",
			Features: []string{"conversation_guard", "agent_negotiation_audit", "tool_use_policies", "group_chat_monitoring", "human_proxy_support"}},
		{ID: "agt-python-sdk", Name: "AOCS Python SDK", Provider: "ocx", Tab: "agent_connectors", Category: "sdk", Icon: "🐍",
			Description: "pip install aocs-agt — universal Python SDK. Wrap tool-calls with @aocs.governed decorator.",
			SetupURL:    "/api/v1/tenant/integrations", Pricing: "included", Certified: true, DocsURL: "https://docs.ocx.ai/connectors/python-sdk",
			Features: []string{"decorator_based", "any_framework", "async_support", "batch_operations", "local_cache"}},
		{ID: "agt-go-sdk", Name: "AOCS Go SDK", Provider: "ocx", Tab: "agent_connectors", Category: "sdk", Icon: "🔷",
			Description: "Go package for custom Go agt. gRPC-native with zero-copy payload forwarding.",
			SetupURL:    "/api/v1/tenant/integrations", Pricing: "included", Certified: true, DocsURL: "https://docs.ocx.ai/connectors/go-sdk",
			Features: []string{"grpc_native", "zero_copy", "context_propagation", "circuit_breaker", "connection_pool"}},

		// ── Proxies ────────────────────────────────────────────────────
		{ID: "agt-openai-proxy", Name: "OpenAI Functions Proxy", Provider: "ocx", Tab: "agent_connectors", Category: "proxy", Icon: "🔀",
			Description: "Transparent proxy for OpenAI function-calling agt. Point base_url to AOCS — zero code changes.",
			SetupURL:    "/api/v1/tenant/integrations", Pricing: "included", Certified: true, DocsURL: "https://docs.ocx.ai/connectors/openai-proxy",
			Features: []string{"transparent_proxy", "function_call_interception", "zero_code_change", "response_auditing", "streaming_passthrough"}},
		{ID: "agt-rest-proxy", Name: "REST Gateway Proxy", Provider: "ocx", Tab: "agent_connectors", Category: "proxy", Icon: "🌍",
			Description: "Language-agnostic REST proxy. Any agt in any language can route HTTP tool-calls through AOCS.",
			SetupURL:    "/api/v1/tenant/integrations", Pricing: "included", Certified: true, DocsURL: "https://docs.ocx.ai/connectors/rest-proxy",
			Features: []string{"language_agnostic", "http_proxy", "header_based_auth", "request_response_audit", "rate_limiting"}},

		// ── Kernel-Level ────────────────────────────────────────────────
		{ID: "agt-ebpf-attach", Name: "eBPF Auto-Attach", Provider: "ocx", Tab: "agent_connectors", Category: "kernel", Icon: "🐝",
			Description: "Zero-code agt gov. Attach eBPF probes to any running process — no SDK, no proxy, no code changes.",
			SetupURL:    "/api/v1/dlp/monitor-pid", Pricing: "included", Certified: true, DocsURL: "https://docs.ocx.ai/connectors/ebpf",
			Features: []string{"zero_code", "kernel_level", "tls_interception", "process_auto_discovery", "hot_attach"}},
	}
}
