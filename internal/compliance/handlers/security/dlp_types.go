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
	"regexp"
	"sync"
	"time"

	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/providers"
	"github.com/ocx/shared/infra/serviceclient"
)

type DLPScanRequest struct {
	TenantID	string	`json:"tenant_id" validate:"required"`
	AgentID	string	`json:"agent_id" validate:"required"`
	Payload   string `json:"payload"`
	ToolID    string `json:"tool_id,omitempty"`
	Direction string `json:"direction"` // "egress" or "ingress"
}
type PIIDetection struct {
	PIIType    string  `json:"pii_type"`
	SHA256Hash string  `json:"sha256_hash"`
	Confidence float64 `json:"confidence"`
	Context    string  `json:"context"` // Redacted surrounding text
}
type CodeDetection struct {
	CodeType    string  `json:"code_type"`
	SnippetHash string  `json:"snippet_hash"` // SHA-256 of the matched snippet
	Language    string  `json:"language"`
	Confidence  float64 `json:"confidence"`
}
type DLPScanResult struct {
	Classification        string          `json:"classification"` // PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED
	PIIDetections         []PIIDetection  `json:"pii_detections"`
	CodeDetections        []CodeDetection `json:"code_detections"`
	TotalPIICount         int             `json:"total_pii_count"`
	TotalCodeCount        int             `json:"total_code_count"`
	RiskScore             float64         `json:"risk_score"` // 0.0–1.0
	ShouldBlock           bool            `json:"should_block"`
	Reasoning             string          `json:"reasoning"`
	HumanBrowserMonitored bool            `json:"human_browser_monitored"`
	ScanDurationMs        int64           `json:"scan_duration_ms"`
}
type DLPIntegration struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Provider    string    `json:"provider"` // "symantec", "netskope", "forcepoint", "zscaler", etc.
	WebhookURL  string    `json:"webhook_url"`
	APIKey      string    `json:"api_key,omitempty"` // Never returned in GET responses
	TenantID    string    `json:"tenant_id"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	LastEventAt time.Time `json:"last_event_at,omitempty"`
	EventCount  int64     `json:"event_count"`
}
type MonitorPIDRequest struct {
	TenantID	string	`json:"tenant_id" validate:"required"`
	PID      int    `json:"pid"`
	Label    string `json:"label"` // "agt", "browser", "service"
}
type MarketplaceDLPConnector struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Provider    string   `json:"provider"`
	Description string   `json:"description"`
	Tab         string   `json:"tab"`      // "security_integrations" or "agent_connectors"
	Category    string   `json:"category"` // enterprise_dlp, casb, siem, soar, iam, grc, notifications, ticketing, vault, mcp, sdk, proxy, kernel
	Icon        string   `json:"icon"`
	SetupURL    string   `json:"setup_url"`
	Features    []string `json:"features"`
	Pricing     string   `json:"pricing"` // "free", "included", "bring_your_own_license"
	Certified   bool     `json:"certified"`
	DocsURL     string   `json:"docs_url"`
}
type DLPStore struct {
	mu            sync.RWMutex
	db            database.DB
	coreClient      *serviceclient.Client  // ocx-core-svc internal API client
	monitoredPIDs map[int]string          // PID -> label (in-memory cache, synced to DB)
	Resolver      providers.Resolver      // pluggable provider resolver (nil = always builtin)
}

var piiPatterns = []struct {
	Type       string
	Regex      *regexp.Regexp
	Confidence float64
}{
	{"email", regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`), 0.95},
	{"phone_us", regexp.MustCompile(`(?:\+1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}`), 0.85},
	{"ssn", regexp.MustCompile(`\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b`), 0.90},
	{"credit_card", regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`), 0.92},
	{"ip_address", regexp.MustCompile(`\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`), 0.75},
	{"iban", regexp.MustCompile(`\b[A-Z]{2}\d{2}\s?[\dA-Z]{4}\s?[\dA-Z]{4}\s?[\dA-Z]{4}`), 0.88},
}
var codePatterns = []struct {
	Type       string
	Regex      *regexp.Regexp
	Language   string
	Confidence float64
}{
	{"aws_access_key", regexp.MustCompile(`(?:AKIA|ASIA)[A-Z0-9]{16}`), "aws", 0.98},
	{"openai_key", regexp.MustCompile(`sk-[A-Za-z0-9]{48,}`), "openai", 0.98},
	{"github_token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,}`), "github", 0.98},
	{"private_key", regexp.MustCompile(`-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----`), "pem", 0.99},
	{"api_key", regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|token|secret|password)\s*[:=]\s*['"]?[A-Za-z0-9_\-]{20,}['"]?`), "generic", 0.85},
	{"sql_query", regexp.MustCompile(`(?i)(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s+(?:INTO|FROM|TABLE|DATABASE|INDEX)\s+[\w.'\"` + "`" + `]+`), "sql", 0.80},
	{"connection_string", regexp.MustCompile(`(?:postgres|mysql|mongodb|redis|amqp)://[^\s]+:[^\s]+@[^\s]+`), "connection", 0.95},
	{"jwt_token", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), "jwt", 0.95},
}
