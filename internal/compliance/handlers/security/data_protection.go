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
		coreClient:    coreClient,
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
	// Metadata is JSONB (an object on the wire): json.RawMessage, not []byte,
	// which would expect a base64 string and fail on every row.
	var rows []struct {
		Metadata json.RawMessage `json:"metadata"`
	}
	// D3: hydrate per live tenant — every read carries tenant_id.
	// Preferred: ocx-core-svc internal API (boundary enforcement); fallback:
	// direct DB read only when coreClient is unavailable (e.g. test mode).
	ctx := context.Background()
	if err := database.ForEachTenant(ctx, s.db, "dlp_pid_hydration", func(ctx context.Context, tenantID string) error {
		if s.coreClient != nil {
			actions, err := s.coreClient.ListEnforcementActionsByType(ctx, tenantID, "dlp_pid_monitor")
			if err != nil {
				return err
			}
			for _, a := range actions {
				rows = append(rows, struct {
					Metadata json.RawMessage `json:"metadata"`
				}{Metadata: a.Metadata})
			}
			return nil
		}
		var tRows []struct {
			Metadata json.RawMessage `json:"metadata"`
		}
		if err := s.db.QueryRowsCompoundCtx(ctx, database.TblCoreEnforcementActions, "metadata",
			"tenant_id", tenantID, "action_type", "dlp_pid_monitor", &tRows); err != nil {
			return err
		}
		rows = append(rows, tRows...)
		return nil
	}); err != nil {
		// Non-fatal: PID map starts partially/empty; registered PIDs will be added on next POST
		slog.Warn("DLP PID hydration incomplete — monitored PID map may be partial", "error", err)
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
