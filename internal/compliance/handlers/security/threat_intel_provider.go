// Package security — pluggable Threat Intelligence provider layer.
//
// ThreatIntelProvider augments the TriFactorGate with real-time threat feeds.
// Unlike DLP and Content Safety, Threat Intel ADDS to AOCS rather than replaces:
// the builtin identity checks still run, and the vendor feed adds additional signals.
//
// New providers: implement ThreatIntelProvider + add a case to NewThreatIntelProvider.
package security

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/ocx/shared/infra/providers"
)

// ThreatIntelResult is the normalised threat intel evaluation result.
type ThreatIntelResult struct {
	Threat        bool              `json:"threat"`       // true = active threat detected
	ThreatLevel   string            `json:"threat_level"` // "none" | "low" | "medium" | "high" | "critical"
	Indicators    []ThreatIndicator `json:"indicators,omitempty"`
	ProviderName  string            `json:"provider_name"`
	ProviderError string            `json:"provider_error,omitempty"` // non-empty on provider parse/request failure
}

// ThreatIndicator is a single threat signal from the feed.
type ThreatIndicator struct {
	Type        string `json:"type"`        // "ip" | "domain" | "hash" | "cve" | "actor"
	Value       string `json:"value"`       // the IOC value
	Confidence  string `json:"confidence"`  // "low" | "medium" | "high"
	Description string `json:"description,omitempty"`
}

// ThreatIntelProvider is the interface every threat intelligence backend must satisfy.
type ThreatIntelProvider interface {
	CheckIndicators(ctx context.Context, tenantID string, indicators []string) *ThreatIntelResult
}

// ── Provider factory ─────────────────────────────────────────────────────────

// NewThreatIntelProvider returns the correct ThreatIntelProvider for the resolved config.
// Returns nil when no provider is configured — threat intel is optional.
func NewThreatIntelProvider(cfg *providers.ProviderConfig) ThreatIntelProvider {
	if cfg == nil || cfg.IsBuiltin {
		return nil // builtin has no threat feed — optional capability
	}
	switch providers.ProviderName(cfg.ConnectorType) {
	case providers.ProviderCrowdStrikeIntel:
		return &CrowdStrikeThreatIntelProvider{
			APIURL: getCredOrDefault(cfg, "api_url", "https://api.crowdstrike.com"),
		}
	default:
		slog.Warn("unknown threat intel provider — threat intel disabled", "connector_type", cfg.ConnectorType)
		return nil
	}
}

// ── CrowdStrike Falcon Threat Intelligence ────────────────────────────────────

// CrowdStrikeThreatIntelProvider queries the CrowdStrike Falcon Intelligence Feed.
// POST /intel/combined/indicators/v1 — match IOCs against known threats.
type CrowdStrikeThreatIntelProvider struct {
	APIURL      string
	accessToken string `json:"-"` // OAuth2 client credentials — injected from vault
}

func (p *CrowdStrikeThreatIntelProvider) CheckIndicators(ctx context.Context, tenantID string, indicators []string) *ThreatIntelResult {
	if len(indicators) == 0 || p.accessToken == "" {
		return &ThreatIntelResult{ProviderName: "crowdstrike_threat_intel"}
	}

	reqBody, _ := json.Marshal(map[string]any{
		"filter":  "type:'ip'",
		"q":       indicators[0], // primary indicator
		"limit":   10,
		"sources": []string{"us", "eu"},
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.APIURL+"/intel/combined/indicators/v1", bytes.NewReader(reqBody))
	if err != nil {
		slog.Error("crowdstrike ti: build request failed", "err", err)
		return &ThreatIntelResult{ProviderName: "crowdstrike_threat_intel"}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.accessToken)

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("crowdstrike ti: request failed — non-blocking", "err", err)
		return &ThreatIntelResult{ProviderName: "crowdstrike_threat_intel"}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))

	var csResp struct {
		Resources []struct {
			Type       string   `json:"type"`
			Indicator  string   `json:"indicator"`
			Confidence int      `json:"confidence"` // 0–100
			Severity   string   `json:"severity"`
			Labels     []struct { Name string `json:"name"` } `json:"labels"`
		} `json:"resources"`
	}
	// Log prominently so ops can detect CrowdStrike API drift.
	if err := json.Unmarshal(body, &csResp); err != nil {
		slog.Error("crowdstrike threat intel: response JSON parse failed",
			"err", err, "body_len", len(body))
		return &ThreatIntelResult{
			ProviderName:  "crowdstrike_threat_intel",
			ThreatLevel:   "unknown",
			ProviderError: fmt.Sprintf("response parse error: %v", err),
		}
	}

	result := &ThreatIntelResult{ProviderName: "crowdstrike_threat_intel", ThreatLevel: "none"}
	for _, r := range csResp.Resources {
		if r.Confidence > 40 {
			result.Threat = true
			conf := "low"
			if r.Confidence > 70 { conf = "medium" }
			if r.Confidence > 90 { conf = "high" }
			result.Indicators = append(result.Indicators, ThreatIndicator{
				Type:       r.Type,
				Value:      r.Indicator,
				Confidence: conf,
			})
			if r.Severity != "" {
				result.ThreatLevel = r.Severity
			}
		}
	}
	if result.Threat {
		slog.Warn("crowdstrike ti: threat detected",
			"tenant", tenantID, "indicators", len(result.Indicators), "level", result.ThreatLevel)
	}
	return result
}
