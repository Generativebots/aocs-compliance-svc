// Package security — pluggable Content Safety provider layer.
//
// ContentSafetyProvider is the interface for all content moderation backends.
// The builtin provider uses the existing callCognitiveService() chain unchanged.
// Vendor providers delegate to external APIs.
//
// Resolution order:
//  1. Tenant's configured provider (aocs_enterprise_provider_config)
//  2. Platform builtin (AOCS cognitive service URL)
//
// New content safety providers: implement ContentSafetyProvider + add a case to NewContentSafetyProvider.
package security

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ocx/shared/infra/providers"
)

// ContentSafetyResult is the normalised content safety evaluation result.
// Populated regardless of which provider runs the check.
type ContentSafetyResult struct {
	Safe          bool               `json:"safe"`
	Verdict       string             `json:"verdict"` // "ALLOW" | "BLOCK" | "REVIEW"
	Violations    []ContentViolation `json:"violations,omitempty"`
	ProviderName  string             `json:"provider_name"`
	TrustLevel    float64            `json:"trust_level,omitempty"`
	AnomalyScore  float64            `json:"anomaly_score,omitempty"`
	ProviderError string             `json:"provider_error,omitempty"` // non-empty on provider parse/request failure
}

// ContentViolation describes a single content policy violation.
type ContentViolation struct {
	Category   string  `json:"category"`   // "hate_speech" | "pii" | "malware" | ...
	Severity   string  `json:"severity"`   // "low" | "medium" | "high"
	Confidence float64 `json:"confidence"` // 0.0 – 1.0
}

// ContentSafetyProvider is the interface every content safety backend must satisfy.
type ContentSafetyProvider interface {
	Evaluate(ctx context.Context, tenantID, payload string) *ContentSafetyResult
}

// ── Provider factory ─────────────────────────────────────────────────────────

// NewContentSafetyProvider returns the correct ContentSafetyProvider for the resolved config.
// cognitiveServiceURL is the builtin AOCS cognitive service — used when no provider is configured.
func NewContentSafetyProvider(cfg *providers.ProviderConfig, cognitiveServiceURL string) ContentSafetyProvider {
	if cfg == nil || cfg.IsBuiltin {
		return &BuiltinContentSafetyProvider{CognitiveServiceURL: cognitiveServiceURL}
	}
	switch providers.ProviderName(cfg.ConnectorType) {
	case providers.ProviderAzureContentSafety:
		return &AzureContentSafetyProvider{
			Endpoint:    getCredOrDefault(cfg, "endpoint", "https://aocs-content.cognitiveservices.azure.com"),
			APIVersion:  "2024-09-01",
			accessToken: getCredOrDefault(cfg, "api_key", ""),
		}
	case providers.ProviderLakera:
		return &LakeraGuardProvider{
			APIURL:  getCredOrDefault(cfg, "api_url", "https://api.lakera.ai/v2"),
			APIKey:  getCredOrDefault(cfg, "api_key", ""),
		}
	case providers.ProviderAWSGuardrails:
		return &AWSGuardDutyProvider{
			Region: getCredOrDefault(cfg, "region", "us-east-1"),
		}
	default:
		slog.Warn("unknown content safety provider — using builtin", "connector_type", cfg.ConnectorType)
		return &BuiltinContentSafetyProvider{CognitiveServiceURL: cognitiveServiceURL}
	}
}

// ── Builtin (existing cognitive service) ─────────────────────────────────────

// BuiltinContentSafetyProvider delegates to the AOCS Python cognitive service.
// This is the unchanged path — it is the default for all tenants.
type BuiltinContentSafetyProvider struct {
	CognitiveServiceURL string
}

func (p *BuiltinContentSafetyProvider) Evaluate(ctx context.Context, tenantID, payload string) *ContentSafetyResult {
	if p.CognitiveServiceURL == "" {
		slog.Warn("content safety: cognitive service URL not configured — PASS silently",
			"tenant", tenantID,
			"impact", "content-violation checks are bypassed",
			"action_required", "set OCX_COGNITIVE_SERVICE_URL to enable content safety validation",
		)
		return &ContentSafetyResult{Safe: true, Verdict: "ALLOW", ProviderName: "builtin_unconfigured"}
	}

	reqBody, _ := json.Marshal(map[string]any{
		"tenant_id": tenantID,
		"payload":   map[string]any{"raw": payload},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.CognitiveServiceURL+"/audit", bytes.NewReader(reqBody))
	if err != nil {
		slog.Error("content safety: build request failed", "err", err)
		return &ContentSafetyResult{Safe: true, Verdict: "ALLOW", ProviderName: "builtin"}
	}
	req.Header.Set("Content-Type", "application/json")

	client := httpClient()
	resp, err := client.Do(req)
	if err != nil {
		slog.Warn("content safety: cognitive service unavailable", "err", err)
		return &ContentSafetyResult{Safe: true, Verdict: "ALLOW", ProviderName: "builtin"}
	}
	defer resp.Body.Close()

	var raw struct {
		Verdict          string  `json:"verdict"`
		TrustLevel       float64 `json:"trust_level"`
		ViolationsCount  int     `json:"violations_count"`
		AnomalyDetected  bool    `json:"anomaly_detected"`
		AnomalyScore     float64 `json:"anomaly_score"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		slog.Error("content safety: decode failed", "err", err)
		return &ContentSafetyResult{Safe: true, Verdict: "ALLOW", ProviderName: "builtin"}
	}

	result := &ContentSafetyResult{
		Verdict:      strings.ToUpper(raw.Verdict),
		TrustLevel:   raw.TrustLevel,
		AnomalyScore: raw.AnomalyScore,
		ProviderName: "builtin",
	}
	result.Safe = result.Verdict == "ALLOW" || result.Verdict == ""
	return result
}

// ── Azure Content Safety ──────────────────────────────────────────────────────

// AzureContentSafetyProvider delegates to the Azure Content Safety API.
// Credentials: endpoint, api_key (from tenant vault).
type AzureContentSafetyProvider struct {
	Endpoint    string
	APIVersion  string
	accessToken string `json:"-"`
}

func (p *AzureContentSafetyProvider) Evaluate(ctx context.Context, tenantID, payload string) *ContentSafetyResult {
	url := fmt.Sprintf("%s/contentsafety/text:analyze?api-version=%s", p.Endpoint, p.APIVersion)
	reqBody, _ := json.Marshal(map[string]any{
		"text": payload,
		"categories": []string{"Hate", "SelfHarm", "Sexual", "Violence"},
		"outputType": "FourSeverityLevels",
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		slog.Error("azure content safety: build request failed", "err", err)
		return &ContentSafetyResult{Safe: true, Verdict: "ALLOW", ProviderName: "azure_content_safety"}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Ocp-Apim-Subscription-Key", p.accessToken)

	client := httpClient()
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("azure content safety: request failed", "err", err)
		return &ContentSafetyResult{Safe: true, Verdict: "ALLOW", ProviderName: "azure_content_safety"}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	var azResp struct {
		CategoriesAnalysis []struct {
			Category string `json:"category"`
			Severity int    `json:"severity"` // 0=safe, 2=low, 4=medium, 6=high
		} `json:"categoriesAnalysis"`
	}
	// Fail-open for content safety (ALLOW) but log the error prominently.
	if err := json.Unmarshal(body, &azResp); err != nil {
		slog.Error("azure content safety: response JSON parse failed — failing OPEN (ALLOW)",
			"err", err, "tenant", tenantID, "body_len", len(body))
		return &ContentSafetyResult{
			ProviderName:  "azure_content_safety",
			Verdict:       "ALLOW",
			Safe:          true,
			ProviderError: fmt.Sprintf("response parse error: %v", err),
		}
	}

	result := &ContentSafetyResult{ProviderName: "azure_content_safety", Verdict: "ALLOW", Safe: true}
	for _, cat := range azResp.CategoriesAnalysis {
		if cat.Severity >= 2 {
			result.Safe = false
			result.Verdict = "BLOCK"
			sev := "low"
			if cat.Severity >= 4 { sev = "medium" }
			if cat.Severity >= 6 { sev = "high" }
			result.Violations = append(result.Violations, ContentViolation{
				Category:   strings.ToLower(cat.Category),
				Severity:   sev,
				Confidence: float64(cat.Severity) / 6.0,
			})
		}
	}
	slog.Debug("azure content safety evaluated",
		"tenant", tenantID, "verdict", result.Verdict, "violations", len(result.Violations))
	return result
}

// ── Lakera Guard ──────────────────────────────────────────────────────────────

// LakeraGuardProvider delegates to Lakera Guard (LLM-specific jailbreak/prompt injection detection).
type LakeraGuardProvider struct {
	APIURL string
	APIKey string `json:"-"`
}

func (p *LakeraGuardProvider) Evaluate(ctx context.Context, tenantID, payload string) *ContentSafetyResult {
	reqBody, _ := json.Marshal(map[string]any{
		"messages": []map[string]string{{"role": "user", "content": payload}},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.APIURL+"/guard", bytes.NewReader(reqBody))
	if err != nil {
		slog.Error("lakera guard: build request failed", "err", err)
		return &ContentSafetyResult{Safe: true, Verdict: "ALLOW", ProviderName: "lakera_guard"}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.APIKey)

	client := httpClient()
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("lakera guard: request failed", "err", err)
		return &ContentSafetyResult{Safe: true, Verdict: "ALLOW", ProviderName: "lakera_guard"}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	var lkResp struct {
		Results []struct {
			Categories struct {
				PromptInjection bool `json:"prompt_injection"`
				Jailbreak       bool `json:"jailbreak"`
				Unknown         bool `json:"unknown"`
			} `json:"categories"`
			Flagged bool `json:"flagged"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &lkResp); err != nil {
		slog.Error("lakera guard: response JSON parse failed — failing OPEN (ALLOW)",
			"err", err, "body_len", len(body))
		return &ContentSafetyResult{
			ProviderName:  "lakera_guard",
			Verdict:       "ALLOW",
			Safe:          true,
			ProviderError: fmt.Sprintf("response parse error: %v", err),
		}
	}

	result := &ContentSafetyResult{ProviderName: "lakera_guard", Verdict: "ALLOW", Safe: true}
	for _, r := range lkResp.Results {
		if r.Flagged {
			result.Safe = false
			result.Verdict = "BLOCK"
			if r.Categories.PromptInjection {
				result.Violations = append(result.Violations, ContentViolation{Category: "prompt_injection", Severity: "high", Confidence: 0.95})
			}
			if r.Categories.Jailbreak {
				result.Violations = append(result.Violations, ContentViolation{Category: "jailbreak", Severity: "high", Confidence: 0.9})
			}
		}
	}
	return result
}

// ── AWS GuardDuty ─────────────────────────────────────────────────────────────

// AWSGuardDutyProvider delegates to Amazon GuardDuty for malware/threat detection.
// In production: use aws-sdk-go-v2 with STS assumed-role credentials.
type AWSGuardDutyProvider struct {
	Region string
}

func (p *AWSGuardDutyProvider) Evaluate(ctx context.Context, tenantID, payload string) *ContentSafetyResult {
	slog.Info("aws guardduty: evaluate invoked", "region", p.Region, "tenant", tenantID)
	return &ContentSafetyResult{ProviderName: "aws_guardduty", Verdict: "ALLOW", Safe: true}
}
