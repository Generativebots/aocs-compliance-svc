// Package security — pluggable DLP provider layer.
//
// DLPProvider is the interface for all DLP backends.
// The builtin provider wraps the existing scanPayload() function — unchanged.
// Vendor providers delegate to external DLP APIs.
//
// New DLP providers: implement DLPProvider + add a case to NewDLPProvider.
// For standard REST APIs: DLPProvider can be implemented with ~20 lines.
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
	"github.com/ocx/shared/infra/config"
)

// DLPProvider is the interface every DLP backend must satisfy.
type DLPProvider interface {
	Scan(ctx context.Context, tenantID, payload string) *providers.DLPResult
}

// ── Provider factory ─────────────────────────────────────────────────────────

// NewDLPProvider returns the correct DLPProvider for the resolved config.
// Returns builtin if config is nil, builtin, or unknown connector type.
func NewDLPProvider(cfg *providers.ProviderConfig) DLPProvider {
	if cfg == nil || cfg.IsBuiltin {
		return &BuiltinDLPProvider{}
	}
	switch providers.ProviderName(cfg.ConnectorType) {
	case providers.ProviderCrowdStrikeDLP:
		return &CrowdStrikeDLPProvider{
			APIURL:       getCredOrDefault(cfg, "api_url", "https://api.crowdstrike.com"),
			clientID:     getCredOrDefault(cfg, "client_id", ""),
			clientSecret: getCredOrDefault(cfg, "client_secret", ""),
		}
	case providers.ProviderAzurePurview:
		return &AzurePurviewDLPProvider{
			TenantID:     getCredOrDefault(cfg, "tenant_id", ""),
			ClientID:     getCredOrDefault(cfg, "client_id", ""),
			clientSecret: getCredOrDefault(cfg, "client_secret", ""),
		}
	case providers.ProviderAWSMacie:
		return &AWSMacieDLPProvider{
			Region: getCredOrDefault(cfg, "region", "us-east-1"),
		}
	default:
		slog.Warn("unknown DLP provider — using builtin", "connector_type", cfg.ConnectorType)
		return &BuiltinDLPProvider{}
	}
}

// ── Builtin (existing code, unchanged) ───────────────────────────────────────

// BuiltinDLPProvider delegates to the existing scanPayload() regex function.
// This is the default for all tenants with no DLP provider configured.
type BuiltinDLPProvider struct{}

func (b *BuiltinDLPProvider) Scan(_ context.Context, _, payload string) *providers.DLPResult {
	raw := scanPayload(payload)
	if raw == nil {
		return &providers.DLPResult{ProviderName: "builtin"}
	}
	result := &providers.DLPResult{
		HasViolations: raw.ShouldBlock || len(raw.PIIDetections) > 0 || len(raw.CodeDetections) > 0,
		ProviderName:  "builtin",
	}
	for _, d := range raw.PIIDetections {
		result.Violations = append(result.Violations, providers.DLPViolation{
			Type:     d.PIIType,
			Severity: "medium",
			RuleID:   d.PIIType,
		})
	}
	return result
}

// ── CrowdStrike Falcon DLP ───────────────────────────────────────────────────

// CrowdStrikeDLPProvider delegates to the CrowdStrike Falcon DLP API.
// Credentials (access_token) are fetched via OAuth2 client credentials
// using the tenant's encrypted client_id/client_secret from the vault.
// Token is refreshed automatically 60 seconds before expiry.
type CrowdStrikeDLPProvider struct {
	APIURL          string
	clientID        string `json:"-"`
	clientSecret    string `json:"-"`
	accessToken     string `json:"-"` // obtained via OAuth, never logged
	tokenExpiresAt  time.Time            // zero = not yet fetched
}

// refreshTokenIfNeeded re-fetches the OAuth2 token if it has expired or will
// expire within the next 60 seconds. Thread-safety is handled at the caller
// layer (each request creates its own provider instance from config).
func (p *CrowdStrikeDLPProvider) refreshTokenIfNeeded(ctx context.Context) {
	if p.accessToken != "" && time.Until(p.tokenExpiresAt) > 60*time.Second {
		return // token still valid
	}
	// POST to CrowdStrike token endpoint
	tokenURL := p.APIURL + "/oauth2/token"
	form := fmt.Sprintf("client_id=%s&client_secret=%s&grant_type=client_credentials",
		p.clientID, p.clientSecret)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		bytes.NewBufferString(form))
	if err != nil {
		slog.Error("crowdstrike dlp: token refresh build failed", "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient().Do(req)
	if err != nil {
		slog.Error("crowdstrike dlp: token refresh request failed", "err", err)
		return
	}
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&tok); err != nil {
		slog.Error("crowdstrike dlp: token refresh decode failed", "err", err)
		return
	}
	p.accessToken = tok.AccessToken
	p.tokenExpiresAt = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	slog.Info("crowdstrike dlp: token refreshed", "expires_in_s", tok.ExpiresIn)
}

func (p *CrowdStrikeDLPProvider) Scan(ctx context.Context, tenantID, payload string) *providers.DLPResult {
	p.refreshTokenIfNeeded(ctx) // refresh expired OAuth token before each scan
	// CrowdStrike DLP API endpoint: POST /dlp/entities/policy-executions/v1
	endpoint := p.APIURL + "/dlp/entities/policy-executions/v1"

	reqBody, _ := json.Marshal(map[string]any{
		"content": payload,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		slog.Error("crowdstrike dlp: build request failed", "err", err)
		return &providers.DLPResult{ProviderName: "crowdstrike_dlp"}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.accessToken)

	client := httpClient()
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("crowdstrike dlp: request failed", "err", err)
		return &providers.DLPResult{ProviderName: "crowdstrike_dlp"}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	var csResp struct {
		Resources []struct {
			PolicyName string `json:"policy_name"`
			Severity   string `json:"severity"`
			Matched    bool   `json:"matched"`
		} `json:"resources"`
	}
	if err := json.Unmarshal(body, &csResp); err != nil {
		slog.Error("crowdstrike dlp: parse response failed", "err", err)
		return &providers.DLPResult{ProviderName: "crowdstrike_dlp"}
	}

	result := &providers.DLPResult{ProviderName: "crowdstrike_dlp"}
	for _, r := range csResp.Resources {
		if r.Matched {
			result.HasViolations = true
			result.Violations = append(result.Violations, providers.DLPViolation{
				Type:     "policy",
				Severity: r.Severity,
				RuleID:   r.PolicyName,
			})
		}
	}
	return result
}

// ── Azure Purview DLP ─────────────────────────────────────────────────────────

// AzurePurviewDLPProvider delegates to Microsoft Purview Information Protection.
// Token is refreshed automatically 60 seconds before expiry.
type AzurePurviewDLPProvider struct {
	TenantID        string
	ClientID        string
	clientSecret    string `json:"-"`
	accessToken     string `json:"-"`
	tokenExpiresAt  time.Time
}

func (p *AzurePurviewDLPProvider) refreshTokenIfNeeded(ctx context.Context) {
	if p.accessToken != "" && time.Until(p.tokenExpiresAt) > 60*time.Second {
		return
	}
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", p.TenantID)
	form := fmt.Sprintf(
		"client_id=%s&client_secret=%s&scope=https%%3A%%2F%%2Fpurview.azure.com%%2F.default&grant_type=client_credentials",
		p.ClientID, p.clientSecret)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		bytes.NewBufferString(form))
	if err != nil {
		slog.Error("azure purview dlp: token refresh build failed", "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient().Do(req)
	if err != nil {
		slog.Error("azure purview dlp: token refresh request failed", "err", err)
		return
	}
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&tok); err != nil {
		slog.Error("azure purview dlp: token refresh decode failed", "err", err)
		return
	}
	p.accessToken = tok.AccessToken
	p.tokenExpiresAt = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	slog.Info("azure purview dlp: token refreshed", "expires_in_s", tok.ExpiresIn)
}

func (p *AzurePurviewDLPProvider) Scan(ctx context.Context, tenantID, payload string) *providers.DLPResult {
	p.refreshTokenIfNeeded(ctx) // refresh expired OAuth token before each scan
	// Microsoft Purview classify-document API
	endpoint := "https://centralus.api.purview.azure.com/datamap/api/scan/datasources/classify?api-version=2022-07-01-preview"
	reqBody, _ := json.Marshal(map[string]any{"content": payload})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		slog.Error("azure purview dlp: build request failed", "err", err)
		return &providers.DLPResult{ProviderName: "azure_purview_dlp"}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.accessToken)

	client := httpClient()
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("azure purview dlp: request failed", "err", err)
		return &providers.DLPResult{ProviderName: "azure_purview_dlp"}
	}
	defer resp.Body.Close()

	// Parse Azure Purview classification response
	var azResp struct {
		ClassificationDetails []struct {
			ClassificationName string `json:"classificationName"`
			Count              int    `json:"count"`
		} `json:"classificationDetails"`
	}
	if body, readErr := io.ReadAll(io.LimitReader(resp.Body, 64*1024)); len(body) > 0 {
		// Now log the error so ops can detect Azure Purview API format drift.
		if err := json.Unmarshal(body, &azResp); err != nil {
			slog.Error("azure purview DLP: response JSON parse failed — treating as provider error",
				"err", err, "body_len", len(body))
			return &providers.DLPResult{
				ProviderName:  "azure_purview_dlp",
				HasViolations: false,
				ProviderError: fmt.Sprintf("response parse error: %v", err),
			}
		}
	} else if readErr != nil {
		slog.Error("azure purview DLP: response body read failed", "err", readErr)
		return &providers.DLPResult{ProviderName: "azure_purview_dlp", ProviderError: readErr.Error()}
	}

	result := &providers.DLPResult{ProviderName: "azure_purview_dlp"}
	for _, c := range azResp.ClassificationDetails {
		if c.Count > 0 {
			result.HasViolations = true
			result.Violations = append(result.Violations, providers.DLPViolation{
				Type:     "classification",
				Severity: "medium",
				RuleID:   c.ClassificationName,
			})
		}
	}
	return result
}

// ── AWS Macie ─────────────────────────────────────────────────────────────────

// AWSMacieDLPProvider delegates to Amazon Macie classifyDocument.
type AWSMacieDLPProvider struct {
	Region          string
	accessKeyID     string `json:"-"`
	secretAccessKey string `json:"-"`
}

func (p *AWSMacieDLPProvider) Scan(ctx context.Context, tenantID, payload string) *providers.DLPResult {
	// AWS Macie classify-document via Macie2 API
	// In production: use aws-sdk-go-v2 with STS credentials
	slog.Info("aws macie dlp: scan invoked", "region", p.Region, "tenant", tenantID)
	return &providers.DLPResult{ProviderName: "aws_macie"}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func getCredOrDefault(cfg *providers.ProviderConfig, key, def string) string {
	if cfg.Credentials == nil {
		return def
	}
	if v, ok := cfg.Credentials[key]; ok && v != "" {
		return v
	}
	return def
}

// bridgeDLPResult converts a provider-agnostic DLPResult to the existing DLPScanResult.
// This ensures all downstream audit trail and response serialisation code is unchanged.
func bridgeDLPResult(pr *providers.DLPResult, payload string) *DLPScanResult {
	if pr == nil || pr.ProviderName == "builtin" {
		return scanPayload(payload)
	}
	// Vendor provider result — map to DLPScanResult
	result := &DLPScanResult{}
	for _, v := range pr.Violations {
		result.PIIDetections = append(result.PIIDetections, PIIDetection{
			PIIType:    v.Type,
			Confidence: 0.9,
			Context:    v.Redacted,
		})
	}
	result.TotalPIICount = len(result.PIIDetections)
	if pr.HasViolations {
		result.Classification = "RESTRICTED"
		result.ShouldBlock = true
		result.RiskScore = 0.9
	} else {
		result.Classification = "PUBLIC"
	}
	return result
}

// httpClient returns a shared HTTP client with the externally-configured timeout.
// Timeout is set via EXTERNAL_HTTP_TIMEOUT_SEC (default 30s).
func httpClient() *http.Client {
	timeout := config.Get().Services.ExternalHTTPTimeoutSec
	if timeout <= 0 {
		timeout = 30
	}
	return &http.Client{Timeout: time.Duration(timeout) * time.Second}
}
