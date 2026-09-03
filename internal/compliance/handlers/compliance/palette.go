package compliance

// palette.go — Studio node palette manifest for the Compliance ring.
//
// GET /api/v1/compliance/palette-manifest
//
// This endpoint is called by aocs-studio-svc at palette request time to
// discover which compliance nodes are available for the Studio canvas.
//
// Design:
//   - No DB required — the manifest is static (compliance capabilities are
//     code-shipped, not operator-configured at runtime).
//   - No auth guard — the gateway already validates the tenant JWT; this
//     endpoint is internal VPC only (Cloud Run ingress = internal).
//   - Format matches ringclient.CompliancePaletteNode in aocs-studio-svc.
//   - The Available flag is NOT set here — studio-svc sets it based on the
//     tenant's FeatureCompliance JWT claim after fetching this manifest.

import (
	"encoding/json"
	"net/http"
)

// compliancePaletteManifest is the static list of compliance pipeline nodes
// that aocs-compliance-svc exposes to the Studio canvas.
// Add new node types here when new compliance capabilities are shipped.
var compliancePaletteManifest = []map[string]any{
	{
		"id":               "compliance.dlp_scan",
		"type":             "compliance",
		"category":         "Compliance Pipeline",
		"label":            "DLP Scan",
		"icon":             "🔍",
		"color":            "#DC2626",
		"description":      "Pipe data through the DLP scanner before proceeding. Blocks if PII/sensitive data detected and policy forbids it.",
		"default_data":     map[string]any{"compliance_step": "dlp_scan", "block_on_pii": true},
		"requires_feature": "compliance",
		"inputs":           1,
		"outputs":          2, // output 0 = clean, output 1 = flagged
	},
	{
		"id":               "compliance.zkp_proof",
		"type":             "compliance",
		"category":         "Compliance Pipeline",
		"label":            "ZKP Proof",
		"icon":             "🔐",
		"color":            "#7C3AED",
		"description":      "Attach a zero-knowledge proof to the enforcement decision. Required for EU AI Act Article 13 auditability.",
		"default_data":     map[string]any{"compliance_step": "zkp_proof"},
		"requires_feature": "compliance",
		"inputs":           1,
		"outputs":          1,
	},
	{
		"id":               "compliance.evidence_capture",
		"type":             "compliance",
		"category":         "Compliance Pipeline",
		"label":            "Evidence Vault",
		"icon":             "📦",
		"color":            "#059669",
		"description":      "Store this decision in the tamper-evident evidence vault. Required for SOC2 CC6.1 compliance audit.",
		"default_data":     map[string]any{"compliance_step": "evidence_capture", "vault_type": "decision"},
		"requires_feature": "compliance",
		"inputs":           1,
		"outputs":          1,
	},
	{
		"id":               "compliance.audit_pipe",
		"type":             "compliance",
		"category":         "Compliance Pipeline",
		"label":            "Audit Checkpoint",
		"icon":             "📋",
		"color":            "#0284C7",
		"description":      "Force an immutable audit log entry at this exact branch. Use on high-risk decision paths.",
		"default_data":     map[string]any{"compliance_step": "audit_pipe", "severity": "high"},
		"requires_feature": "compliance",
		"inputs":           1,
		"outputs":          1,
	},
}

// manifestJSON is the pre-serialised manifest bytes — computed once at startup.
var manifestJSON []byte

func init() {
	b, err := json.Marshal(compliancePaletteManifest)
	if err != nil {
		panic("compliance: failed to serialise palette manifest: " + err.Error())
	}
	manifestJSON = b
}

// HandleGetPaletteManifest returns the static compliance node manifest.
//
// GET /api/v1/compliance/palette-manifest
//
// Called by aocs-studio-svc ringclient on every GET /policies/builder/node-palette
// request. Response is served from in-memory bytes — no DB or allocations.
func HandleGetPaletteManifest() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(manifestJSON)
	}
}
