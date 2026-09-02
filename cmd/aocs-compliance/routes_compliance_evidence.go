package main

// routes_compliance_evidence.go — ZKP, Evidence, and Audit verification routes
// Ring 2 only. All Ring 1 imports removed. RLHC clusters owned by Ring 1 (aocs-hub).

import (
	"log/slog"
	"os"

	"github.com/gorilla/mux"
	compliance "github.com/ocx/compliance/internal/compliance/handlers/compliance"
	zkp "github.com/ocx/compliance/internal/compliance/handlers/zkp"
	gra "github.com/ocx/compliance/internal/compliance/handlers/gra"
	analytics "github.com/ocx/compliance/internal/compliance/handlers/reports"
	evaluation "github.com/ocx/compliance/internal/compliance/handlers/evidence"
	regulatory "github.com/ocx/compliance/internal/compliance/handlers/regulatory"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/middleware"
	"github.com/ocx/shared/infra/serviceclient"
)

// registerComplianceEvidenceRoutes wires ZKP, evidence, and audit trail endpoints.
func registerComplianceEvidenceRoutes(
	api *mux.Router,
	db *database.SupabaseClient,
	pc *auth.PermissionChecker,
	pgxPool *database.PGXPool,
	coreClient *serviceclient.Client,
) {
	// Set ZKP_ED25519_PUBLIC_KEY in .env (hex-encoded Ed25519 public key, 64 chars)
	zkpPublicKeyHex := os.Getenv("ZKP_ED25519_PUBLIC_KEY")
	if zkpPublicKeyHex == "" {
		slog.Warn("ZKP_ED25519_PUBLIC_KEY not set — ZKP verifier running in ephemeral-key mode (local dev only)")
	}
	zkpV := zkp.NewZKPVerifier(zkpPublicKeyHex, 300, db)

	// ── ZKP ───────────────────────────────────────────────────────────────────
	api.HandleFunc("/zkp/verification", auth.RequireAccess(pc, "zkp", "read", zkp.HandleGetZKPVerification(db))).Methods("GET")
	api.HandleFunc("/zkp/verification/{id}", auth.RequireAccess(pc, "zkp", "read", middleware.RequireValidPathVars("id")(zkp.HandleGetZKPVerification(db)))).Methods("GET")
	api.HandleFunc("/zkp/verifications", auth.RequireAccess(pc, "analytics", "read", zkp.HandleListZKPVerifications(db))).Methods("GET")
	api.HandleFunc("/zkp/verifications/{id}", auth.RequireAccess(pc, "compliance", "read", middleware.RequireValidPathVars("id")(zkp.HandleGetZKPVerification(db)))).Methods("GET")
	api.HandleFunc("/zkp/stats", auth.RequireAccess(pc, "zkp", "read", zkp.HandleGetZKPStats(db))).Methods("GET")
	api.HandleFunc("/zkp/proofs", auth.RequireAccess(pc, "analytics", "write", zkp.HandleGenerateZKPProof(db))).Methods("POST")
	api.HandleFunc("/zkp/verify", auth.RequireAccess(pc, "zkp", "write", zkp.HandleVerifyZKP(db, zkpV))).Methods("POST")
	api.HandleFunc("/zkp/chain", auth.RequireAccess(pc, "compliance", "write", compliance.HandleGenerateProofChain(db))).Methods("POST")
	api.HandleFunc("/zkp/chain/{agent_id}/{period}", auth.RequireAccess(pc, "compliance", "read", middleware.RequireValidPathVars("agent_id")(compliance.HandleGetProofChain(db)))).Methods("GET")
	api.HandleFunc("/zkp/chain/verify", auth.RequireAccess(pc, "compliance", "write", compliance.HandleVerifyProofInclusion(db))).Methods("POST")
	api.HandleFunc("/zkp/export", auth.RequireAccess(pc, "compliance", "read", compliance.HandleExportVerifiableCredential(db))).Methods("POST")
	api.HandleFunc("/zkp/batch", auth.RequireAccess(pc, "compliance", "write", compliance.HandleCreateZKPBatchJob(db))).Methods("POST")
	api.HandleFunc("/zkp/batch/{job_id}", auth.RequireAccess(pc, "compliance", "read", middleware.RequireValidPathVars("job_id")(compliance.HandleGetZKPBatchJob(db)))).Methods("GET")
	// Maps to HandleGenerateZKPProof (same as /zkp/generate). GET returns the verifications list.
	api.HandleFunc("/zkp/proofs", auth.RequireAccess(pc, "analytics", "write", zkp.HandleGenerateZKPProof(db))).Methods("POST")
	api.HandleFunc("/zkp/proofs", auth.RequireAccess(pc, "analytics", "read", zkp.HandleListZKPVerifications(db))).Methods("GET")
	api.HandleFunc("/zkp/proofs/{id}", auth.RequireAccess(pc, "compliance", "read",
		middleware.RequireValidPathVars("id")(zkp.HandleGetZKPVerification(db)))).Methods("GET")

	// Real route is /zkp/verifications. Both now return the same ZKP list data.
	api.HandleFunc("/qcore/zkp-proofs", auth.RequireAccess(pc, "analytics", "read", zkp.HandleListZKPVerifications(db))).Methods("GET")
	api.HandleFunc("/qcore/zkp-proofs/{id}", auth.RequireAccess(pc, "compliance", "read", middleware.RequireValidPathVars("id")(zkp.HandleGetZKPVerification(db)))).Methods("GET")

	// NOTE: /hitl/rlhc/clusters is owned by Ring 1 (aocs-hub). Not registered here.
	// Frontend should call aocs-hub directly via the API gateway.

	// ── Evidence — Tenant-scoped CRUD ─────────────────────────────────────────
	//
	// Auth model (two tiers — NOT a route conflict):
	//   ┌─ TENANT-ADMIN scope (these routes, on `api` router) ─────────────────┐
	//   │  GET    /evidence/{id}  → analytics:read   — read one evidence record  │
	//   │  PUT    /evidence/{id}  → analytics:write  — update (HITLGuard gates)  │
	//   │  DELETE /evidence/{id}  → analytics:delete — delete (HITLGuard gates)  │
	//   └─────────────────────────────────────────────────────────────────────────┘
	//   ┌─ SUPER-ADMIN scope (routes_legal.go, /admin/compliance-evidence) ──────┐
	//   │  GET  /admin/compliance-evidence       → admin:read  (SOC2/GDPR list)   │
	//   │  PUT  /admin/compliance-evidence/{id}  → admin:write (control update)   │
	//   └─────────────────────────────────────────────────────────────────────────┘
	//
	// The three HandleFunc calls below on "/evidence/{id}" are INTENTIONAL —
	// gorilla/mux dispatches on HTTP method, so GET/PUT/DELETE are independent.
	// This is NOT a duplicate registration.
	api.HandleFunc("/evidence", auth.RequireAccess(pc, "analytics", "write", evaluation.HandleCreateEvidence(db))).Methods("POST")
	api.HandleFunc("/evidence/chain", auth.RequireAccess(pc, "analytics", "read", evaluation.HandleGetEvidenceChainByID(db))).Methods("GET")
	api.HandleFunc("/evidence/{id}", auth.RequireAccess(pc, "analytics", "read", middleware.RequireValidPathVars("id")(evaluation.HandleGetEvidence(db)))).Methods("GET")
	// HITLMutationGuard checks aocs_evidence_records.hitl_case_id; blocks mutation if case is open.
	api.HandleFunc("/evidence/{id}", auth.RequireAccess(pc, "analytics", "write",
		middleware.HITLMutationGuard(db, "aocs_evidence_records", "evidence_id")(analytics.HandleUpdateEvidence(db)))).Methods("PUT")
	api.HandleFunc("/evidence/{id}", auth.RequireAccess(pc, "analytics", "delete",
		middleware.HITLMutationGuard(db, "aocs_evidence_records", "evidence_id")(analytics.HandleDeleteEvidence(db)))).Methods("DELETE")
	api.HandleFunc("/evidence/{id}/attest", auth.RequireAccess(pc, "analytics", "write", middleware.RequireValidPathVars("id")(evaluation.HandleAttestEvidence(db)))).Methods("POST")
	api.HandleFunc("/evidence/{id}/chain", auth.RequireAccess(pc, "analytics", "read", middleware.RequireValidPathVars("id")(analytics.HandleVerifyChain(db)))).Methods("GET")
	api.HandleFunc("/evidence-attestations", auth.RequireAccess(pc, "analytics", "read", evaluation.HandleListEvidenceAttestations(db))).Methods("GET")
	api.HandleFunc("/evidence-attestations/{id}", auth.RequireAccess(pc, "analytics", "read", middleware.RequireValidPathVars("id")(evaluation.HandleGetEvidenceAttestations(db)))).Methods("GET")
	api.HandleFunc("/evidence-chain-by-id/{id}", auth.RequireAccess(pc, "analytics", "read", middleware.RequireValidPathVars("id")(evaluation.HandleGetEvidenceChainByID(db)))).Methods("GET")
	api.HandleFunc("/evidence-chain-by-id", auth.RequireAccess(pc, "analytics", "read", evaluation.HandleGetEvidenceChainByID(db))).Methods("GET")
	api.HandleFunc("/evidence-stats/{id}", auth.RequireAccess(pc, "analytics", "read", middleware.RequireValidPathVars("id")(evaluation.HandleGetEvidenceStats(db)))).Methods("GET")
	api.HandleFunc("/evidence-stats", auth.RequireAccess(pc, "analytics", "read", evaluation.HandleGetEvidenceStats(db))).Methods("GET")
	api.HandleFunc("/evidences", auth.RequireAccess(pc, "analytics", "read", evaluation.HandleListEvidence(db))).Methods("GET")
	api.HandleFunc("/verify-evidence", auth.RequireAccess(pc, "analytics", "read", evaluation.HandleVerifyEvidence(db))).Methods("GET")

	// ── Compliance reports ────────────────────────────────────────────────────
	api.HandleFunc("/compliance-reports", auth.RequireAccess(pc, "analytics", "read", analytics.HandleListComplianceReports(db))).Methods("GET")
	api.HandleFunc("/compliance-reports/{id}", auth.RequireAccess(pc, "compliance", "read", middleware.RequireValidPathVars("id")(analytics.HandleGetComplianceReport(db)))).Methods("GET")
	api.HandleFunc("/compliance-reports/{id}", auth.RequireAccess(pc, "compliance", "write", middleware.RequireValidPathVars("id")(analytics.HandleUpdateComplianceReport(db)))).Methods("PATCH")
	api.HandleFunc("/compliance-reports/{id}", auth.RequireAccess(pc, "compliance", "delete", middleware.RequireValidPathVars("id")(analytics.HandleDeleteComplianceReport(db)))).Methods("DELETE")
	api.HandleFunc("/compliance/reports/export", auth.RequireAccess(pc, "compliance", "write", compliance.HandleCreateCaseExportJob(db))).Methods("POST")
	api.HandleFunc("/compliance/reports/export/{job_id}", auth.RequireAccess(pc, "compliance", "read", middleware.RequireValidPathVars("job_id")(compliance.HandleGetCaseExportJob(db)))).Methods("GET")

	// ── Ledger ────────────────────────────────────────────────────────────────
	api.HandleFunc("/ledger/root", auth.RequireAccess(pc, "compliance", "read", compliance.HandleGetLedgerRoot(db))).Methods("GET")
	api.HandleFunc("/ledger/root/{id}", auth.RequireAccess(pc, "compliance", "read", middleware.RequireValidPathVars("id")(compliance.HandleGetLedgerRootEntry(db)))).Methods("GET")

	// ── Coverage + policy ─────────────────────────────────────────────────────
	// NOTE: Routes below owned by Ring 1 (aocs-gate/hub) — removed from Ring 2.
	// governance/federation/workflow handlers registered by aocs-gate service.
	api.HandleFunc("/compliance/policy-summary", auth.RequireAccess(pc, "compliance", "read", compliance.HandleGetPolicySummary(pgxPool))).Methods("GET")
	api.HandleFunc("/compliance/policy-impact", auth.RequireAccess(pc, "compliance", "read", compliance.HandleGetPolicyImpact(pgxPool))).Methods("GET")
	api.HandleFunc("/compliance/policy-impact/preview", auth.RequireAccess(pc, "compliance", "read", compliance.HandleGetPolicyImpactPreview(pgxPool))).Methods("POST")
	// calls GET /gra/policy-impact. Alias to the compliance policy impact handler.
	api.HandleFunc("/gra/policy-impact", auth.RequireAccess(pc, "compliance", "read", compliance.HandleGetPolicyImpact(pgxPool))).Methods("GET")

	// ── Authority admin ───────────────────────────────────────────────────────
	api.HandleFunc("/admin/authority/gaps", auth.RequireSuperAdmin(compliance.HandleAdminListAuthorityGaps(db))).Methods("GET")
	api.HandleFunc("/admin/authority/gaps/{id}", auth.RequireSuperAdmin(middleware.RequireValidPathVars("id")(compliance.HandleGetAuthorityGap(db)))).Methods("GET")
	api.HandleFunc("/admin/authority/contracts", auth.RequireSuperAdmin(compliance.HandleAdminListAuthorityContracts(db))).Methods("GET")
	api.HandleFunc("/admin/authority/contracts/{id}", auth.RequireSuperAdmin(middleware.RequireValidPathVars("id")(compliance.HandleAdminGetAuthorityContract(db)))).Methods("GET")
	api.HandleFunc("/admin/authority/documents/{id}", auth.RequireSuperAdmin(middleware.RequireValidPathVars("id")(compliance.HandleAdminGetParsedDocument(db)))).Methods("GET")
	api.HandleFunc("/admin/compliance/submissions", auth.RequireSuperAdmin(compliance.HandleListComplianceSubmissions(db))).Methods("GET")
	api.HandleFunc("/admin/compliance/submissions", auth.RequireSuperAdmin(compliance.HandleCreateComplianceSubmission(db))).Methods("POST")
	api.HandleFunc("/admin/compliance/submissions/{id}", auth.RequireSuperAdmin(middleware.RequireValidPathVars("id")(compliance.HandleGetComplianceSubmission(db)))).Methods("GET")
	api.HandleFunc("/admin/compliance/submissions/{id}", auth.RequireSuperAdmin(middleware.RequireValidPathVars("id")(compliance.HandleUpdateComplianceSubmission(db)))).Methods("PATCH")
	api.HandleFunc("/admin/compliance/submissions/{id}", auth.RequireSuperAdmin(middleware.RequireValidPathVars("id")(compliance.HandleDeleteComplianceSubmission(db)))).Methods("DELETE")
	api.HandleFunc("/admin/compliance/submissions/{id}/review", auth.RequireSuperAdmin(middleware.RequireValidPathVars("id")(compliance.HandleApproveComplianceSubmission(db)))).Methods("POST")

	// ── Regulator ─────────────────────────────────────────────────────────────

	// ── GRA ───────────────────────────────────────────────────────────────────
	api.HandleFunc("/gra/compliance-obligations", auth.RequireAccess(pc, "governance", "read", compliance.HandleListComplianceObligations(pgxPool))).Methods("GET")
	api.HandleFunc("/gra/compliance-obligations/{id}", auth.RequireAccess(pc, "compliance", "read", middleware.RequireValidPathVars("id")(compliance.HandleGetGRAObligation(db)))).Methods("GET")
	api.HandleFunc("/gra/compliance-regions", auth.RequireAccess(pc, "governance", "write", compliance.HandleCreateComplianceRegion(db))).Methods("POST")
	api.HandleFunc("/gra/compliance-regions", auth.RequireAccess(pc, "governance", "read", compliance.HandleListComplianceRegions(db))).Methods("GET")
	api.HandleFunc("/gra/frameworks/{id}", auth.RequireAccess(pc, "compliance", "read", middleware.RequireValidPathVars("id")(compliance.HandleGetGRAFramework(db)))).Methods("GET")
	api.HandleFunc("/gra/frameworks/{id}", auth.RequireAccess(pc, "compliance", "write", middleware.RequireValidPathVars("id")(compliance.HandleUpdateGRAFramework(db)))).Methods("PATCH")
	api.HandleFunc("/gra/risk-config/{id}", auth.RequireAccess(pc, "compliance", "read", middleware.RequireValidPathVars("id")(compliance.HandleGetGRARiskConfig(db)))).Methods("GET")
	api.HandleFunc("/gra/risk-config/{id}", auth.RequireAccess(pc, "compliance", "write", middleware.RequireValidPathVars("id")(compliance.HandleUpdateGRARiskConfig(db)))).Methods("PATCH")

	// ── Misc ──────────────────────────────────────────────────────────────────
	api.HandleFunc("/import-sources", auth.RequireAccess(pc, "analytics", "read", analytics.HandleListImportSources(db))).Methods("GET")
	api.HandleFunc("/rlhcclaims", auth.RequireAccess(pc, "admin", "read", analytics.HandleGetRLHCClaims(db))).Methods("GET")
	api.HandleFunc("/rlhcclaims/{id}", auth.RequireAccess(pc, "admin", "read", middleware.RequireValidPathVars("id")(analytics.HandleGetRLHCClaims(db)))).Methods("GET")
	api.HandleFunc("/sanction-summary", auth.RequireAccess(pc, "governance", "read", analytics.HandleGetSanctionSummary(db))).Methods("GET")
	api.HandleFunc("/compliance/obligations", auth.RequireAccess(pc, "compliance", "read", gra.HandleListGRAComplianceObligations(db, coreClient))).Methods("GET")
	api.HandleFunc("/compliance/obligations/{id}", auth.RequireAccess(pc, "compliance", "read", middleware.RequireValidPathVars("id")(compliance.HandleGetComplianceObligation(db)))).Methods("GET")
	api.HandleFunc("/compliance/obligations/{id}", auth.RequireAccess(pc, "compliance", "write", middleware.RequireValidPathVars("id")(compliance.HandleUpdateComplianceObligation(db)))).Methods("PATCH")
	api.HandleFunc("/compliance/obligations/{id}", auth.RequireAccess(pc, "compliance", "delete", middleware.RequireValidPathVars("id")(compliance.HandleDeleteComplianceObligation(db)))).Methods("DELETE")
	api.HandleFunc("/compliance/regulatory-frameworks", auth.RequireAccess(pc, "compliance", "read", gra.HandleListGRARegulatoryFrameworks(db, coreClient))).Methods("GET")

	// ── EU AI Act Article 13 — Transparency Reporting (Interactive Card) ──────
	// Regulation (EU) 2024/1689 Art.13: providers of high-risk AI systems must supply
	// users with a machine-readable transparency card covering purpose, oversight,
	// technical specs, performance metrics, and known limitations.
	// Effective: 2 August 2026 (GPAI: 2 August 2025).
	// Fine: up to €30M or 6% of worldwide annual turnover per deployment.
	//
	// GET  /compliance/eu-ai-act/transparency        — generate transparency card (live data)
	// POST /compliance/eu-ai-act/transparency/submit — file a signed declaration
	// GET  /compliance/eu-ai-act/transparency/status — declaration filing status
	api.HandleFunc("/compliance/eu-ai-act/transparency", auth.RequireAccess(pc, "compliance", "read", compliance.HandleGetEUAIActTransparency(db, coreClient))).Methods("GET")
	api.HandleFunc("/compliance/eu-ai-act/transparency", auth.RequireAccess(pc, "compliance", "write", compliance.HandleSubmitEUAIActDeclaration(db))).Methods("POST")
	api.HandleFunc("/compliance/eu-ai-act/transparency/status", auth.RequireAccess(pc, "compliance", "read", compliance.HandleGetEUAIActDeclarationStatus(db))).Methods("GET")

	// ── EU AI Act Article 13 — Formal Regulatory Report Artefact ─────────────
	// Distinct from the interactive card above: these routes produce a downloadable,
	// SHA-256-hashed, version-locked artefact for formal submission to a supervisory
	// authority (Article 71) or notified body (Article 43 conformity assessment).
	// Status lifecycle: DRAFT → FILED (immutable). To supersede, generate a new DRAFT.
	//
	// GET  /compliance/regulatory/eu-ai-act/report        — generate Article 13 report (DRAFT)
	// POST /compliance/regulatory/eu-ai-act/report/submit — file report (DRAFT → FILED)
	// GET  /compliance/regulatory/eu-ai-act/report/{id}   — retrieve filed report by ID
	api.HandleFunc("/compliance/regulatory/eu-ai-act/report", auth.RequireAccess(pc, "compliance", "write", regulatory.HandleGenerateEUAIActReport(db, coreClient))).Methods("GET")
	api.HandleFunc("/compliance/regulatory/eu-ai-act/reports", auth.RequireAccess(pc, "compliance", "write", regulatory.HandleSubmitEUAIActReport(db))).Methods("POST")
	api.HandleFunc("/compliance/regulatory/eu-ai-act/report/{id}", auth.RequireAccess(pc, "compliance", "read", middleware.RequireValidPathVars("id")(regulatory.HandleGetEUAIActReport(db)))).Methods("GET")

	// ── SOC2 Type II Evidence Package Generator ────────────────────────────────
	// AICPA Trust Service Criteria (CC1–CC9, A1) — auto-generated from live AOCS data.
	// Evidence is collected from: active policies, gate verdicts, HITL decisions,
	// GRA risk assessments, DLP findings, ZKP audit chain, and agent access controls.
	//
	// POST /compliance/soc2/evidence-package        — generate evidence package (DRAFT)
	// GET  /compliance/soc2/evidence-package/{id}   — retrieve package by ID
	// GET  /compliance/soc2/evidence-packages       — list all packages for tenant
	api.HandleFunc("/compliance/soc2/evidence-package", auth.RequireAccess(pc, "compliance", "write", evaluation.HandleGenerateSOC2Package(db))).Methods("POST")
	api.HandleFunc("/compliance/soc2/evidence-package/{id}", auth.RequireAccess(pc, "compliance", "read", middleware.RequireValidPathVars("id")(evaluation.HandleGetSOC2Package(db)))).Methods("GET")
	api.HandleFunc("/compliance/soc2/evidence-packages", auth.RequireAccess(pc, "compliance", "read", evaluation.HandleListSOC2Packages(db))).Methods("GET")

	// ── Evidence Chain (SOX/GDPR cryptographic audit trail) ──────────────────
	// GET  /compliance/evidence/{id}/chain  — retrieve full hash-chained evidence blocks
	// PATCH /compliance/evidence/{id}       — update evidence record (pre-attestation only)
	// DELETE /compliance/evidence/{id}      — soft-delete (preserves chain integrity)
	api.HandleFunc("/compliance/evidence/{id}/chain",
		auth.RequireAccess(pc, "compliance", "read",
			middleware.RequireValidPathVars("id")(analytics.HandleGetEvidenceChain(db)))).Methods("GET")
	api.HandleFunc("/compliance/evidence/{id}",
		auth.RequireAccess(pc, "compliance", "write",
			middleware.RequireValidPathVars("id")(analytics.HandleUpdateEvidence(db)))).Methods("PATCH")
	api.HandleFunc("/compliance/evidence/{id}",
		auth.RequireAccess(pc, "compliance", "delete",
			middleware.RequireValidPathVars("id")(analytics.HandleDeleteEvidence(db)))).Methods("DELETE")

	// ── Disputes (Patent Claim 3 — tenant-initiated formal objections) ────────
	// Full lifecycle: Create → Assign → Resolve → Delete
	// Disputes feed back into the GRA self-heal loop (CIP-2).
	api.HandleFunc("/compliance/disputes",
		auth.RequireAccess(pc, "compliance", "read",
			compliance.HandleListDisputes(db))).Methods("GET")
	api.HandleFunc("/compliance/disputes",
		auth.RequireAccess(pc, "compliance", "write",
			compliance.HandleCreateDispute(db))).Methods("POST")
	api.HandleFunc("/compliance/disputes/{id}",
		auth.RequireAccess(pc, "compliance", "read",
			middleware.RequireValidPathVars("id")(compliance.HandleGetDispute(db)))).Methods("GET")
	api.HandleFunc("/compliance/disputes/{id}/resolve",
		auth.RequireAccess(pc, "compliance", "write",
			middleware.RequireValidPathVars("id")(compliance.HandleResolveDispute(db)))).Methods("POST")
	api.HandleFunc("/compliance/disputes/{id}",
		auth.RequireAccess(pc, "compliance", "delete",
			middleware.RequireValidPathVars("id")(compliance.HandleDeleteDispute(db)))).Methods("DELETE")

	// ── Governance Proposals + Voting (autonomous governance — GRA CRUD) ──────
	api.HandleFunc("/gra/proposals",
		auth.RequireAccess(pc, "governance", "read",
			gra.HandleListGovernanceVotes(db))).Methods("GET")
	api.HandleFunc("/gra/proposals",
		auth.RequireAccess(pc, "governance", "write",
			gra.HandleCreateGovernanceProposal(db))).Methods("POST")
	api.HandleFunc("/gra/proposals/{id}",
		auth.RequireAccess(pc, "governance", "read",
			middleware.RequireValidPathVars("id")(gra.HandleGetGovernanceProposal(db)))).Methods("GET")
	api.HandleFunc("/gra/proposals/{id}",
		auth.RequireAccess(pc, "governance", "write",
			middleware.RequireValidPathVars("id")(gra.HandleUpdateGovernanceProposal(db)))).Methods("PATCH")
	api.HandleFunc("/gra/proposals/{id}",
		auth.RequireAccess(pc, "governance", "delete",
			middleware.RequireValidPathVars("id")(gra.HandleDeleteGovernanceProposal(db)))).Methods("DELETE")
	api.HandleFunc("/gra/proposals/{id}/vote",
		auth.RequireAccess(pc, "governance", "write",
			middleware.RequireValidPathVars("id")(gra.HandleCastGovernanceVote(db)))).Methods("POST")

	// ── GRA Federation Peers (admin CRUD) ─────────────────────────────────────
	api.HandleFunc("/gra/federation/peers",
		auth.RequireAccess(pc, "governance", "write",
			gra.HandleAdminCreateFederationPeer(db))).Methods("POST")
	api.HandleFunc("/gra/federation/peers/{id}",
		auth.RequireAccess(pc, "governance", "read",
			middleware.RequireValidPathVars("id")(gra.HandleAdminGetFederationPeer(db)))).Methods("GET")
	api.HandleFunc("/gra/federation/peers/{id}",
		auth.RequireAccess(pc, "governance", "write",
			middleware.RequireValidPathVars("id")(gra.HandleAdminUpdateFederationPeer(db)))).Methods("PATCH")
	api.HandleFunc("/gra/federation/peers/{id}",
		auth.RequireAccess(pc, "governance", "delete",
			middleware.RequireValidPathVars("id")(gra.HandleAdminDeleteFederationPeer(db)))).Methods("DELETE")

	// ── CAE Sessions (Continuous Agent Evaluation) ────────────────────────────
	api.HandleFunc("/compliance/cae-sessions",
		auth.RequireAccess(pc, "compliance", "read",
			analytics.HandleListCAESessions(db))).Methods("GET")
	api.HandleFunc("/compliance/cae-sessions/{id}",
		auth.RequireAccess(pc, "compliance", "read",
			middleware.RequireValidPathVars("id")(analytics.HandleGetCAESession(db)))).Methods("GET")

	// ── Trust Economy — Staking, Trust Tax, Usage Records ────────────────────
	// These handlers take *database.SupabaseClient directly (concrete type required).
	api.HandleFunc("/analytics/staking-ledger",
		auth.RequireAccess(pc, "compliance", "read",
			analytics.HandleListStakingLedger(db))).Methods("GET")
	api.HandleFunc("/analytics/trust-tax-claims/{id}",
		auth.RequireAccess(pc, "compliance", "read",
			middleware.RequireValidPathVars("id")(analytics.HandleGetTrustTaxClaim(db)))).Methods("GET")
	api.HandleFunc("/analytics/trust-tax-claims/{id}",
		auth.RequireAccess(pc, "compliance", "write",
			middleware.RequireValidPathVars("id")(analytics.HandleUpdateTrustTaxClaim(db)))).Methods("PATCH")
	api.HandleFunc("/analytics/tenant-usage/{id}",
		auth.RequireAccess(pc, "compliance", "read",
			middleware.RequireValidPathVars("id")(analytics.HandleGetTenantUsageRecord(db)))).Methods("GET")
	api.HandleFunc("/analytics/tenant-usage/{id}",
		auth.RequireAccess(pc, "compliance", "write",
			middleware.RequireValidPathVars("id")(analytics.HandleUpdateTenantUsageRecord(db)))).Methods("PATCH")

	// ── Economics Dashboard (SuperAdmin cross-tenant) ─────────────────────────
	// nolint:tenant_filter — SuperAdmin views intentionally span all tenants.
	api.HandleFunc("/analytics/economics/overview",
		auth.RequireAccess(pc, "platform", "read",
			analytics.HandleGetEconomicsOverview(db))).Methods("GET")
	api.HandleFunc("/analytics/economics/revenue",
		auth.RequireAccess(pc, "platform", "read",
			analytics.HandleGetEconomicsRevenue(db))).Methods("GET")

	// ── Resource Graph Snapshot ───────────────────────────────────────────────
	api.HandleFunc("/analytics/resource-graph/snapshot",
		auth.RequireAccess(pc, "compliance", "read",
			analytics.HandleGetResourceGraphSnapshot(db))).Methods("GET")
}


