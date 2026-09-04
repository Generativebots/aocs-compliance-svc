package main

import (
	compliance "github.com/ocx/compliance/internal/compliance/handlers/compliance"
	hsecurity "github.com/ocx/compliance/internal/compliance/handlers/security"
	regulatory "github.com/ocx/compliance/internal/compliance/handlers/regulatory"
	reports "github.com/ocx/compliance/internal/compliance/handlers/reports"
	"github.com/gorilla/mux"
	"github.com/ocx/shared/contracts"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/middleware"
	"github.com/ocx/shared/infra/security"
	"github.com/ocx/shared/infra/serviceclient"
	"github.com/ocx/shared/types"
)

// routes_compliance.go — Ring 2 only: /violations/*, /sanctions/*, /dlp/*, /cases/*, /hitl/cases/*, /entropy/*
// All Ring 1 dependencies removed. Entropy uses contracts.EntropyMonitor interface.
// ZKP/Evidence/GRA routes delegated to registerComplianceEvidenceRoutes().

func registerIntelComplianceRoutes(
	api *mux.Router,
	db *database.SupabaseClient,
	pc *auth.PermissionChecker,
	pgx *database.PGXPool,
	dlpStore *hsecurity.DLPStore,
	entropyMonitor contracts.EntropyMonitor,
	secMgr *security.SecurityManager,
	extractorURL string,
	coreClient *serviceclient.Client,
) {
	// ── Evidence/ZKP/GRA delegated ────────────────────────────────────────────
	registerComplianceEvidenceRoutes(api, db, pc, pgx, coreClient)

	// ── Studio palette manifest — called by aocs-studio-svc ringclient ────────
	// GET /compliance/palette-manifest — no DB, no auth guard (internal VPC only).
	// Returns the static list of compliance pipeline nodes for the Studio canvas.
	// Available flag is set by studio-svc based on the tenant's FeatureCompliance claim.
	api.HandleFunc("/compliance/palette-manifest", compliance.HandleGetPaletteManifest()).Methods("GET")

	// ── Violations ────────────────────────────────────────────────────────────
	api.HandleFunc("/violations", auth.RequireAccess(pc, "compliance", "read", compliance.HandleListViolations(db))).Methods("GET")
	api.HandleFunc("/violations", auth.RequireAccess(pc, "compliance", "write", compliance.HandleCreateViolation(db))).Methods("POST")
	api.HandleFunc("/violations/{id}/comments", auth.RequireAccess(pc, "compliance", "write", middleware.RequireValidPathVars("id")(compliance.HandleCreateViolationComment(db)))).Methods("POST")
	api.HandleFunc("/violations/{id}", auth.RequireAccess(pc, "compliance", "delete", middleware.RequireValidPathVars("id")(compliance.HandleDeleteViolation(db)))).Methods("DELETE")
	// /violations/bulk/{action} — canonical per paths.ts violationsBulkAction.
	api.HandleFunc("/violations/bulk/{action}", auth.RequireAccess(pc, "compliance", "write", compliance.HandleBulkViolations(db))).Methods("POST")
	// /governance/violations — canonical path; frontend governance sidebar links here.
	api.HandleFunc("/governance/violations", auth.RequireAccess(pc, "compliance", "read", compliance.HandleListViolations(db))).Methods("GET")

	api.HandleFunc("/violations/{id}", auth.RequireAccess(pc, "compliance", "read", middleware.RequireValidPathVars("id")(compliance.HandleGetViolation(db)))).Methods("GET")
	api.HandleFunc("/violations/{id}", auth.RequireAccess(pc, "compliance", "write", middleware.RequireValidPathVars("id")(compliance.HandleUpdateViolation(db)))).Methods("PATCH")
	api.HandleFunc("/violations/{id}/resolve", auth.RequireAccess(pc, "compliance", "write", middleware.RequireValidPathVars("id")(compliance.HandleResolveViolation(db)))).Methods("POST")
	api.HandleFunc("/violations/{id}/quarantine", auth.RequireAccess(pc, "compliance", "write", middleware.RequireValidPathVars("id")(compliance.HandleIsolateViolation(db)))).Methods("POST")
	api.HandleFunc("/violations/{id}/release", auth.RequireAccess(pc, "compliance", "write", middleware.RequireValidPathVars("id")(compliance.HandleRestoreViolation(db)))).Methods("POST")
	api.HandleFunc("/violations/{id}/escalate", auth.RequireAccess(pc, "compliance", "write", middleware.RequireValidPathVars("id")(compliance.HandleEscalateViolation(db)))).Methods("POST")
	api.HandleFunc("/violations/{id}/summary", auth.RequireAccess(pc, "compliance", "read", middleware.RequireValidPathVars("id")(compliance.HandleGetViolationSummary(db)))).Methods("GET")
	api.HandleFunc("/violations/{id}/comments", auth.RequireAccess(pc, "compliance", "write", middleware.RequireValidPathVars("id")(compliance.HandleCreateCaseComment(db)))).Methods("POST")

	// ── Sanctions ─────────────────────────────────────────────────────────────
	api.HandleFunc("/sanctions", auth.RequireAccess(pc, "compliance", "read", compliance.HandleListSanctions(db))).Methods("GET")
	api.HandleFunc("/sanctions", auth.RequireAccess(pc, "compliance", "write", compliance.HandleCreateSanction(db))).Methods("POST")
	api.HandleFunc("/sanctions/{id}", auth.RequireAccess(pc, "compliance", "read", middleware.RequireValidPathVars("id")(compliance.HandleGetSanction(db)))).Methods("GET")
	api.HandleFunc("/sanctions/{id}", auth.RequireAccess(pc, "compliance", "write", middleware.RequireValidPathVars("id")(compliance.HandleUpdateSanction(db)))).Methods("PATCH")
	api.HandleFunc("/sanctions/{id}", auth.RequireAccess(pc, "compliance", "delete", middleware.RequireValidPathVars("id")(compliance.HandleDeleteSanction(db)))).Methods("DELETE")
	api.HandleFunc("/sanctions/{id}/appeal", auth.RequireAccess(pc, "compliance", "write", middleware.RequireValidPathVars("id")(compliance.HandleSubmitSanctionAppeal(db)))).Methods("POST")

	// /disputes is owned by aocs-hub — NGINX routes /api/v1/disputes → aocs-hub.
	// Handlers here are unreachable via the gateway. Removed.

	// ── DLP ───────────────────────────────────────────────────────────────────
	api.HandleFunc("/dlp", auth.RequireAccess(pc, "compliance", "read", hsecurity.HandleDLPStatus(dlpStore))).Methods("GET")
	api.HandleFunc("/dlp/scan", auth.RequireAccess(pc, "compliance", "read", compliance.HandleListDLPFindings(db))).Methods("GET")
	api.HandleFunc("/dlp/scan", auth.RequireAccess(pc, "compliance", "write", hsecurity.HandleDLPScan(dlpStore))).Methods("POST")
	api.HandleFunc("/dlp/webhook", auth.RequireAccess(pc, "compliance", "write", hsecurity.HandleDLPWebhook(dlpStore))).Methods("POST")
	api.HandleFunc("/dlp/monitor", auth.RequireAccess(pc, "compliance", "write", hsecurity.HandleDLPMonitorPID(dlpStore))).Methods("POST")
	api.HandleFunc("/dlp/integrations", auth.RequireAccess(pc, "compliance", "read", hsecurity.HandleListDLPIntegrations(dlpStore))).Methods("GET")
	api.HandleFunc("/dlp/integrations", auth.RequireAccess(pc, "compliance", "write", hsecurity.HandleCreateDLPIntegration(dlpStore))).Methods("POST")
	api.HandleFunc("/dlp/integrations/{id}", auth.RequireAccess(pc, "compliance", "write", middleware.RequireValidPathVars("id")(hsecurity.HandleUpdateDLPIntegration(dlpStore)))).Methods("PATCH")
	api.HandleFunc("/dlp/integrations/{id}", auth.RequireAccess(pc, "compliance", "delete", middleware.RequireValidPathVars("id")(hsecurity.HandleDeleteDLPIntegration(dlpStore)))).Methods("DELETE")
	api.HandleFunc("/dlp/findings", auth.RequireAccess(pc, "compliance", "read", compliance.HandleListDLPFindings(db))).Methods("GET")
	api.HandleFunc("/dlp/findings", auth.RequireAccess(pc, "compliance", "write", compliance.HandleCreateDLPFinding(db))).Methods("POST")
	api.HandleFunc("/dlp/findings/{id}", auth.RequireAccess(pc, "compliance", "read", middleware.RequireValidPathVars("id")(compliance.HandleGetDLPFinding(db)))).Methods("GET")
	api.HandleFunc("/dlp/findings/{id}", auth.RequireAccess(pc, "compliance", "write", middleware.RequireValidPathVars("id")(compliance.HandleUpdateDLPFinding(db)))).Methods("PATCH")
	api.HandleFunc("/dlp/findings/{id}", auth.RequireAccess(pc, "compliance", "delete", middleware.RequireValidPathVars("id")(compliance.HandleDeleteDLPFinding(db)))).Methods("DELETE")
	api.HandleFunc("/dlp/policies", auth.RequireAccess(pc, "compliance", "read", compliance.HandleListDLPFindings(db))).Methods("GET")
	api.HandleFunc("/dlp/policies", auth.RequireAccess(pc, "compliance", "write", compliance.HandleCreateDLPFinding(db))).Methods("POST")
	api.HandleFunc("/compliance/dlp/monitors", auth.RequireAccess(pc, "compliance", "read", hsecurity.HandleDLPMonitorPID(dlpStore))).Methods("GET")
	// ── DLP quarantine & incident log ───────────────────────────────────────────────
	api.HandleFunc("/dlp/quarantine", auth.RequireAccess(pc, "compliance", "write", hsecurity.HandleDLPQuarantine(dlpStore))).Methods("POST")
	api.HandleFunc("/dlp/incidents", auth.RequireAccess(pc, "compliance", "write", compliance.HandleCreateDLPFinding(db))).Methods("POST")

	// ── HITL Cases ────────────────────────────────────────────────────────────
	api.HandleFunc("/hitl/cases/{id}/arbitrate", auth.RequireAccess(pc, "hitl", "write", middleware.RequireValidPathVars("id")(compliance.HandleResolveCase(db, nil, coreClient)))).Methods("POST")
	api.HandleFunc("/hitl/cases/{id}/assign", auth.RequireAccess(pc, "hitl", "write", middleware.RequireValidPathVars("id")(compliance.HandleReassignCase(db, coreClient)))).Methods("POST")
	api.HandleFunc("/hitl/cases/{id}/comments", auth.RequireAccess(pc, "hitl", "read", middleware.RequireValidPathVars("id")(compliance.HandleListCaseComments(db)))).Methods("GET")
	api.HandleFunc("/hitl/cases/{id}/recusal-log", auth.RequireAccess(pc, "hitl", "read", middleware.RequireValidPathVars("id")(compliance.HandleGetRecusalLog(db)))).Methods("GET")
	api.HandleFunc("/hitl/cases/{id}/votes", auth.RequireAccess(pc, "hitl", "read", middleware.RequireValidPathVars("id")(compliance.HandleListHITLVotes(db)))).Methods("GET")
	api.HandleFunc("/hitl/departments/{id}/cases", auth.RequireAccess(pc, "hitl", "read", middleware.RequireValidPathVars("id")(compliance.HandleListCases(db)))).Methods("GET")
	api.HandleFunc("/hitl/jurors/{member_id}/recuse", auth.RequireAccess(pc, "hitl", "write", middleware.RequireValidPathVars("member_id")(compliance.HandleRejectJuror(db)))).Methods("POST")
	api.HandleFunc("/ops/cases/{id}", auth.RequireAccess(pc, "ops", "read", middleware.RequireValidPathVars("id")(compliance.HandleGetCase(db, coreClient)))).Methods("GET")
	api.HandleFunc("/ops/cases/{id}/arbitrate", auth.RequireAccess(pc, "ops", "write", middleware.RequireValidPathVars("id")(compliance.HandleResolveCase(db, nil, coreClient)))).Methods("POST")
	api.HandleFunc("/ops/cases/{id}/assign", auth.RequireAccess(pc, "ops", "write", middleware.RequireValidPathVars("id")(compliance.HandleReassignCase(db, coreClient)))).Methods("POST")
	api.HandleFunc("/ops/cases/{id}/comments", auth.RequireAccess(pc, "ops", "read", middleware.RequireValidPathVars("id")(compliance.HandleListCaseComments(db)))).Methods("GET")
	// /compliance/cases — canonical path; called by state machine (transitions.ts) for case lifecycle.
	api.HandleFunc("/compliance/cases", auth.RequireAccess(pc, "compliance", "read", compliance.HandleListCases(db))).Methods("GET")
	// /compliance/cases/{id} — canonical path; called by transitions.ts for case state transitions.
	api.HandleFunc("/compliance/cases/{id}", auth.RequireAccess(pc, "compliance", "read", middleware.RequireValidPathVars("id")(compliance.HandleGetCase(db, coreClient)))).Methods("GET")
	api.HandleFunc("/cases/leaderboard", auth.RequireAccess(pc, "compliance", "read", compliance.HandleGetCaseLeaderboard(db))).Methods("GET")

	// ── Entropy ───────────────────────────────────────────────────────────────
	api.HandleFunc("/entropy/events", auth.RequireAccess(pc, "analytics", "read", hsecurity.HandleGetEntropyEvents(db))).Methods("GET")
	api.HandleFunc("/entropy/events", auth.RequireAccess(pc, "admin", "write", hsecurity.HandleCreateEntropyEvent(db))).Methods("POST")
	api.HandleFunc("/entropy/events/{id}", auth.RequireAccess(pc, "analytics", "read", middleware.RequireValidPathVars("id")(hsecurity.HandleGetEntropyEvent(db)))).Methods("GET")
	api.HandleFunc("/entropy/events/{id}", auth.RequireAccess(pc, "admin", "write", middleware.RequireValidPathVars("id")(hsecurity.HandleUpdateEntropyEvent(db)))).Methods("PATCH")
	api.HandleFunc("/entropy/events/{id}", auth.RequireAccess(pc, "admin", "delete", middleware.RequireValidPathVars("id")(hsecurity.HandleDeleteEntropyEvent(db)))).Methods("DELETE")
	api.HandleFunc("/entropy/status", auth.RequireAccess(pc, "compliance", "read", hsecurity.HandleGetEntropyStatus(entropyMonitor))).Methods("GET")
	api.HandleFunc("/security/entropy/scan", auth.RequireAccess(pc, "compliance", "write", hsecurity.HandleScanEntropy(entropyMonitor))).Methods("POST")
	api.HandleFunc("/security/entropy/status", auth.RequireAccess(pc, "compliance", "read", hsecurity.HandleGetEntropyStatus(entropyMonitor))).Methods("GET")

	// ── Security ──────────────────────────────────────────────────────────────
	if secMgr != nil {
		api.HandleFunc("/security/attacks", auth.RequireAccess(pc, "compliance", "read", hsecurity.HandleListAttackEvents(secMgr.SybilDetector, secMgr.NonceStore))).Methods("GET")
		api.HandleFunc("/nonce/validations", auth.RequireAccess(pc, "compliance", "write", hsecurity.HandleValidateNonce(secMgr.NonceStore))).Methods("POST")
		api.HandleFunc("/security/nonce/validations", auth.RequireAccess(pc, "compliance", "write", hsecurity.HandleValidateNonce(secMgr.NonceStore))).Methods("POST")
		api.HandleFunc("/sybil/check", auth.RequireAccess(pc, "compliance", "write", hsecurity.HandleCheckSybil(secMgr.SybilDetector, db))).Methods("POST")
		api.HandleFunc("/security/sybil/check", auth.RequireAccess(pc, "compliance", "write", hsecurity.HandleCheckSybil(secMgr.SybilDetector, db))).Methods("POST")
		api.HandleFunc("/security/sybil-check", auth.RequireAccess(pc, "security", "read", hsecurity.HandleCheckSybil(secMgr.SybilDetector, db))).Methods("POST")
	}

	// ── Credentials ───────────────────────────────────────────────────────────
	api.HandleFunc("/credentials", auth.RequireAccess(pc, "compliance", "read", compliance.HandleListCredentials(db))).Methods("GET")
	api.HandleFunc("/credentials", auth.RequireAccess(pc, "compliance", "write", compliance.HandleCreateCredential(db))).Methods("POST")
	api.HandleFunc("/credentials/{id}", auth.RequireAccess(pc, "compliance", "read", middleware.RequireValidPathVars("id")(compliance.HandleGetCredential(db)))).Methods("GET")
	api.HandleFunc("/credentials/{id}", auth.RequireAccess(pc, "compliance", "write", middleware.RequireValidPathVars("id")(compliance.HandleUpdateCredential(db)))).Methods("PATCH")
	api.HandleFunc("/credentials/{id}", auth.RequireAccess(pc, "compliance", "delete", middleware.RequireValidPathVars("id")(compliance.HandleRevokeCredential(db)))).Methods("DELETE")

	// ── Blocklists ────────────────────────────────────────────────────────────
	api.HandleFunc("/blocklists", auth.RequireAccess(pc, "compliance", "read", compliance.HandleListBlocklist(db))).Methods("GET")
	api.HandleFunc("/blocklists", auth.RequireAccess(pc, "compliance", "write", compliance.HandleCreateBlocklistEntry(db))).Methods("POST")
	api.HandleFunc("/blocklist-entry/{id}", auth.RequireAccess(pc, "compliance", "read", middleware.RequireValidPathVars("id")(compliance.HandleGetBlocklistEntry(db)))).Methods("GET")
	api.HandleFunc("/blocklist-entry/{id}", auth.RequireAccess(pc, "compliance", "write", middleware.RequireValidPathVars("id")(compliance.HandleDeleteBlocklistEntry(db)))).Methods("DELETE")
	api.HandleFunc("/blocklist-entry", auth.RequireAccess(pc, "compliance", "write", compliance.HandleCreateBlocklistEntry(db))).Methods("POST")

	// ── Departments ───────────────────────────────────────────────────────────
	// IntentClassifier — uses shared types interface, no Ring 1 import needed
	coreClassifier := types.NewIntentClassifierHTTP(extractorURL)
	api.HandleFunc("/departments/route", auth.RequireAccess(pc, "compliance", "read", compliance.HandleRouteDepartment(db, coreClassifier, coreClient))).Methods("POST")
	api.HandleFunc("/departments/{slug}/overflow-route", auth.RequireAccess(pc, "compliance", "write", compliance.HandleRouteDeptOverflow(db, coreClient))).Methods("POST")
	api.HandleFunc("/departments/{slug}/pre-delete-check", auth.RequireAccess(pc, "compliance", "write", compliance.HandleGuardDeptDeletion(db, coreClient))).Methods("POST")

	// ── Trust attestations ────────────────────────────────────────────────────
	api.HandleFunc("/trust-attestations/{id}", auth.RequireAccess(pc, "compliance", "read", middleware.RequireValidPathVars("id")(compliance.HandleGetTrustAttestation(db)))).Methods("GET")
	api.HandleFunc("/trust-attestations/{id}", auth.RequireAccess(pc, "compliance", "write", middleware.RequireValidPathVars("id")(compliance.HandleUpdateTrustAttestation(db)))).Methods("PATCH")
	api.HandleFunc("/trust-attestations/{id}", auth.RequireAccess(pc, "compliance", "delete", middleware.RequireValidPathVars("id")(compliance.HandleRevokeTrustAttestation(db)))).Methods("DELETE")

	// ── Misc ──────────────────────────────────────────────────────────────────
	api.HandleFunc("/export-jobs", auth.RequireAccess(pc, "admin", "read", compliance.HandleGetCaseExportJob(db))).Methods("GET")
	api.HandleFunc("/compliance/siem/config", auth.RequireAccess(pc, "compliance", "read", compliance.HandleGetComplianceSIEMConfig(db))).Methods("GET")
	api.HandleFunc("/compliance/siem/config", auth.RequireAccess(pc, "compliance", "write", compliance.HandleUpdateComplianceSIEMConfig(db))).Methods("PUT")
	api.HandleFunc("/compliance/siem/config", auth.RequireAccess(pc, "compliance", "delete", compliance.HandleDeleteSIEMConfig(db))).Methods("DELETE")
	api.HandleFunc("/compliance/siem/test", auth.RequireAccess(pc, "compliance", "write", compliance.HandleTestSIEMWebhook(db))).Methods("POST")
	api.HandleFunc("/compliance/siem", auth.RequireAccess(pc, "compliance", "read", compliance.HandleGetComplianceSIEMConfig(db))).Methods("GET")
	api.HandleFunc("/compliance/siem", auth.RequireAccess(pc, "compliance", "write", compliance.HandleUpdateComplianceSIEMConfig(db))).Methods("PUT")
	api.HandleFunc("/compliance/siem", auth.RequireAccess(pc, "compliance", "write", compliance.HandleUpdateComplianceSIEMConfig(db))).Methods("POST")

	// ── COMP-P1: EU AI Act Article 13 — Formal Regulatory Report ─────────────
	// GET  /compliance/regulatory/eu-ai-act/report        → generate DRAFT report artefact
	// POST /compliance/regulatory/eu-ai-act/report/submit → file (immutable FILED state)
	// GET  /compliance/regulatory/eu-ai-act/report/{id}   → retrieve saved report
	//
	// Ref: EU AI Act (Reg. (EU) 2024/1689) Art.13, Art.43, Art.47, Art.71.
	// Penalty: up to €30M or 6% global annual turnover.
	api.HandleFunc("/compliance/regulatory/eu-ai-act/report",
		auth.RequireAccess(pc, "compliance", "write", regulatory.HandleGenerateEUAIActReport(db, coreClient))).Methods("GET")
	api.HandleFunc("/compliance/regulatory/eu-ai-act/reports",
		auth.RequireAccess(pc, "compliance", "write", regulatory.HandleSubmitEUAIActReport(db))).Methods("POST")
	api.HandleFunc("/compliance/regulatory/eu-ai-act/report/{id}",
		auth.RequireAccess(pc, "compliance", "read",
			middleware.RequireValidPathVars("id")(regulatory.HandleGetEUAIActReport(db)))).Methods("GET")

	// ── Compliance Report CRUD (gap-audit 2026-08-30) ─────────────────────────
	// Frontend calls /compliance-report/{id} (singular) — these were 404.
	api.HandleFunc("/compliance-report/{id}",
		auth.RequireAccess(pc, "compliance", "read",
			middleware.RequireValidPathVars("id")(reports.HandleGetComplianceReport(db)))).Methods("GET")
	api.HandleFunc("/compliance-report/{id}/execute",
		auth.RequireAccess(pc, "compliance", "write",
			middleware.RequireValidPathVars("id")(reports.HandleExecuteComplianceReport(db)))).Methods("POST")
	api.HandleFunc("/compliance-report/{id}/schedule",
		auth.RequireAccess(pc, "compliance", "write",
			middleware.RequireValidPathVars("id")(reports.HandleScheduleComplianceReport(db)))).Methods("POST")

	// ── Cases (create + assign) ───────────────────────────────────────────────
	// HandleCreateCase requires psBroker for pub/sub publishing — pass nil for
	// services that don't run a broker (graceful degradation: event is skipped).
	api.HandleFunc("/compliance/cases",
		auth.RequireAccess(pc, "compliance", "write",
			compliance.HandleCreateCase(db, nil, coreClient))).Methods("POST")
	api.HandleFunc("/compliance/cases/{id}/assign",
		auth.RequireAccess(pc, "compliance", "write",
			middleware.RequireValidPathVars("id")(compliance.HandleAssignCase(db, coreClassifier)))).Methods("POST")
	api.HandleFunc("/compliance/cases/{id}/merge",
		auth.RequireAccess(pc, "compliance", "write",
			middleware.RequireValidPathVars("id")(compliance.HandleMergeCase(db)))).Methods("POST")
	api.HandleFunc("/compliance/cases/{id}/jury-vote",
		auth.RequireAccess(pc, "compliance", "write",
			middleware.RequireValidPathVars("id")(compliance.HandleCasesSubmitJuryVote(db, coreClient)))).Methods("POST")

	// ── Bulk HITL Resolution ──────────────────────────────────────────────────
	api.HandleFunc("/hitl/bulk-resolve",
		auth.RequireAccess(pc, "hitl", "write",
			compliance.HandleResolveBulkHITL(db, coreClient))).Methods("POST")

	// ── Dispute Update ────────────────────────────────────────────────────────
	api.HandleFunc("/compliance/disputes/{id}",
		auth.RequireAccess(pc, "compliance", "write",
			middleware.RequireValidPathVars("id")(compliance.HandleUpdateDispute(db)))).Methods("PUT")

	// ── Credential Delete ─────────────────────────────────────────────────────
	api.HandleFunc("/compliance/credentials/{id}",
		auth.RequireAccess(pc, "compliance", "delete",
			middleware.RequireValidPathVars("id")(compliance.HandleDeleteCredential(db)))).Methods("DELETE")

	// ── Case and Decision Timelines ───────────────────────────────────────────
	api.HandleFunc("/compliance/cases/{id}/timeline",
		auth.RequireAccess(pc, "compliance", "read",
			middleware.RequireValidPathVars("id")(compliance.HandleGetCaseTimeline(db)))).Methods("GET")
	api.HandleFunc("/compliance/decisions/{id}/timeline",
		auth.RequireAccess(pc, "compliance", "read",
			middleware.RequireValidPathVars("id")(compliance.HandleGetDecisionTimeline(db)))).Methods("GET")

	// ── GRA Risk Configs List ─────────────────────────────────────────────────
	api.HandleFunc("/gra/risk-configs",
		auth.RequireAccess(pc, "compliance", "read",
			compliance.HandleListGRARiskConfigs(db))).Methods("GET")

	// ── Admin: Parsed Documents ───────────────────────────────────────────────
	api.HandleFunc("/admin/parsed-documents",
		auth.RequireAccess(pc, "compliance", "read",
			compliance.HandleAdminListParsedDocuments(db))).Methods("GET")

	// ── compliance.compliance_cases — investigative case store (C1 FIX 2026-09-04) ──
	// DISTINCT from /compliance/cases which backs core_hitl (HITL decisions in ocx-core-svc).
	// These routes manage the compliance-module's own investigation case tracking.
	api.HandleFunc("/compliance/investigation-cases",
		auth.RequireAccess(pc, "compliance", "read",
			compliance.HandleListComplianceCases(db))).Methods("GET")
	api.HandleFunc("/compliance/investigation-cases",
		auth.RequireAccess(pc, "compliance", "write",
			compliance.HandleCreateComplianceCase(db))).Methods("POST")
	api.HandleFunc("/compliance/investigation-cases/{id}",
		auth.RequireAccess(pc, "compliance", "read",
			middleware.RequireValidPathVars("id")(compliance.HandleGetComplianceCase(db)))).Methods("GET")
	api.HandleFunc("/compliance/investigation-cases/{id}/status",
		auth.RequireAccess(pc, "compliance", "write",
			middleware.RequireValidPathVars("id")(compliance.HandleUpdateComplianceCaseStatus(db)))).Methods("PATCH")
	api.HandleFunc("/compliance/investigation-cases/{id}/assign",
		auth.RequireAccess(pc, "compliance", "write",
			middleware.RequireValidPathVars("id")(compliance.HandleAssignComplianceCase(db)))).Methods("POST")
	api.HandleFunc("/compliance/investigation-cases/{id}/comments",
		auth.RequireAccess(pc, "compliance", "write",
			middleware.RequireValidPathVars("id")(compliance.HandleAddComplianceCaseComment(db)))).Methods("POST")
}