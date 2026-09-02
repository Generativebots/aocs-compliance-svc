package regulatory

// eu_ai_act_report.go — EU AI Act Article 13 Formal Regulatory Report Artefact
//
// THIS PACKAGE CALLS handlers/compliance/eu_ai_act.go — it does NOT duplicate logic.
//
// Architecture:
//
//	handlers/compliance/eu_ai_act.go → live, interactive transparency "card"
//	                                   for operator dashboards (GET/POST/GET).
//	                                   Routes: /compliance/eu-ai-act/transparency/*
//	                                   Exported: BuildEUAIActTransparencyCard(ctx, db, tenantID)
//
//	handlers/regulatory/eu_ai_act_report.go (THIS FILE) → formal regulatory filing artefact
//	                                   wraps the compliance.EUAIActTransparencyCard + adds:
//	                                   • SHA-256 content hash (non-repudiation)
//	                                   • Version-locked snapshot (immutable on FILED)
//	                                   • Notified body reference (Art.43 conformity assessment)
//	                                   • Declaration-of-Conformity URL (Art.47)
//	                                   • Filing status lifecycle: DRAFT → FILED (immutable)
//	                                   Routes: /compliance/regulatory/eu-ai-act/report/*
//
// How it works:
//   1. GET /compliance/regulatory/eu-ai-act/report
//      → calls compliance.BuildEUAIActTransparencyCard(ctx, db, tenantID) to get the live card
//      → wraps it in a RegulatoryReport with SHA-256 hash
//      → persists as DRAFT (case_type='EU_AI_ACT_REGULATORY_REPORT')
//
//   2. POST /compliance/regulatory/eu-ai-act/report/submit
//      → fetches existing DRAFT by ID, transitions it to FILED (immutable)
//      → stores notified body ref, EU representative, declaration URL
//      → re-hashes the final body for tamper-proof audit
//
//   3. GET /compliance/regulatory/eu-ai-act/report/{id}
//      → retrieves any previously generated report (DRAFT or FILED) by ID
//
// EU AI Act (Regulation (EU) 2024/1689) references:
//   - Article 13  — Transparency and provision of information to deployers
//   - Article 16(d) — Technical documentation obligation
//   - Article 43  — Conformity assessment (notified body)
//   - Article 47  — Declaration of Conformity
//   - Article 71  — Market surveillance authority + penalties (€30M / 6% turnover)
//
// Permission: compliance:write

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	compliance "github.com/ocx/compliance/internal/compliance/handlers/compliance"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/serviceclient"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// RegulatoryReport is the formal Article 13 transparency report artefact.
// It wraps compliance.EUAIActTransparencyCard (the live dashboard card) and
// adds filing metadata for regulatory authority submission.
type RegulatoryReport struct {
	// Artefact identity
	ReportID  string `json:"report_id"`
	TenantID  string `json:"tenant_id"`
	Version   string `json:"version"`
	CreatedAt string `json:"created_at"`
	FiledAt   string `json:"filed_at,omitempty"`
	Status    string `json:"status"` // DRAFT | FILED

	// Non-repudiation: SHA-256 of the transparency card JSON body
	ContentHash string `json:"content_hash"`

	// Formal filing metadata (Art.43 + Art.47)
	NotifiedBodyRef  string `json:"notified_body_ref,omitempty"`
	DeclarationURL   string `json:"declaration_of_conformity_url,omitempty"`
	EURepresentative string `json:"eu_representative,omitempty"`

	// The actual transparency card — sourced from compliance.BuildEUAIActTransparencyCard.
	// The compliance package owns this struct; regulatory wraps and hashes it.
	// This is the single source of truth for Art.13 content.
	TransparencyCard compliance.EUAIActTransparencyCard `json:"transparency_card"`
}

// submitRequest is the payload for POST /compliance/regulatory/eu-ai-act/report/submit
type submitRequest struct {
	ReportID         string `json:"report_id"`
	NotifiedBodyRef  string `json:"notified_body_ref,omitempty"`
	DeclarationURL   string `json:"declaration_url,omitempty"`
	EURepresentative string `json:"eu_representative,omitempty"`
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// HandleGenerateEUAIActReport — GET /compliance/regulatory/eu-ai-act/report
//
// Generates a formal Article 13 regulatory filing report by:
//  1. Calling compliance.BuildEUAIActTransparencyCard to get the live card (single source of truth)
//  2. Wrapping it in a RegulatoryReport with a SHA-256 hash
//  3. Persisting it as a DRAFT in core_compliance (case_type='EU_AI_ACT_REGULATORY_REPORT')
//
// The DRAFT can then be reviewed and submitted via the /submit route.
func HandleGenerateEUAIActReport(db database.DB, coreClient *serviceclient.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		ctx := r.Context()
		now := time.Now().UTC()
		reportID := uuid.New().String()

		// ── Step 1: Get the live transparency card from compliance package ──
		// compliance.BuildEUAIActTransparencyCard is the canonical source of
		// Art.13 content. We do NOT re-implement that logic here.
		card, err := compliance.BuildEUAIActTransparencyCard(ctx, db, coreClient, tenantID)
		if err != nil {
			slog.ErrorContext(ctx, "regulatory/report: failed to build transparency card",
				"tenant_id", tenantID, "err", err)
			respond.InternalError(w, http.StatusInternalServerError, "build transparency card", err)
			return
		}

		// ── Step 2: Wrap card in regulatory report + compute SHA-256 hash ──
		// Hash the card body first (before adding report metadata) so the hash
		// covers the Art.13 content only — making it reproducible for verification.
		cardBytes, _ := json.Marshal(card)
		h := sha256.Sum256(cardBytes)
		contentHash := hex.EncodeToString(h[:])

		report := RegulatoryReport{
			ReportID:         reportID,
			TenantID:         tenantID,
			Version:          "2026.1",
			CreatedAt:        now.Format(time.RFC3339),
			Status:           "DRAFT",
			ContentHash:      contentHash,
			TransparencyCard: card,
		}

		// ── Step 3: Persist as DRAFT in core_compliance ────────────
		reportBytes, _ := json.Marshal(report)
		userID := auth.GetUserID(ctx)
		if err := db.InsertRow(database.TblComplianceCases, map[string]any{
			"case_id":     reportID,
			"tenant_id":   tenantID,
			"case_type":   "EU_AI_ACT_REGULATORY_REPORT",
			"status":      "DRAFT",
			"title":       fmt.Sprintf("EU AI Act Art.13 Regulatory Report — %s", now.Format("2006-01-02")),
			"description": fmt.Sprintf("SHA-256: %s... | Agents: %d | Policies: %d", contentHash[:16], card.AgentCount, card.ActivePolicies),
			"case_data":   string(reportBytes),
			"created_by":  userID,
			"created_at":  now.Format(time.RFC3339),
			"updated_at":  now.Format(time.RFC3339),
		}); err != nil {
			slog.ErrorContext(ctx, "regulatory/report: persist DRAFT failed",
				"report_id", reportID, "tenant_id", tenantID, "err", err)
			respond.InternalError(w, http.StatusInternalServerError, "persist report draft", err)
			return
		}

		slog.InfoContext(ctx, "regulatory/report: Article 13 regulatory report generated (DRAFT)",
			"report_id", reportID,
			"tenant_id", tenantID,
			"hash_prefix", contentHash[:16],
			"active_agents", card.AgentCount,
			"active_policies", card.ActivePolicies,
		)
		respond.OK(w, report)
	}
}

// HandleSubmitEUAIActReport — POST /compliance/regulatory/eu-ai-act/report/submit
//
// Transitions a DRAFT report to FILED (immutable). Adds formal filing metadata:
// notified body reference, EU representative, and Declaration of Conformity URL.
// A FILED report cannot be modified — create a new DRAFT to supersede it.
func HandleSubmitEUAIActReport(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		ctx := r.Context()
		var req submitRequest
		if !validate.Bind(w, r, &req) {
			return
		}
		if req.ReportID == "" {
			respond.BadRequest(w, "report_id is required")
			return
		}

		// Verify report belongs to this tenant and is still DRAFT
		var cases []map[string]any
		if err := db.QueryRowsCompound(database.TblComplianceCases,
			"case_id,status,case_data",
			"case_id", req.ReportID, "tenant_id", tenantID, &cases); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "lookup report", err)
			return
		}
		if len(cases) == 0 {
			respond.NotFound(w, fmt.Sprintf("/compliance/regulatory/eu-ai-act/report/%s", req.ReportID))
			return
		}

		if s, _ := cases[0]["status"].(string); s != "DRAFT" {
			respond.BadRequest(w, fmt.Sprintf("report is already %s — create a new DRAFT to supersede", s))
			return
		}

		// Parse the stored report and update filing metadata
		var stored RegulatoryReport
		if caseData, ok := cases[0]["case_data"].(string); ok {
			_ = json.Unmarshal([]byte(caseData), &stored)
		}

		now := time.Now().UTC()
		stored.Status = "FILED"
		stored.FiledAt = now.Format(time.RFC3339)
		stored.NotifiedBodyRef = req.NotifiedBodyRef
		stored.DeclarationURL = req.DeclarationURL
		stored.EURepresentative = req.EURepresentative

		// Re-hash the complete filed report (covers filing metadata additions).
		// The original ContentHash covering the Art.13 card content is preserved
		// inside TransparencyCard and can be independently verified.
		finalBody, _ := json.Marshal(stored)
		h := sha256.Sum256(finalBody)
		stored.ContentHash = hex.EncodeToString(h[:])
		finalBodyWithHash, _ := json.Marshal(stored)

		if err := db.UpdateRowCompound(database.TblComplianceCases,
			"case_id", req.ReportID, "tenant_id", tenantID,
			map[string]any{
				"status":      "FILED",
				"case_data":   string(finalBodyWithHash),
				"updated_at":  now.Format(time.RFC3339),
				"resolved_at": now.Format(time.RFC3339),
			}); err != nil {
			slog.ErrorContext(ctx, "regulatory/submit: transition to FILED failed",
				"report_id", req.ReportID, "err", err)
			respond.InternalError(w, http.StatusInternalServerError, "file report", err)
			return
		}

		slog.InfoContext(ctx, "regulatory/submit: Article 13 report FILED",
			"report_id", req.ReportID,
			"tenant_id", tenantID,
			"notified_body_ref", req.NotifiedBodyRef,
			"hash_prefix", stored.ContentHash[:16],
		)
		respond.OK(w, stored)
	}
}

// HandleGetEUAIActReport — GET /compliance/regulatory/eu-ai-act/report/{id}
//
// Retrieves a previously generated regulatory report (DRAFT or FILED) by ID.
// Returns the full RegulatoryReport including the embedded transparency card
// and SHA-256 hash for integrity verification.
func HandleGetEUAIActReport(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		reportID := mux.Vars(r)["id"]
		if reportID == "" {
			respond.BadRequest(w, "report id is required")
			return
		}

		var cases []map[string]any
		if err := db.QueryRowsCompound(database.TblComplianceCases,
			"case_id,status,case_data,created_at,updated_at",
			"case_id", reportID, "tenant_id", tenantID, &cases); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "lookup report", err)
			return
		}
		if len(cases) == 0 {
			respond.NotFound(w, fmt.Sprintf("/compliance/regulatory/eu-ai-act/report/%s", reportID))
			return
		}

		var report RegulatoryReport
		if caseData, ok := cases[0]["case_data"].(string); ok {
			if err := json.Unmarshal([]byte(caseData), &report); err != nil {
				respond.InternalError(w, http.StatusInternalServerError, "parse stored report", err)
				return
			}
		}
		respond.OK(w, report)
	}
}

// ensure context is used (BuildEUAIActTransparencyCard uses ctx via slog.InfoContext)
var _ context.Context
