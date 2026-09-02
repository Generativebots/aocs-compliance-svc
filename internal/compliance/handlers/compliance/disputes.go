// Package compliance — Disputes CRUD + Cases namespace aliases.
//
// Disputes (core_disputes): Tenant-initiated formal objections against
// enforcement decisions, HITL verdicts, or trust-tax assessments.
//
// Business context (CIP-1 / Patent Claim 3):
//
//	When the QCore Gate blocks an agent action (verdict = BLOCK) or the
//	IA enforcement engine raises a VIOLATION, the affected tenant can file
//	a Dispute. Disputes feed back into the GRA (Governance & Risk Assessment)
//	loop — sustained dispute rates trigger automatic policy relaxation via the
//	Self-Heal Advisor (CIP-2, governance/self_heal.go).
//
// CRITICAL DESIGN RULE — Enforcement-Driven Record Creation:
//
//	core_hitl and core_enforcement_actions rows are NEVER created
//	by REST handlers directly. They are created by:
//	  1. workflow/enforcement.go::PoliceExecution() — called on every agent
//	     activity execution; creates HITL cases + enforcement actions on
//	     VIOLATION / ESCALATE verdicts. (Claims 4, 6, 8)
//	  2. governance/gate.go — QCore Gate creates core_events audit
//	     rows on every verdict and publishes to Pub/Sub aocs.cases.escalated.
//	     The Python jury subscriber creates HITL decisions downstream.
//	  3. operations/human_review.go::HandleHITLDecide — human reviewer
//	     submitting a verdict creates the final core_hitl record.
//
//	REST lifecycle actions (close, appeal, assign, comment) are in:
//	  operations/human_review_actions.go (HandleCloseCase, HandleAppealDecision,
//	                                      HandleOpsAssignCase, HandleOpsAddCaseComment)
//	DO NOT duplicate those here.
//
// Tables owned by this file:
//
//	core_disputes  (PK: dispute_id)  — full CRUD
//	core_hitl              — READ-ONLY aliases for the cases/* namespace
//	aocs_jury_pools                  — READ-ONLY leaderboard
package compliance

import (
	"log/slog"
	"net/http"
	"time"
	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

// HandleListDisputes returns all disputes for the calling tenant.
// GET /api/v1/disputes
func HandleListDisputes(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var rows []map[string]any
		if err := db.QueryRowsCtx(r.Context(), database.TblComplianceCases,
			"case_id,tenant_id,agent_id,case_type,reason,status,evidence_url,created_at,resolved_at",
			"tenant_id", tenantID, &rows); err != nil {
			slog.Error("HandleListDisputes: query failed", "tenant_id", tenantID, "error", err)
			rows = []map[string]any{}
		}
		if rows == nil {
			rows = []map[string]any{}
		}
		respond.OK(w, map[string]any{"disputes": rows, "total": len(rows)})
	}
}

// HandleGetDispute returns a single dispute by ID.
// GET /api/v1/disputes/{id}
func HandleGetDispute(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		id := mux.Vars(r)["id"]
		if id == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing dispute id")
			return
		}
		var rows []map[string]any
		if err := db.QueryRowsCompound(database.TblComplianceCases,
			"case_id,tenant_id,agent_id,case_type,reason,status,evidence_url,created_at,resolved_at",
			"dispute_id", id, "tenant_id", tenantID, &rows); err != nil || len(rows) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "dispute not found")
			return
		}
		respond.OK(w, rows[0])
	}
}

// HandleCreateDispute opens a new dispute against an enforcement decision.
// POST /api/v1/disputes
//
// CIP-1: Each dispute is linked to a case_id (core_hitl.decision_id).
// The case is created upstream by the enforcement engine (workflow/enforcement.go)
// or the QCore Gate (governance/gate.go) — never by this handler.
// Sustained dispute volume (>15% of decisions) triggers the self-heal advisor
// to propose policy threshold relaxation (see governance/self_heal.go).
func HandleCreateDispute(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		respond.LimitBody(r)
		var body CreateDisputeRequest
		respond.LimitBody(r)
		if !validate.Bind(w, r, &body) {
			return
		}
		if body.CaseID == "" || body.Reason == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "case_id and reason are required")
			return
		}
		disputeID := generatePlatformID()
		now := time.Now().UTC().Format(time.RFC3339)
		if err := db.InsertRow(database.TblComplianceCases, map[string]any{
			"dispute_id":   disputeID,
			"tenant_id":    tenantID,
			"case_id":      body.CaseID,
			"agent_id":     body.AgentID,
			"reason":       body.Reason,
			"evidence_url": body.EvidenceURL,
			"status":       "OPEN",
			"created_at":   now,
		}); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "create dispute", err)
			return
		}
		respond.JSON(w, http.StatusCreated, map[string]any{
			"dispute_id": disputeID, "status": "OPEN", "case_id": body.CaseID,
		})
	}
}

// HandleResolveDispute closes a dispute with a resolution verdict.
// POST /api/v1/disputes/{id}/resolve
//
// Resolution verdicts: UPHELD (enforcement decision stands) | OVERTURNED (decision reversed).
// OVERTURNED disputes trigger a re-evaluation of the linked HITL case.
func HandleResolveDispute(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		id := mux.Vars(r)["id"]
		if id == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing dispute id")
			return
		}
		respond.LimitBody(r)
		var body struct {
			Verdict    string `json:"verdict"`    // UPHELD | OVERTURNED
			Resolution string `json:"resolution"` // human-readable explanation
		}
		respond.LimitBody(r)
		if !validate.Bind(w, r, &body) {
			return
		}
		if body.Verdict != "UPHELD" && body.Verdict != "OVERTURNED" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "verdict must be UPHELD or OVERTURNED")
			return
		}
		now := time.Now().UTC().Format(time.RFC3339)
		// Verify ownership + current status before mutation
		var existing []map[string]any
		if err := db.QueryRowsCompound(database.TblComplianceCases, "dispute_id,tenant_id,status",
			"dispute_id", id, "tenant_id", tenantID, &existing); err != nil || len(existing) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "dispute not found")
			return
		}
		if s, _ := existing[0]["status"].(string); s != "OPEN" {
			respond.ErrorWithCode(w, http.StatusConflict, respond.ErrCodeConflict, "only OPEN disputes can be resolved (current: "+s+")")
			return
		}
		if err := db.UpdateRowCompound(database.TblComplianceCases, "dispute_id", id, "tenant_id", tenantID, map[string]any{
			"status":            body.Verdict,
			"resolution":        body.Resolution,
			"resolved_at":       now,
		}); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "resolve dispute", err)
			return
		}
		slog.Info("HandleResolveDispute: resolved", "dispute_id", id, "verdict", body.Verdict, "tenant_id", tenantID)
		respond.OK(w, map[string]any{
			"dispute_id": id, "verdict": body.Verdict, "resolved_at": now,
		})
	}
}

// HandleDeleteDispute soft-deletes a dispute (WITHDRAWN state).
// DELETE /api/v1/disputes/{id}
func HandleDeleteDispute(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		id := mux.Vars(r)["id"]
		if id == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing dispute id")
			return
		}
		// Verify tenant ownership
		var existing []map[string]any
		if err := db.QueryRowsCompound(database.TblComplianceCases, "dispute_id,tenant_id",
			"dispute_id", id, "tenant_id", tenantID, &existing); err != nil || len(existing) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "dispute not found")
			return
		}
		if err := db.UpdateRowCompound(database.TblComplianceCases, "dispute_id", id, "tenant_id", tenantID, map[string]any{
			"status":            "WITHDRAWN",
			"resolved_at":       time.Now().UTC().Format(time.RFC3339),
		}); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "withdraw dispute", err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// ─── Cases Namespace Aliases ──────────────────────────────────────────────────
// These handlers are READ-ONLY views over core_hitl. They provide
// the /cases/* namespace for the JARVIS HUD frontend. Record creation in
// core_hitl is exclusively owned by the enforcement engine
// (workflow/enforcement.go) and the gate (governance/gate.go).

// HandleGetCaseLeaderboard returns jury reviewer performance metrics.
// GET /api/v1/cases/leaderboard
//
// Leaderboard data drives the HITL gamification layer — reviewers with
// consistently high accuracy scores are weighted more heavily in jury pools.
// Source: aocs_jury_pools.total_votes + accuracy_score columns.
func HandleGetCaseLeaderboard(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var rows []map[string]any
		if err := db.QueryRowsCtx(r.Context(), database.TblJuryPools,
			"jury_pool_id,jury_id,reviewer_id,total_votes,accuracy_score,response_time_avg,last_active_at",
			"tenant_id", tenantID, &rows); err != nil {
			rows = []map[string]any{}
		}
		if rows == nil {
			rows = []map[string]any{}
		}
		respond.OK(w, map[string]any{"leaderboard": rows, "total": len(rows)})
	}
}
