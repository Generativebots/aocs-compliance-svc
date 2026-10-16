// Package compliance — HITL / edge-case resolution handlers.
//
// Gathers: Cases, ZKP (chain, export, batch), Ledger Root, SIEM config, Report Export.
package compliance

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/serviceclient"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

func HandleGetCaseExportJob(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var rows []map[string]any
		// PK on aocs_bulk_import_jobs (TblCoreJobs) is job_id, not nexus_export_job_id.
		if err := db.QueryRowsCompound(database.TblCoreJobs, database.ColsNexusExportJobs, "job_id", mux.Vars(r)["id"], "tenant_id", tenantID, &rows); err != nil || len(rows) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "export job not found")
			return
		}
		respond.OK(w, rows[0])
	}
}

// POST /api/v1/hitl/cases/{id}/merge
// Merges a child HITL case into a parent, consolidating decisions and reasons.

func HandleMergeCase(db database.DB, coreClients ...*serviceclient.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		childID := mux.Vars(r)["id"]
		if childID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}
		var body struct {
			ParentCaseID      string   `json:"parent_case_id"`
			AdditionalReasons []string `json:"additional_reasons"`
		}
		respond.LimitBody(r)
		if !validate.Bind(w, r, &body) {
			return
		}
		if body.ParentCaseID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "parent_case_id required")
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if childID == body.ParentCaseID {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "cannot merge a case into itself")
			return
		}

		cc := hitlCore(coreClients...)
		if !requireHITLCore(w, cc) {
			return
		}
		// Verify parent case exists and belongs to the same tenant
		parent, err := cc.FetchHITLCase(r.Context(), tenantID, body.ParentCaseID, "decision_id,status")
		if err != nil {
			if errors.Is(err, serviceclient.ErrHITLNotFound) {
				respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "parent case not found")
				return
			}
			writeHITLCoreErr(w, err, "merge case")
			return
		}
		if ps, _ := parent["status"].(string); ps == "MERGED" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "cannot merge into a case that is already merged")
			return
		}

		update := map[string]any{
			"parent_case_id":     body.ParentCaseID,
			"additional_reasons": body.AdditionalReasons,
			"status":             "MERGED",
		}
		if err := cc.PatchHITLCaseIf(r.Context(), tenantID, childID, update, nil, []string{"MERGED"}); err != nil {
			writeHITLCoreErr(w, err, "merge case")
			return
		}
		respond.OK(w, map[string]any{
			"child_case_id": childID, "parent_case_id": body.ParentCaseID, "status": "MERGED",
		})
	}
}

// HandleCasesSubmitJuryVote casts a per-reviewer jury vote with industry-standard
// quorum enforcement (Byzantine fault tolerance principles).
//
// POST /api/v1/hitl/cases/{id}/vote
//
// Quorum invariants:
//   - Minimum panel size: 5 jurors (configurable via decision_data.quorum_threshold,
//     floor-clamped to 5 — never less).
//   - Odd-only enforcement: even thresholds are rejected to prevent tied outcomes.
//   - Supermajority: >65% of total votes cast must agree for resolution.
//     A bare majority (51%) is insufficient for compliance decisions.
//   - ABSTAIN votes count toward total cast but NOT toward approve/reject tallies.
//     This prevents abstention from artificially inflating majority ratios.
//
// Dual-write strategy (Batch 8):
//  1. INSERT normalised row into core_hitl_votes (durable, GROUP BY tally).
//  2. UPDATE core_hitl.decision_data JSONB for fast reads / quorum check.
//
// UNIQUE (case_id, voter_id) on core_hitl_votes prevents double-voting;
// returns 409 Conflict on duplicate.
func HandleCasesSubmitJuryVote(db database.DB, coreClient *serviceclient.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDBWrite(w, db) {
			return
		}
		caseID := mux.Vars(r)["id"]

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		respond.LimitBody(r)
		var body CasesSubmitJuryVoteRequest
		// (BATCH): removed duplicate LimitBody — double-wrapping halves max body size
		if !validate.Bind(w, r, &body) {
			return
		}
		if caseID == "" {
			caseID = body.CaseID
		}
		decision := body.Decision
		if decision == "" {
			decision = body.Verdict
		}
		// Industry standard: no implicit default decision.
		// A vote without an explicit decision is invalid — never silently APPROVE.
		if decision == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "decision is required (APPROVE, REJECT, or ABSTAIN)")
			return
		}
		// Normalise to DB CHECK values
		switch decision {
		case "APPROVED":
			decision = "APPROVE"
		case "REJECTED":
			decision = "REJECT"
		case "ABSTAINED":
			decision = "ABSTAIN"
		}
		// Validate decision is a known enum value
		switch decision {
		case "APPROVE", "REJECT", "ABSTAIN":
			// valid
		default:
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "decision must be APPROVE, REJECT, or ABSTAIN")
			return
		}

		if body.VoterID == "" {
			body.VoterID = body.MemberID
		}
		if body.VoterID == "" {
			body.VoterID = auth.GetUserID(r.Context())
		}
		if caseID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "case_id is required (path param or body field)")
			return
		}
		if body.VoterID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "voter_id is required")
			return
		}

		// Quorum rules (min panel 5, odd-only, >65% supermajority, deadlock escalation) and the
		// core_hitl_votes / core_hitl writes live in ocx-core-svc; one transaction there.
		cc := hitlCore(coreClient)
		if !requireHITLCore(w, cc) {
			return
		}
		res, err := cc.CastHITLVote(r.Context(), tenantID, caseID, map[string]any{
			"voter_id":   body.VoterID,
			"decision":   decision,
			"confidence": body.Confidence,
			"rationale":  body.Rationale,
		})
		if err != nil {
			slog.Error("HandleCasesSubmitJuryVote: core vote failed", "case_id", caseID, "voter_id", body.VoterID, "error", err)
			writeHITLCoreErr(w, err, "submit vote")
			return
		}
		slog.Info("jury vote cast", "case_id", caseID, "tenant", tenantID, "voter", body.VoterID,
			"decision", decision, "status", res["status"], "quorum_reached", res["quorum_reached"])
		respond.JSON(w, http.StatusOK, res)
	}
}

// HandleListHITLVotes returns all per-reviewer votes for a case.
// GET /hitl/cases/{id}/votes
//
// Reads from core_hitl_votes (Batch 8). Frontend uses this for the
// quorum tally panel (GROUP BY decision done client-side or via SQL VIEW).
func HandleListHITLVotes(db database.DB, coreClients ...*serviceclient.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		caseID := mux.Vars(r)["id"]
		if caseID == "" {
			caseID = mux.Vars(r)["case_id"]
		}
		if caseID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing case id")
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		cc := hitlCore(coreClients...)
		if !requireHITLCore(w, cc) {
			return
		}
		out, err := cc.ListHITLVotes(r.Context(), tenantID, caseID)
		if err != nil {
			slog.Error("ListHITLVotes failed", "case_id", caseID, "error", err)
			writeHITLCoreErr(w, err, "list votes")
			return
		}
		respond.OK(w, out)
	}
}

// POST /api/v1/hitl/cases/{id}/escalate
// Escalates a HITL case to the jury pool for multi-agent review.
// Sets status to ESCALATED and records escalation metadata in context_data.
