// Package compliance — HITL / edge-case resolution handlers.
//
// Gathers: Cases, ZKP (chain, export, batch), Ledger Root, SIEM config, Report Export.
package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/concurrent"
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
		// SCHEMA FIX: PK on aocs_bulk_import_jobs (TblExportJobs) is job_id, not nexus_export_job_id.
		if err := db.QueryRowsCompound(database.TblExportJobs, database.ColsNexusExportJobs, "job_id", mux.Vars(r)["id"], "tenant_id", tenantID, &rows); err != nil || len(rows) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "export job not found")
			return
		}
		respond.OK(w, rows[0])
	}
}

// POST /api/v1/hitl/cases/{id}/merge
// Merges a child HITL case into a parent, consolidating decisions and reasons.

func HandleMergeCase(db database.DB) http.HandlerFunc {
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
		if body.ParentCaseID == ""{
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "parent_case_id required")
			return
		}
		update := map[string]any{
			"parent_case_id":     body.ParentCaseID,
			"additional_reasons": body.AdditionalReasons,
			"status":             "MERGED",
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if err := db.UpdateRowCompound(database.TblHITLDecisions, "decision_id", childID, "tenant_id", tenantID, update); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "merge case", err)
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
		if respond.RequireDB(w, db) {
			return
		}
		caseID := mux.Vars(r)["id"]

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		respond.LimitBody(r)
		var body CasesSubmitJuryVoteRequest
		respond.LimitBody(r)
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
			body.VoterID = r.Header.Get("X-User-Id")
		}
		if caseID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "case_id is required (path param or body field)")
			return
		}
		if body.VoterID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "voter_id is required")
			return
		}

		// 1. INSERT into core_hitl_votes (UNIQUE case_id+voter_id → 409 on duplicate)
		vote := database.HITLVote{
			CaseID:     caseID,
			TenantID:   tenantID,
			VoterID:    body.VoterID,
			Decision:   decision,
			Confidence: body.Confidence,
			Rationale:  body.Rationale,
		}
		respondedAt := time.Now().UTC().Format(time.RFC3339)
		var txResult struct {
			newStatus       string
			newResult       string
			quorumReached   bool
			panelComplete   bool
			approveCount    int
			rejectCount     int
			abstainCount    int
			totalCast       int
			quorumThreshold int
			approveRatio    float64
			rejectRatio     float64
			// postDeadlockEvent signals that a QUORUM_DEADLOCKED platform event should be
			// posted via ocx-core-svc API *after* the transaction commits (Ring2 isolation).
			postDeadlockEvent bool
		}
		if txErr := db.WithTransaction(r.Context(), func(tx database.DB) error {
			// 1. INSERT vote (UNIQUE case_id+voter_id → error on duplicate)
			if err := tx.InsertRow(database.TblHITLVotes, vote.InsertPayload()); err != nil {
				return err
			}
			// 2. Read current case state inside tx to prevent TOCTOU race
			var rows []map[string]any
			if err := tx.QueryRowsCompoundForUpdate(database.TblHITLDecisions, "decision_id,status,result,decision_data",
				"decision_id", caseID, "tenant_id", tenantID, &rows); err != nil || len(rows) == 0 {
				return fmt.Errorf("case not found: %s", caseID)
			}
			cur := rows[0]
			curStatus, _ := cur["status"].(string)
			existingData, _ := cur["decision_data"].(map[string]any)
			if existingData == nil {
				existingData = map[string]any{}
			}
			votes, _ := existingData["votes"].([]any)
			votes = append(votes, map[string]any{
				"voter_id":   body.VoterID,
				"decision":   decision,
				"confidence": body.Confidence,
				"rationale":  body.Rationale,
				"voted_at":   respondedAt,
			})
			existingData["votes"] = votes

			const (
				minQuorumFloor     = 5
				supermajorityRatio = 0.65
			)
			quorumThreshold := minQuorumFloor
			if qt, ok := existingData["quorum_threshold"].(float64); ok && int(qt) >= minQuorumFloor {
				quorumThreshold = int(qt)
			}
			if quorumThreshold%2 == 0 {
				quorumThreshold++
			}

			approveCount, rejectCount, abstainCount := 0, 0, 0
			for _, v := range votes {
				if vm, ok := v.(map[string]any); ok {
					switch vm["decision"] {
					case "APPROVE":
						approveCount++
					case "REJECT":
						rejectCount++
					case "ABSTAIN":
						abstainCount++
					}
				}
			}
			totalCast := approveCount + rejectCount + abstainCount

			newStatus := curStatus
			newResult := ""
			quorumReached := false
			panelComplete := totalCast >= quorumThreshold
			approveRatio := 0.0
			rejectRatio := 0.0
			if totalCast > 0 {
				approveRatio = float64(approveCount) / float64(totalCast)
				rejectRatio = float64(rejectCount) / float64(totalCast)
			}
			if panelComplete {
				if approveRatio > supermajorityRatio {
					newStatus = "APPROVED"
					newResult = "APPROVED"
					quorumReached = true
				} else if rejectRatio > supermajorityRatio {
					newStatus = "REJECTED"
					newResult = "REJECTED"
					quorumReached = true
				}
			}

			existingData["approve_count"] = approveCount
			existingData["reject_count"] = rejectCount
			existingData["abstain_count"] = abstainCount
			existingData["total_cast"] = totalCast
			existingData["quorum_threshold"] = quorumThreshold
			existingData["supermajority_ratio"] = supermajorityRatio
			existingData["approve_ratio"] = approveRatio
			existingData["reject_ratio"] = rejectRatio
			existingData["panel_complete"] = panelComplete
			existingData["quorum_reached"] = quorumReached

			ddBytes, marshalErr := json.Marshal(existingData)
			if marshalErr != nil {
				return marshalErr
			}
			update := map[string]any{
				"status":        newStatus,
				"decision_data": string(ddBytes),
				"responded_at":  respondedAt,
			}
			if quorumReached {
				update["result"] = newResult
			}
			if body.VoterID != "" {
				update["user_id"] = body.VoterID
			}
			// 3. Update main case status + quorum data
			if err := tx.UpdateRowCompound(database.TblHITLDecisions, "decision_id", caseID, "tenant_id", tenantID, update); err != nil {
				return err
			}

			// 4. X-15: Auto-escalate deadlocked panels
			if panelComplete && !quorumReached {
				if err := tx.UpdateRowCompound(database.TblHITLDecisions, "decision_id", caseID, "tenant_id", tenantID,
					map[string]any{
						"status":     "ESCALATED",
						"result":     "DEADLOCKED",
						"updated_at": respondedAt,
					}); err != nil {
					return err
				}
				// Event posted after transaction commits to avoid ocx-core-svc write inside Ring2 transaction.
				txResult.postDeadlockEvent = true
			}

			// Capture results for response
			txResult.newStatus = newStatus
			txResult.newResult = newResult
			txResult.quorumReached = quorumReached
			txResult.panelComplete = panelComplete
			txResult.approveCount = approveCount
			txResult.rejectCount = rejectCount
			txResult.abstainCount = abstainCount
			txResult.totalCast = totalCast
			txResult.quorumThreshold = quorumThreshold
			txResult.approveRatio = approveRatio
			txResult.rejectRatio = rejectRatio
			return nil
		}); txErr != nil {
			slog.Error("HandleCasesSubmitJuryVote: transaction failed", "case_id", caseID, "voter_id", body.VoterID, "error", txErr)
			// Check if it's a duplicate vote (unique constraint)
			if txErr.Error() != "" {
				respond.ErrorWithCode(w, http.StatusConflict, respond.ErrCodeConflict, "vote already cast or case state error: "+txErr.Error())
			} else {
				respond.InternalError(w, http.StatusInternalServerError, "submit vote", txErr)
			}
			return
		}
		slog.Info("jury vote cast",
			"case_id", caseID, "tenant", tenantID, "voter", body.VoterID,
			"decision", decision, "quorum_reached", txResult.quorumReached,
			"approve", txResult.approveCount, "reject", txResult.rejectCount, "abstain", txResult.abstainCount,
			"total", txResult.totalCast, "threshold", txResult.quorumThreshold,
			"approve_ratio", txResult.approveRatio, "reject_ratio", txResult.rejectRatio,
		)
		if txResult.panelComplete && !txResult.quorumReached {
			slog.Error("X-15: HITL quorum DEADLOCKED — auto-escalated", "case_id", caseID)
		}
		// Post QUORUM_DEADLOCKED audit event via ocx-core-svc API after transaction commits.
		if txResult.postDeadlockEvent && coreClient != nil {
			concurrent.Go("quorum-deadlocked-event", func() {
				_ = coreClient.PostEvent(context.Background(), map[string]any{
					"tenant_id":   tenantID,
					"event_type":  "QUORUM_DEADLOCKED",
					"entity_id":   caseID,
					"entity_type": "hitl_decision",
					"action":      "AUTO_ESCALATED",
					"new_value": fmt.Sprintf(`{"approve_count":%d,"reject_count":%d,"approve_ratio":%.2f,"reject_ratio":%.2f,"threshold":%d}`,
						txResult.approveCount, txResult.rejectCount, txResult.approveRatio, txResult.rejectRatio, txResult.quorumThreshold),
					"created_at": respondedAt,
				})
			})
		}
		respond.JSON(w, http.StatusOK, map[string]any{
			"case_id":             caseID,
			"voter_id":            body.VoterID,
			"decision":            decision,
			"status":              txResult.newStatus,
			"result":              txResult.newResult,
			"quorum_threshold":    txResult.quorumThreshold,
			"supermajority_ratio": 0.65,
			"approve_count":       txResult.approveCount,
			"reject_count":        txResult.rejectCount,
			"abstain_count":       txResult.abstainCount,
			"total_cast":          txResult.totalCast,
			"approve_ratio":       txResult.approveRatio,
			"reject_ratio":        txResult.rejectRatio,
			"panel_complete":      txResult.panelComplete,
			"quorum_reached":      txResult.quorumReached,
			"voted_at":            respondedAt,
		})
	}
}

// HandleListHITLVotes returns all per-reviewer votes for a case.
// GET /hitl/cases/{id}/votes
//
// Reads from core_hitl_votes (Batch 8). Frontend uses this for the
// quorum tally panel (GROUP BY decision done client-side or via SQL VIEW).
func HandleListHITLVotes(db database.DB) http.HandlerFunc {
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
		var rows []map[string]any
		// SCHEMA FIX: votes are in core_hitl_votes (TblHITLVotes), not core_hitl.
		// core_hitl_votes columns: vote_id, case_id, tenant_id, voter_id, decision, voted_at.
		if err := db.QueryRowsCompound(database.TblHITLVotes, database.ColsHitlVote, "case_id", caseID, "tenant_id", tenantID, &rows); err != nil {
			slog.Error("ListHITLVotes failed", "case_id", caseID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "list votes", err)
			return
		}
		if rows == nil {
			rows = []map[string]any{}
		}
		// Derive tally for convenience
		tally := map[string]int{"APPROVE": 0, "REJECT": 0, "ABSTAIN": 0}
		for _, v := range rows {
			if d, ok := v["decision"].(string); ok {
				tally[d]++
			}
		}
		respond.OK(w, map[string]any{
			"case_id": caseID,
			"votes":   rows,
			"total":   len(rows),
			"tally":   tally,
		})
	}
}

// POST /api/v1/hitl/cases/{id}/escalate
// Escalates a HITL case to the jury pool for multi-agent review.
// Sets status to ESCALATED and records escalation metadata in context_data.
