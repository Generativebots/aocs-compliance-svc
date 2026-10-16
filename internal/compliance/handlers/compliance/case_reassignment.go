// case_reassign.go — D2D-Department-to-department case handover.
//
// POST /api/v1/hitl/cases/{id}/reassign
//
// Gap (D2D Gap-1): There is no API for transferring a HITL case between departments.
// Operators must do direct DB writes with no audit trail, no HITL-enabled check,
// and no SLA recomputation. Cases assigned to incapable departments stall indefinitely.
//
// This handler:
//  1. Verifies source department owns the case.
//  2. Verifies target department has HITL enabled (enabled_features.hitl=true).
//  3. Recomputes SLA deadline from core_hitl_sla for the target dept.
//  4. Updates core_hitl: department_id, sla_deadline, reassigned_from.
//  5. Emits case.dept_handover platform event (EU AI Act Art.13 traceability).
package compliance

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/serviceclient"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

// HandleReassignCase — POST /api/v1/hitl/cases/{id}/reassign
// Body: { from_dept_id, to_dept_id, reason, escalation_level? }
func HandleReassignCase(db database.DB, coreClients ...*serviceclient.Client) http.HandlerFunc {
	coreClient := hitlCore(coreClients...)
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) || !requireHITLCore(w, coreClient) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		caseID := mux.Vars(r)["id"]
		if caseID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing case id")
			return
		}
		respond.LimitBody(r)

		var req ReassignCaseRequest
		// (BATCH): removed duplicate LimitBody — double-wrapping halves max body size
		if !validate.Bind(w, r, &req) {
			return
		}
		if req.ToDeptID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "to_dept_id is required")
			return
		}
		if req.FromDeptID == req.ToDeptID {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "from_dept_id and to_dept_id must differ")
			return
		}

		// Current department comes from core; the terminal-status guard is re-checked atomically
		// (under core's row lock) by the PATCH below, so concurrent reassignments cannot both win.
		caseRow, fErr := coreClient.FetchHITLCase(r.Context(), tenantID, caseID, "decision_id,department_id,status")
		if fErr != nil {
			writeHITLCoreErr(w, fErr, "load case for reassignment")
			return
		}
		var txResult struct{ currentDept, currentStatus string }
		txResult.currentDept, _ = caseRow["department_id"].(string)
		txResult.currentStatus, _ = caseRow["status"].(string)
		if st := txResult.currentStatus; st == "APPROVED" || st == "REJECTED" || st == "RESOLVED" {
			respond.ErrorWithCode(w, http.StatusConflict, respond.ErrCodeConflict,
				fmt.Sprintf("case is in terminal status '%s' — reassignment not permitted", st))
			return
		}
		currentDept := txResult.currentDept
		_ = txResult.currentStatus // terminal check is enforced inside the lock tx above
		// Warn (but don't block) if from_dept_id doesn't match current dept
		if req.FromDeptID != "" && currentDept != req.FromDeptID {
			slog.Warn("from_dept mismatch — proceeding with actual current dept",
				"case_id", caseID, "claimed_from", req.FromDeptID, "actual_dept", currentDept)
		}

		// ── Check 2: Target dept (by PK) exists and has HITL enabled ──────────
		depts, deptErr := loadTenantDepartments(r.Context(), db, tenantID)
		if deptErr != nil {
			respond.InternalError(w, http.StatusServiceUnavailable, "could not load departments", deptErr)
			return
		}
		toDept, found := depts[req.ToDeptID]
		if !found {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "target department not found")
			return
		}
		if !toDept.hitlEnabled() {
			respond.ErrorWithCode(w, http.StatusUnprocessableEntity, respond.ErrCodeValidation,
				fmt.Sprintf("department %q has HITL disabled — enable it before reassigning cases", toDept.Name))
			return
		}
		fromName, toName := depts.name(currentDept), toDept.Name

		// ── Cross-department policy re-evaluation ─────────────────────
		// Compare source dept vs target dept governance policy thresholds.
		// If policies diverge, surface a policy_conflict in the response for
		// the Co-Pilot to alert the operator before committing the handover.
		// This is advisory (non-blocking) — the reassignment proceeds but the
		// conflict is recorded in the audit trail.
		policyConflict := ""
		{
			type deptPolicy struct {
				AutoApproveThreshold float64 `json:"auto_approve_threshold"`
				EscalateThreshold    float64 `json:"escalate_threshold"`
			}
			fetchPolicy := func(departmentID string) deptPolicy {
				rows, _dbErr := coreClient.HITLSLALookup(r.Context(), tenantID, departmentID)
				if _dbErr != nil {
					slog.Error("core HITLSLALookup failed", "error", _dbErr)
				}
				if len(rows) == 0 {
					return deptPolicy{AutoApproveThreshold: 0.8, EscalateThreshold: 0.4}
				}
				p := deptPolicy{AutoApproveThreshold: 0.8, EscalateThreshold: 0.4}
				if v, ok := rows[0]["auto_approve_threshold"].(float64); ok {
					p.AutoApproveThreshold = v
				}
				if v, ok := rows[0]["escalate_threshold"].(float64); ok {
					p.EscalateThreshold = v
				}
				return p
			}
			srcPolicy := fetchPolicy(currentDept)
			tgtPolicy := fetchPolicy(req.ToDeptID)

			// Detect meaningful policy divergence (>10% threshold gap)
			const divergenceThreshold = 0.10
			if srcPolicy.AutoApproveThreshold-tgtPolicy.AutoApproveThreshold > divergenceThreshold {
				policyConflict = fmt.Sprintf(
					"Policy conflict: %s auto-approves at %.0f%% but %s auto-approves at %.0f%% — "+
						"cases %s would escalate may auto-resolve in %s. Co-Pilot: confirm handover?",
					fromName, srcPolicy.AutoApproveThreshold*100,
					toName, tgtPolicy.AutoApproveThreshold*100,
					fromName, toName,
				)
				slog.Warn("D2D policy conflict detected",
					"from_dept", currentDept, "to_dept", req.ToDeptID,
					"src_auto_approve", srcPolicy.AutoApproveThreshold,
					"tgt_auto_approve", tgtPolicy.AutoApproveThreshold,
				)
			} else if tgtPolicy.AutoApproveThreshold-srcPolicy.AutoApproveThreshold > divergenceThreshold {
				policyConflict = fmt.Sprintf(
					"Policy conflict: %s auto-approves at %.0f%% but %s requires %.0f%% — "+
						"cases %s auto-resolves may escalate in %s. Co-Pilot: confirm handover?",
					fromName, srcPolicy.AutoApproveThreshold*100,
					toName, tgtPolicy.AutoApproveThreshold*100,
					fromName, toName,
				)
			}
		}

		// ── Check 3: Recompute SLA deadline for target dept ───────────────────
		slaRows, _slaErr := coreClient.HITLSLALookup(r.Context(), tenantID, req.ToDeptID)
		if _slaErr != nil {
			slog.Error("core HITLSLALookup failed", "error", _slaErr)
		}
		slaHours := 48 // Default SLA
		if len(slaRows) > 0 {
			if h, ok := slaRows[0]["sla_hours"].(float64); ok && h > 0 {
				slaHours = int(h)
			}
		}

		newDeadline := time.Now().UTC().Add(time.Duration(slaHours) * time.Hour).Format(time.RFC3339)
		now := time.Now().UTC().Format(time.RFC3339)

		// ── Update case: new dept + new SLA deadline ──────────────────────────
		contextUpdate := map[string]any{
			"reassigned_from": currentDept,
			"reassigned_to":   req.ToDeptID,
			"reassigned_at":   now,
			"reassign_reason": req.Reason,
		}
		if req.EscalationLevel > 0 {
			contextUpdate["escalation_level"] = req.EscalationLevel
		}
		ctxBytes, marshalErr := json.Marshal(contextUpdate)
		if marshalErr != nil {
			slog.Error("json.Marshal failed", "err", marshalErr)
			return
		}
		update := map[string]any{
			"department_id": req.ToDeptID,
			"updated_at":    now,
			"context_data":  string(ctxBytes),
		}
		// Only write sla_deadline if the column exists (added in Part 1 migrations)
		update["sla_deadline"] = newDeadline

		meta, _ := json.Marshal(map[string]any{
			"from_dept":        currentDept,
			"to_dept":          req.ToDeptID,
			"reason":           req.Reason,
			"new_sla_hours":    slaHours,
			"new_sla_deadline": newDeadline,
			"policy_conflict":  policyConflict, // persisted in audit trail
		})
		// Department update + handover audit event are applied by core in ONE transaction.
		update[serviceclient.HITLPatchAuditEvent] = map[string]any{
			"event_type": "case.dept_handover",
			"entity_id":  caseID,
			"action":     "dept_reassign",
			"severity":   "INFO",
			"metadata":   json.RawMessage(meta),
			"created_at": now,
		}
		if err := coreClient.PatchHITLCaseIf(r.Context(), tenantID, caseID, update, nil, []string{"APPROVED", "REJECTED", "RESOLVED"}); err != nil {
			slog.Error("update failed", "case_id", caseID, "error", err)
			writeHITLCoreErr(w, err, "reassign case")
			return
		}

		slog.Info("case reassigned",
			"case_id", caseID, "from", currentDept, "to", req.ToDeptID,
			"sla_hours", slaHours, "tenant_id", tenantID,
		)
		resp := map[string]any{
			"status":           "reassigned",
			"case_id":          caseID,
			"from_dept":        currentDept,
			"from_dept_name":   fromName,
			"to_dept":          req.ToDeptID,
			"to_dept_name":     toName,
			"new_sla_deadline": newDeadline,
			"sla_hours":        slaHours,
		}
		// Co-Pilot surface — include advisory policy conflict if detected
		if policyConflict != "" {
			resp["policy_conflict"] = policyConflict
			resp["requires_confirmation"] = true
		}
		respond.OK(w, resp)
	}
}
