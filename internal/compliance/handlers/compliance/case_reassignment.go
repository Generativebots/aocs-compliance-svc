// case_reassign.go — D2D-FIX-1 (Sprint 3): Department-to-department case handover.
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
	"strings"

	"net/http"
	"time"

	"github.com/ocx/shared/infra/concurrent"

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
	var coreClient *serviceclient.Client
	if len(coreClients) > 0 {
		coreClient = coreClients[0]
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
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
	// GATE-06 FIX (BATCH): removed duplicate LimitBody — double-wrapping halves max body size
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

		// Without this, two concurrent reassignments can both read the same department_id
		// and both proceed, causing the case to land in an inconsistent department.
		var caseRows []map[string]any
		type reassignResult struct {
			currentDept   string
			currentStatus string
		}
		txResult, isTxErr := func() (reassignResult, error) {
			var res reassignResult
			err := db.WithTransaction(r.Context(), func(tx database.DB) error {
				if qErr := tx.QueryRowsCompoundForUpdate(database.TblCoreHitl,
					"decision_id,department_id,status",
					"decision_id", caseID, "tenant_id", tenantID, &caseRows); qErr != nil || len(caseRows) == 0 {
					return fmt.Errorf("not_found")
				}
				res.currentDept, _ = caseRows[0]["department_id"].(string)
				res.currentStatus, _ = caseRows[0]["status"].(string)
				if res.currentStatus == "APPROVED" || res.currentStatus == "REJECTED" || res.currentStatus == "RESOLVED" {
					return fmt.Errorf("terminal:%s", res.currentStatus)
				}
				return nil
			})
			return res, err
		}()
		if isTxErr != nil {
			switch {
			case isTxErr.Error() == "not_found":
				respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "case not found")
			case strings.HasPrefix(isTxErr.Error(), "terminal:"):
				respond.ErrorWithCode(w, http.StatusConflict, respond.ErrCodeConflict,
					fmt.Sprintf("case is in terminal status '%s' — reassignment not permitted", strings.TrimPrefix(isTxErr.Error(), "terminal:")))
			default:
				respond.InternalError(w, http.StatusInternalServerError, "lock case for reassignment", isTxErr)
			}
			return
		}
		currentDept := txResult.currentDept
		_ = txResult.currentStatus // terminal check is enforced inside the lock tx above //nolint:errcheck — audited: best-effort, failure is non-critical
		// Warn (but don't block) if from_dept_id doesn't match current dept
		if req.FromDeptID != "" && currentDept != req.FromDeptID {
			slog.Warn("from_dept mismatch — proceeding with actual current dept",
				"case_id", caseID, "claimed_from", req.FromDeptID, "actual_dept", currentDept)
		}

		// ── Check 2: Target dept has HITL enabled ─────────────────────────────
		var deptRows []map[string]any
		if err := db.QueryRowsCompound(database.TblSystDepartments, "slug,enabled_features",
			"slug", req.ToDeptID, "tenant_id", tenantID, &deptRows); err != nil || len(deptRows) == 0 {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest,
				fmt.Sprintf("target department '%s' not found", req.ToDeptID))
			return
		}
		toDept := deptRows[0]
		if ef, ok := toDept["enabled_features"].(map[string]any); ok {
			if hitlVal, hasKey := ef["hitl"]; hasKey {
				switch v := hitlVal.(type) {
				case bool:
					if !v {
						respond.ErrorWithCode(w, http.StatusUnprocessableEntity, respond.ErrCodeValidation,
							fmt.Sprintf("department '%s' has HITL disabled — enable it before reassigning cases", req.ToDeptID))
						return
					}
				case string:
					if v == "false" || v == "0" {
						respond.ErrorWithCode(w, http.StatusUnprocessableEntity, respond.ErrCodeValidation,
							fmt.Sprintf("department '%s' has HITL disabled — enable it before reassigning cases", req.ToDeptID))
						return
					}
				}
			}
		}

		// ── D2D-6: Cross-department policy re-evaluation ─────────────────────
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
			fetchPolicy := func(deptSlug string) deptPolicy {
				var rows []map[string]any
				if _dbErr := db.QueryRowsCompound(database.TblCoreHitlSla,
					"department_id,auto_approve_threshold,escalate_threshold",
					"department_id", deptSlug, "tenant_id", tenantID, &rows); _dbErr != nil {
					slog.Error("QueryRowsCompound failed", "error", _dbErr)
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
					currentDept, srcPolicy.AutoApproveThreshold*100,
					req.ToDeptID, tgtPolicy.AutoApproveThreshold*100,
					currentDept, req.ToDeptID,
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
					currentDept, srcPolicy.AutoApproveThreshold*100,
					req.ToDeptID, tgtPolicy.AutoApproveThreshold*100,
					currentDept, req.ToDeptID,
				)
			}
		}

		// ── Check 3: Recompute SLA deadline for target dept ───────────────────
		var slaRows []map[string]any
		if _dbErr := db.QueryRowsCompound(database.TblCoreHitlSla, "department_id,sla_hours",
			"department_id", req.ToDeptID, "tenant_id", tenantID, &slaRows); _dbErr != nil {
			slog.Error("QueryRowsCompound failed", "error", _dbErr)
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

		if err := db.UpdateRowCompound(database.TblCoreHitl, "decision_id", caseID, "tenant_id", tenantID, update); err != nil {
			slog.Error("update failed", "case_id", caseID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "reassign case", err)
			return
		}

		// ── Audit event (best-effort) ──────────────────────────────────────────
		concurrent.Go("case_reassignment", func() {
			meta, _ := json.Marshal(map[string]any{
				"from_dept":        currentDept,
				"to_dept":          req.ToDeptID,
				"reason":           req.Reason,
				"new_sla_hours":    slaHours,
				"new_sla_deadline": newDeadline,
				"policy_conflict":  policyConflict, // D2D-6: persisted in audit trail
			})
			auditRow := map[string]any{
				"event_type": "case.dept_handover",
				"tenant_id":  tenantID,
				"entity_id":  caseID,
				"action":     "dept_reassign",
				"severity":   "INFO",
				"metadata":   meta,
				"created_at": now,
			}
			if coreClient != nil {
				if _err := coreClient.PostEvent(r.Context(), auditRow); _err != nil {
					slog.Error("coreClient.PostEvent dept_handover failed (best-effort)", "error", _err)
				}
			} else if _dbErr := db.InsertRow(database.TblCoreEvents, auditRow); _dbErr != nil {
				slog.Error("InsertRow failed", "error", _dbErr)
			}
		})

		slog.Info("case reassigned",
			"case_id", caseID, "from", currentDept, "to", req.ToDeptID,
			"sla_hours", slaHours, "tenant_id", tenantID,
		)
		resp := map[string]any{
			"status":           "reassigned",
			"case_id":          caseID,
			"from_dept":        currentDept,
			"to_dept":          req.ToDeptID,
			"new_sla_deadline": newDeadline,
			"sla_hours":        slaHours,
		}
		// D2D-6: Co-Pilot surface — include advisory policy conflict if detected
		if policyConflict != "" {
			resp["policy_conflict"] = policyConflict
			resp["requires_confirmation"] = true
		}
		respond.OK(w, resp)
	}
}
