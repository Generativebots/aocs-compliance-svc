// dept_overflow.go — D2D-Department capacity overflow routing.
//
// D2D Gap-4: There are no capacity limits per department and no overflow routing.
// When a department hits its case limit, new cases pile up silently with no
// system response, SLA breach, or automatic re-routing.
//
// This file provides:
//
//	HandleRouteDeptOverflow: POST /api/v1/departments/{department_id}/overflow-route
//	Evaluates current dept capacity and routes overflowing cases to the next
//	department in the dept's overflow_routing_config.
//
//	HandleGuardDeptDeletion is a guard called before department deletion
//	to either block or auto-reassign all open cases (D2D Gap-5).
//
// Departments are addressed by syst_departments.department_id (PK) only;
// user-facing text shows the department name.
package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
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

// HandleRouteDeptOverflow — POST /api/v1/departments/{department_id}/overflow-route
//
// Checks the current dept capacity against core_hitl_sla.max_cases.
// If over capacity, moves the oldest PENDING cases to the overflow department
// configured in overflow_routing_config.overflow_dept_id (FK → department_id).
// Body: { max_cases_to_move?: int }   (default: 10)
//
// Returns: { department_id, department_name, open_cases, capacity_limit, moved_count, overflow_to, overflow_to_name }
func HandleRouteDeptOverflow(db database.DB, coreClients ...*serviceclient.Client) http.HandlerFunc {
	coreClient := hitlCore(coreClients...)
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) || !requireHITLCore(w, coreClient) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		deptID := mux.Vars(r)["department_id"]
		if deptID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing department_id")
			return
		}

		var req struct {
			MaxCasesToMove int `json:"max_cases_to_move"`
		}
		respond.LimitBody(r)
		if !validate.BindOptional(w, r, &req) {
			return
		}
		if req.MaxCasesToMove <= 0 {
			req.MaxCasesToMove = 10
		}

		// ── Load dept config ───────────────────────────────────────────────────
		dept, found := loadDepartment(db, tenantID, deptID)
		if !found {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "department not found")
			return
		}

		// ── Load SLA/capacity config ───────────────────────────────────────────
		slaRows, _slaErr := coreClient.HITLSLALookup(r.Context(), tenantID, dept.ID)
		if _slaErr != nil {
			slog.Error("core HITLSLALookup failed (best-effort)", "error", _slaErr)
		}
		maxCases := 200 // default
		if len(slaRows) > 0 {
			if mc, ok := slaRows[0]["max_cases"].(float64); ok && mc > 0 {
				maxCases = int(mc)
			}
		}

		// ── Count open cases ───────────────────────────────────────────────────
		var pendingRows []map[string]any
		{
			// SVC-BOUNDARY: read core_hitl via ocx-core-svc API
			hitlRows, _rErr := coreClient.ListHITLCases(r.Context(), tenantID,
				map[string]string{"department_id": dept.ID, "status": "PENDING"}, 500)
			if _rErr != nil {
				respond.InternalError(w, http.StatusInternalServerError, "overflow_check_query_failed", _rErr)
				return
			}
			pendingRows = hitlRows
		}
		openCases := len(pendingRows)

		if openCases <= maxCases {
			respond.OK(w, map[string]any{
				"department_id":   dept.ID,
				"department_name": dept.Name,
				"open_cases":      openCases,
				"capacity_limit":  maxCases,
				"status":          "within_capacity",
				"moved_count":     0,
			})
			return
		}

		// ── Determine overflow target dept (FK only — no hardcoded fallback) ───
		if dept.OverflowDeptID == "" {
			respond.ErrorWithCode(w, http.StatusUnprocessableEntity, respond.ErrCodeValidation,
				fmt.Sprintf("department %q is over capacity but has no overflow department configured (overflow_routing_config.overflow_dept_id)", dept.Name))
			return
		}
		if dept.OverflowDeptID == dept.ID {
			respond.ErrorWithCode(w, http.StatusConflict, respond.ErrCodeConflict,
				fmt.Sprintf("overflow department for %q is itself — configure a different overflow department", dept.Name))
			return
		}

		// ── Verify target dept exists and has HITL enabled ─────────────────────
		target, found := loadDepartment(db, tenantID, dept.OverflowDeptID)
		if !found {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest,
				fmt.Sprintf("overflow department configured for %q no longer exists", dept.Name))
			return
		}
		if !target.hitlEnabled() {
			respond.ErrorWithCode(w, http.StatusUnprocessableEntity, respond.ErrCodeValidation,
				fmt.Sprintf("overflow department %q has HITL disabled", target.Name))
			return
		}

		// ── Get overflow SLA for target dept ───────────────────────────────────
		targetSLARows, _tslaErr := coreClient.HITLSLALookup(r.Context(), tenantID, target.ID)
		if _tslaErr != nil {
			slog.Error("core HITLSLALookup failed (best-effort)", "error", _tslaErr)
		}
		targetSLAHours := 48
		if len(targetSLARows) > 0 {
			if h, ok := targetSLARows[0]["sla_hours"].(float64); ok && h > 0 {
				targetSLAHours = int(h)
			}
		}
		newDeadline := time.Now().UTC().Add(time.Duration(targetSLAHours) * time.Hour).Format(time.RFC3339)
		now := time.Now().UTC().Format(time.RFC3339)

		// ── Move oldest PENDING cases (up to max_cases_to_move) ───────────────
		moved := 0
		for _, cas := range pendingRows {
			if moved >= req.MaxCasesToMove {
				break
			}
			caseID, _ := cas["decision_id"].(string)
			if caseID == "" {
				continue
			}
			ctxUpdate, _ := json.Marshal(map[string]any{
				"overflow_from":   dept.ID,
				"overflow_to":     target.ID,
				"overflow_at":     now,
				"overflow_reason": fmt.Sprintf("%s at capacity, rerouted to %s", dept.Name, target.Name),
			})
			// Only PENDING cases move; the precondition is evaluated under core's row lock.
			if _rErr := coreClient.PatchHITLCaseIf(r.Context(), tenantID, caseID, map[string]any{
				"department_id": target.ID,
				"sla_deadline":  newDeadline,
				"context_data":  string(ctxUpdate),
				"updated_at":    now,
			}, []string{"PENDING"}, nil); _rErr != nil {
				slog.Error("failed to move case via coreClient", "case_id", caseID, "error", _rErr)
				continue
			}
			moved++
			// Audit event per case (best-effort)
			auditCaseID := caseID // capture loop var before goroutine
			concurrent.Go("compliance/dept_overflow", func() {
				auditMeta, _ := json.Marshal(map[string]any{
					"from_dept": dept.ID, "to_dept": target.ID,
					"reason": "overflow_routing", "sla_hours": targetSLAHours,
				})
				auditRow := map[string]any{
					"event_type":  "case.overflow_routed",
					"entity_id":   auditCaseID,
					"entity_type": "hitl_case",
					"tenant_id":   tenantID, // REQUIRED: all platform_events rows must be tenant-scoped
					"payload": map[string]any{
						"action":         "overflow_route",
						"severity":       "WARNING",
						"metadata":       auditMeta,
						"from_dept":      dept.ID,
						"from_dept_name": dept.Name,
						"to_dept":        target.ID,
						"to_dept_name":   target.Name,
					},
				}
				if _err := coreClient.PostEvent(context.Background(), auditRow); _err != nil {
					slog.Error("coreClient.PostEvent overflow_routed failed (best-effort)", "error", _err)
				}
			})
		}

		slog.Info("overflow routing complete",
			"department_id", dept.ID, "open_cases", openCases, "capacity", maxCases,
			"moved", moved, "target_department_id", target.ID,
		)
		respond.OK(w, map[string]any{
			"department_id":    dept.ID,
			"department_name":  dept.Name,
			"open_cases":       openCases,
			"capacity_limit":   maxCases,
			"overflow_to":      target.ID,
			"overflow_to_name": target.Name,
			"moved_count":      moved,
			"new_sla_hours":    targetSLAHours,
			"note":             fmt.Sprintf("Co-Pilot: %s at capacity. Moved %d cases to %s.", dept.Name, moved, target.Name),
		})
	}
}

// HandleGuardDeptDeletion — called as a pre-deletion guard.
// D2D Gap-5: Department deletion currently orphans all open HITL cases with no
// re-assignment. This handler blocks deletion if open cases exist, unless a
// target_department_id is provided for case migration.
//
// POST /api/v1/departments/{department_id}/pre-delete-check
// Body: { target_department_id?: string }  — if set, migrates cases; if not set, blocks deletion.
func HandleGuardDeptDeletion(db database.DB, coreClients ...*serviceclient.Client) http.HandlerFunc {
	coreClient := hitlCore(coreClients...)
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) || !requireHITLCore(w, coreClient) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		deptID := mux.Vars(r)["department_id"]
		if deptID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing department_id")
			return
		}
		dept, found := loadDepartment(db, tenantID, deptID)
		if !found {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "department not found")
			return
		}

		var req struct {
			TargetDepartmentID string `json:"target_department_id"`
		}
		respond.LimitBody(r)
		if !validate.BindOptional(w, r, &req) {
			return
		}
		var pendingRows []map[string]any
		{
			// SVC-BOUNDARY: read core_hitl via ocx-core-svc API
			hitlRows, _rErr := coreClient.ListHITLCases(r.Context(), tenantID,
				map[string]string{"department_id": dept.ID, "status": "PENDING"}, 500)
			if _rErr != nil {
				respond.InternalError(w, http.StatusInternalServerError, "overflow_check_query_failed", _rErr)
				return
			}
			pendingRows = hitlRows
		}
		openCount := len(pendingRows)

		if openCount == 0 {
			respond.OK(w, map[string]any{
				"safe_to_delete":  true,
				"open_cases":      0,
				"department_id":   dept.ID,
				"department_name": dept.Name,
			})
			return
		}

		// Open cases exist — block unless a target department is provided
		if req.TargetDepartmentID == "" {
			respond.ErrorWithCode(w, http.StatusConflict, respond.ErrCodeConflict,
				fmt.Sprintf("department %q has %d open HITL cases — provide target_department_id to migrate them before deletion", dept.Name, openCount))
			return
		}
		if req.TargetDepartmentID == dept.ID {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "target department must differ from the department being deleted")
			return
		}
		target, found := loadDepartment(db, tenantID, req.TargetDepartmentID)
		if !found {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "target department not found")
			return
		}

		// Migrate all open cases to target dept
		now := time.Now().UTC().Format(time.RFC3339)
		migrated := 0
		for _, cas := range pendingRows {
			caseID, _ := cas["decision_id"].(string)
			if caseID == "" {
				continue
			}
			ctxUpdate, _ := json.Marshal(map[string]any{
				"migrated_from":    dept.ID,
				"migrated_to":      target.ID,
				"migration_at":     now,
				"migration_reason": fmt.Sprintf("%s pre-deletion migration to %s", dept.Name, target.Name),
			})
			// SVC-BOUNDARY: update core_hitl via ocx-core-svc API (PENDING only, under row lock)
			if _rErr := coreClient.PatchHITLCaseIf(r.Context(), tenantID, caseID, map[string]any{
				"department_id": target.ID,
				"context_data":  string(ctxUpdate),
				"updated_at":    now,
			}, []string{"PENDING"}, nil); _rErr == nil {
				migrated++
			}
		}

		respond.OK(w, map[string]any{
			"safe_to_delete":   migrated == openCount,
			"open_cases":       openCount,
			"migrated":         migrated,
			"migrated_to":      target.ID,
			"migrated_to_name": target.Name,
			"department_id":    dept.ID,
			"department_name":  dept.Name,
			"note":             fmt.Sprintf("%d of %d cases migrated to %s from %s.", migrated, openCount, target.Name, dept.Name),
		})
	}
}
