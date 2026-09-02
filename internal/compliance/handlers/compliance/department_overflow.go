// dept_overflow.go — D2D-FIX: Department capacity overflow routing.
//
// D2D Gap-4: There are no capacity limits per department and no overflow routing.
// When a department hits its case limit, new cases pile up silently with no
// system response, SLA breach, or automatic re-routing.
//
// This file provides:
//
//	HandleRouteDeptOverflow: POST /api/v1/departments/{slug}/overflow-route
//	Evaluates current dept capacity and routes overflowing cases to the next
//	department in the dept's overflow_routing_config.
//
//	HandleGuardDeptDeletion is a guard called before department deletion
//	to either block or auto-reassign all open cases (D2D Gap-5).
package compliance

import (
	"github.com/ocx/shared/infra/concurrent"
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

// HandleRouteDeptOverflow — POST /api/v1/departments/{slug}/overflow-route
//
// Checks the current dept capacity against core_hitl_sla.max_cases.
// If over capacity, moves the oldest PENDING cases to the configured overflow dept.
// Body: { max_cases_to_move?: int }   (default: 10)
//
// Returns: { dept_id, open_cases, capacity_limit, moved_count, target_dept }
func HandleRouteDeptOverflow(db database.DB, coreClients ...*serviceclient.Client) http.HandlerFunc {
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
		slug := mux.Vars(r)["slug"]
		if slug == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing department slug")
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
		var deptRows []map[string]any
		if err := db.QueryRowsCompound(database.TblPlatformDepartments,
			"slug,name,enabled_features,overflow_routing_config",
			"slug", slug, "tenant_id", tenantID, &deptRows); err != nil || len(deptRows) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, fmt.Sprintf("department %q not found", slug))
			return
		}
		dept := deptRows[0]

		// ── Load SLA/capacity config ───────────────────────────────────────────
		var slaRows []map[string]any
		if _dbErr := db.QueryRowsCompound(database.TblHITLSLAConfig, "department_id,sla_hours,max_cases",
			"department_id", slug, "tenant_id", tenantID, &slaRows); _dbErr != nil {
			slog.Error("db.QueryRowsCompound failed (best-effort)", "error", _dbErr)
		}
		maxCases := 200 // default
		if len(slaRows) > 0 {
			if mc, ok := slaRows[0]["max_cases"].(float64); ok && mc > 0 {
				maxCases = int(mc)
			}
		}

		// ── Count open cases ───────────────────────────────────────────────────
		var pendingRows []map[string]any
		if coreClient != nil {
			// SVC-BOUNDARY: read core_hitl via ocx-core-svc API
			hitlRows, _rErr := coreClient.ListHITLCases(r.Context(), tenantID,
				map[string]string{"department_id": slug, "status": "PENDING"}, 500)
			if _rErr != nil {
				respond.InternalError(w, http.StatusInternalServerError, "overflow_check_query_failed", _rErr)
				return
			}
			pendingRows = hitlRows
		} else if _dbErr := db.QueryRowsCompound(database.TblHITLDecisions, "decision_id,created_at",
			"department_id", slug, "status", "PENDING", &pendingRows); _dbErr != nil {
			slog.Error("db.QueryRowsCompound failed", "error", _dbErr)
			respond.InternalError(w, http.StatusInternalServerError, "overflow_check_query_failed", nil)
			return
		}
		openCases := len(pendingRows)

		if openCases <= maxCases {
			respond.OK(w, map[string]any{
				"dept_id":        slug,
				"open_cases":     openCases,
				"capacity_limit": maxCases,
				"status":         "within_capacity",
				"moved_count":    0,
			})
			return
		}

		// ── Determine overflow target dept ─────────────────────────────────────
		overflowConfig, _ := dept["overflow_routing_config"].(string)
		targetDept := ""
		if overflowConfig != "" && overflowConfig != "null" {
			var cfg struct {
				OverflowDept string `json:"overflow_dept"`
			}
			if err := json.Unmarshal([]byte(overflowConfig), &cfg); err == nil {
				targetDept = cfg.OverflowDept
			}
		}
		// Default overflow: compliance (safest AOCS fallback)
		if targetDept == "" {
			targetDept = "compliance"
		}
		if targetDept == slug {
			respond.ErrorWithCode(w, http.StatusConflict, respond.ErrCodeConflict,
				fmt.Sprintf("overflow target dept is same as source dept %q — configure a different overflow_routing_config", slug))
			return
		}

		// ── Verify target dept has HITL enabled ────────────────────────────────
		var targetDeptRows []map[string]any
		if err := db.QueryRowsCompound(database.TblPlatformDepartments, "slug,enabled_features",
			"slug", targetDept, "tenant_id", tenantID, &targetDeptRows); err != nil || len(targetDeptRows) == 0 {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest,
				fmt.Sprintf("overflow target department %q not found", targetDept))
			return
		}

		// ── Get overflow SLA for target dept ───────────────────────────────────
		var targetSLARows []map[string]any
		if _dbErr := db.QueryRowsCompound(database.TblHITLSLAConfig, "department_id,sla_hours",
			"department_id", targetDept, "tenant_id", tenantID, &targetSLARows); _dbErr != nil {
			slog.Error("db.QueryRowsCompound failed (best-effort)", "error", _dbErr)
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
				"overflow_from":   slug,
				"overflow_to":     targetDept,
				"overflow_at":     now,
				"overflow_reason": fmt.Sprintf("dept %s at capacity, rerouting", slug),
			})
			if coreClient != nil {
				// SVC-BOUNDARY: update core_hitl via ocx-core-svc API
				if _rErr := coreClient.PatchHITLCase(r.Context(), tenantID, caseID, map[string]any{
					"department_id": targetDept,
					"sla_deadline":  newDeadline,
					"context_data":  string(ctxUpdate),
					"updated_at":    now,
				}); _rErr != nil {
					slog.Error("failed to move case via coreClient",
						"case_id", caseID, "error", _rErr)
					continue
				}
			} else if err := db.UpdateRowCompound(database.TblHITLDecisions, "decision_id", caseID, "status", "PENDING",
				map[string]any{
					"department_id": targetDept,
					"sla_deadline":  newDeadline,
					"context_data":  string(ctxUpdate),
					"updated_at":    now,
				}); err != nil {
				slog.Error("failed to move case",
					"case_id", caseID, "error", err)
				continue
			}
			moved++
			// Audit event per case (best-effort)
			auditCaseID := caseID // capture loop var before goroutine
			concurrent.Go("compliance/dept_overflow", func() {
				auditMeta, _ := json.Marshal(map[string]any{
					"from_dept": slug, "to_dept": targetDept,
					"reason": "overflow_routing", "sla_hours": targetSLAHours,
				})
				auditRow := map[string]any{
					"event_type":  "case.overflow_routed",
					"entity_id":   auditCaseID,
					"entity_type": "hitl_case",
					"tenant_id":   tenantID, // REQUIRED: all platform_events rows must be tenant-scoped
					"payload": map[string]any{
						"action":    "overflow_route",
						"severity":  "WARN",
						"metadata":  auditMeta,
						"from_dept": slug,
						"to_dept":   targetDept,
					},
				}
				if coreClient != nil {
					if _err := coreClient.PostEvent(r.Context(), auditRow); _err != nil {
						slog.Error("coreClient.PostEvent overflow_routed failed (best-effort)", "error", _err)
					}
				} else if _dbErr := db.InsertRow(database.TblPlatformEvents, auditRow); _dbErr != nil {
					slog.Error("db.InsertRow failed (best-effort)", "error", _dbErr)
				}
			})
		}

		slog.Info("overflow routing complete",
			"dept", slug, "open_cases", openCases, "capacity", maxCases,
			"moved", moved, "target_dept", targetDept,
		)
		respond.OK(w, map[string]any{
			"dept_id":        slug,
			"open_cases":     openCases,
			"capacity_limit": maxCases,
			"overflow_to":    targetDept,
			"moved_count":    moved,
			"new_sla_hours":  targetSLAHours,
			"note":           fmt.Sprintf("Co-Pilot: %s at capacity. Moved %d cases to %s.", slug, moved, targetDept),
		})
	}
}

// HandleGuardDeptDeletion — called as a pre-deletion guard.
// D2D Gap-5: Department deletion currently orphans all open HITL cases with no
// re-assignment. This handler blocks deletion if open cases exist, unless a
// target_dept is provided for case migration.
//
// POST /api/v1/departments/{slug}/pre-delete-check
// Body: { target_dept?: string }  — if set, migrates cases; if not set, blocks deletion.
func HandleGuardDeptDeletion(db database.DB, coreClients ...*serviceclient.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		slug := mux.Vars(r)["slug"]
		if slug == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing department slug")
			return
		}

		var req struct {
			TargetDept string `json:"target_dept"`
		}
		respond.LimitBody(r)
		if !validate.BindOptional(w, r, &req) {
			return
		}
		var pendingRows []map[string]any
		if len(coreClients) > 0 && coreClients[0] != nil {
			// SVC-BOUNDARY: read core_hitl via ocx-core-svc API
			hitlRows, _rErr := coreClients[0].ListHITLCases(r.Context(), tenantID,
				map[string]string{"department_id": slug, "status": "PENDING"}, 500)
			if _rErr != nil {
				respond.InternalError(w, http.StatusInternalServerError, "overflow_check_query_failed", _rErr)
				return
			}
			pendingRows = hitlRows
		} else if _dbErr := db.QueryRowsCompound(database.TblHITLDecisions, "decision_id",
			"department_id", slug, "status", "PENDING", &pendingRows); _dbErr != nil {
			slog.Error("db.QueryRowsCompound failed", "error", _dbErr)
			respond.InternalError(w, http.StatusInternalServerError, "overflow_check_query_failed", nil)
			return
		}
		openCount := len(pendingRows)

		if openCount == 0 {
			respond.OK(w, map[string]any{
				"safe_to_delete": true,
				"open_cases":     0,
				"dept_id":        slug,
			})
			return
		}

		// Open cases exist — block unless target_dept provided
		if req.TargetDept == "" {
			respond.ErrorWithCode(w, http.StatusConflict, respond.ErrCodeConflict,
				fmt.Sprintf("department %q has %d open HITL cases — provide target_dept to migrate them before deletion", slug, openCount))
			return
		}
		if req.TargetDept == slug {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "target_dept must differ from the department being deleted")
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
				"migrated_from":    slug,
				"migrated_to":      req.TargetDept,
				"migration_at":     now,
				"migration_reason": fmt.Sprintf("dept %s pre-deletion migration", slug),
			})
			if len(coreClients) > 0 && coreClients[0] != nil {
				// SVC-BOUNDARY: update core_hitl via ocx-core-svc API
				if _rErr := coreClients[0].PatchHITLCase(r.Context(), tenantID, caseID, map[string]any{
					"department_id": req.TargetDept,
					"context_data":  string(ctxUpdate),
					"updated_at":    now,
				}); _rErr == nil {
					migrated++
				}
			} else if err := db.UpdateRowCompound(database.TblHITLDecisions, "decision_id", caseID, "tenant_id", tenantID,
				map[string]any{
					"department_id": req.TargetDept,
					"context_data":  string(ctxUpdate),
					"updated_at":    now,
				}); err == nil {
				migrated++
			}
		}

		respond.OK(w, map[string]any{
			"safe_to_delete": true,
			"open_cases":     openCount,
			"migrated":       migrated,
			"migrated_to":    req.TargetDept,
			"dept_id":        slug,
			"note":           fmt.Sprintf("%d cases migrated to %s — department %s is now safe to delete.", migrated, req.TargetDept, slug),
		})
	}
}
