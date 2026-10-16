// department_route.go — AI-driven department routing endpoint.
//
// POST /api/v1/departments/route
//
// The patent (P-06) requires that department assignment be driven by an AI
// intent classifier, NOT by static configuration or manual selection alone.
// This endpoint exposes that capability as a standalone consultable service so:
//   - The Co-Pilot dashboard can call it during case creation to auto-suggest departments.
//   - A2A orchestrator agents can pre-route sub-tasks before HITL escalation.
//   - SDK callers can route ad-hoc without opening a full HITL case.
//
// The handler:
//  1. Calls the IntentClassifier (→ ENT AI service or local TF-IDF fallback).
//  2. Validates suggested departments against syst_departments.
//  3. Checks current capacity per department (DEPT_MAX_HITL_CASES).
//  4. Returns a ranked routing recommendation with metadata for the caller.
package compliance

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/concurrent"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/serviceclient"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/types"
	"github.com/ocx/shared/validate"
)

// HandleRouteDepartment — POST /api/v1/departments/route
//
// Request body:
//
//	{
//	  "decision_type": "AGENT_ESC",,
//	  "policy_category":  "data_privacy",
//	  "rule_type":        "GDPR",
//	  "description":      "Agent tried to export PII to external S3 bucket",
//	  "agent_id":         "<uuid>",      // optional: attach to audit
//	  "check_capacity":   true            // optional: include capacity check (default true)
//	}
//
// Response:
//
//	{
//	  "intent":           "data_leak",
//	  "confidence":       0.87,
//	  "source":           "ai",               // or "local_fallback"
//	  "departments":      ["<department_id>", "<department_id>"],
//	  "department_names": ["Security", "Compliance"],
//	  "capacity_status":  { "<department_id>": { "department_name": "Security", "available": true, "pending": 14, "max": 200 }, ... }
//	}
func HandleRouteDepartment(db database.DB, classifier types.IntentClassifier, coreClient *serviceclient.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		if classifier == nil {
			respond.ErrorWithCode(w, http.StatusServiceUnavailable, respond.ErrCodeUnavailable, "department routing classifier not configured")
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		respond.LimitBody(r)

		var req DepartmentRouteRequest
		// (BATCH): removed duplicate LimitBody — double-wrapping halves max body size
		if !validate.Bind(w, r, &req) {
			return
		}
		if req.CaseType == "" && req.Description == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "at least one of case_type or description is required")
			return
		}

		result := classifier.Classify(r.Context(), req.CaseType, req.PolicyCategory, req.RuleType, req.Description)
		if result == nil {
			respond.ErrorWithCode(w, http.StatusServiceUnavailable, respond.ErrCodeUnavailable,
				"department routing classifier unavailable — pass department_ids explicitly")
			return
		}
		slog.Info("classification complete",
			"tenant_id", tenantID,
			"intent", result.Intent,
			"confidence", result.Confidence,
			"source", result.Source,
			"departments", result.Departments,
			"agent_id", req.AgentID,
		)

		depts, deptErr := loadTenantDepartments(r.Context(), db, tenantID)
		if deptErr != nil {
			respond.InternalError(w, http.StatusServiceUnavailable, "could not load departments", deptErr)
			return
		}

		// Resolve classifier output to department_id PKs; drop anything unknown.
		var validDepts []string
		var invalidDepts []string
		seen := make(map[string]bool, len(result.Departments))
		for _, key := range result.Departments {
			d, found := depts.resolve(key)
			if !found {
				invalidDepts = append(invalidDepts, key)
				continue
			}
			if !seen[d.ID] {
				seen[d.ID] = true
				validDepts = append(validDepts, d.ID)
			}
		}
		if len(invalidDepts) > 0 {
			slog.Warn("classifier returned unknown departments — filtered",
				"invalid", invalidDepts, "tenant_id", tenantID)
		}
		if len(validDepts) == 0 {
			// No hardcoded catch-all department key: record the miss and make the
			// caller choose explicitly.
			slog.Warn("X-19: HITL routing unresolved — no valid departments from classifier",
				"tenant_id", tenantID, "intent", result.Intent, "routing_source", result.RoutingSource)
			evt := map[string]any{
				"tenant_id":   tenantID,
				"event_type":  "HITL_ROUTING_UNRESOLVED",
				"entity_type": "department_routing",
				"action":      "NO_VALID_DEPARTMENT",
				"new_value":   fmt.Sprintf(`{"intent":%q,"routing_source":%q,"invalid_depts":%d}`, result.Intent, result.RoutingSource, len(invalidDepts)),
				"created_at":  time.Now().UTC().Format(time.RFC3339),
			}
			if coreClient != nil {
				concurrent.Go("hitl-routing-unresolved-event", func() {
					if evErr := coreClient.PostEvent(context.Background(), evt); evErr != nil {
						slog.Warn("HITL routing unresolved: audit event delivery to core failed (non-fatal)",
							"tenant_id", tenantID, "intent", result.Intent, "error", evErr)
					}
				})
			} else if _wErr := db.InsertRow(database.TblCoreEvents, evt); _wErr != nil {
				slog.Error("db write failed: InsertRow",
					"table", database.TblCoreEvents, "file", "aocs-compliance/handlers/compliance/department_routing.go", "err", _wErr)
			}
			respond.ErrorWithCode(w, http.StatusUnprocessableEntity, "department_required",
				"no matching department for this case — pass department_ids explicitly")
			return
		}

		checkCapacity := true
		if req.CheckCapacity != nil {
			checkCapacity = *req.CheckCapacity
		}
		maxCases := 200
		if v := os.Getenv("DEPT_MAX_HITL_CASES"); v != "" {
			if n, err2 := strconv.Atoi(v); err2 == nil && n > 0 {
				maxCases = n
			}
		}

		capacityStatus := make(map[string]any, len(validDepts))
		if checkCapacity {
			for _, dept := range validDepts {
				var pendingRows []map[string]any
				if cc := hitlCore(coreClient); cc != nil {
					rows, _lErr := cc.ListHITLCases(r.Context(), tenantID, map[string]string{"department_id": dept, "status": "PENDING"}, 1000)
					if _lErr != nil {
						slog.Error("core ListHITLCases failed (best-effort)", "error", _lErr)
					}
					pendingRows = rows
				}
				available := len(pendingRows) < maxCases
				capacityStatus[dept] = map[string]any{
					"department_name": depts.name(dept),
					"available":       available,
					"pending":         len(pendingRows),
					"max":             maxCases,
				}
				if !available {
					slog.Warn("department at capacity",
						"department_id", dept, "pending", len(pendingRows), "max", maxCases)
				}
			}
		}

		concurrent.Go("department_routing", func() {
			if _dbErr := db.InsertRow(database.TblCoreEvents, map[string]any{
				"event_type": "department_route_query",
				"tenant_id":  tenantID,
				"agent_id":   req.AgentID,
				"metadata": map[string]any{
					"decision_type": req.CaseType,
					"intent":        result.Intent,
					"confidence":    result.Confidence,
					"source":        result.Source,
					"departments":   validDepts,
				},
			}); _dbErr != nil {
				slog.Error("db.InsertRow failed (best-effort)", "error", _dbErr)
			}
		})

		// ── Response ───────────────────────────────────────────────────────────
		// UI had no easy way to detect degraded routing — add routing_degraded bool.
		routingDegraded := result.RoutingSource == "hardcoded_fallback_db_error" ||
			result.RoutingSource == "hardcoded_fallback_empty"
		if routingDegraded {
			slog.Warn("F-HITL-03: HITL routing is DEGRADED — using hardcoded fallback, not DB config. "+
				"Department assignments may be incorrect. Check database connectivity.",
				"routing_source", result.RoutingSource, "tenant_id", tenantID)
		}
		respond.JSON(w, http.StatusOK, map[string]any{
			"intent":           result.Intent,
			"confidence":       result.Confidence,
			"source":           result.Source, // "ai" | "local_fallback"
			"routing_source":   result.RoutingSource,
			"routing_degraded": routingDegraded,
			"departments":      validDepts,
			"department_names": depts.names(validDepts),
			"capacity_status":  capacityStatus,
			"filtered_out":     invalidDepts,
			"note": fmt.Sprintf(
				"Routing driven by AI intent classification (P-06). Source: %s. Degraded: %v.",
				result.Source, routingDegraded,
			),
		})
	}
}
