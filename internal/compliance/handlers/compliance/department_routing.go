// department_route.go — FIX-036 (Patent P-06): AI-driven department routing endpoint.
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
//  2. Validates suggested departments against aocs_platform_departments.
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
	"github.com/ocx/shared/validate"
	"github.com/ocx/shared/types"
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
//	  "departments":      ["dept_security", "dept_compliance"],
//	  "capacity_status":  { "dept_security": { "available": true, "pending": 14, "max": 200 }, ... }
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
		respond.LimitBody(r)
		if !validate.Bind(w, r, &req) {
			return
		}
		if req.CaseType == "" && req.Description == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "at least one of case_type or description is required")
			return
		}

		result := classifier.Classify(r.Context(), req.CaseType, req.PolicyCategory, req.RuleType, req.Description)
		slog.Info("classification complete",
			"tenant_id", tenantID,
			"intent", result.Intent,
			"confidence", result.Confidence,
			"source", result.Source,
			"departments", result.Departments,
			"agent_id", req.AgentID,
		)

		var knownDepts []map[string]any
		// nolint:tenant_filter — aocs_platform_departments is GLOBAL by design.
		// Same model as global roles/permissions. Member ↔ dept association is in aocs_tenant_user_roles.
		if _dbErr := db.QueryRowsCtx(r.Context(), database.TblPlatformDepartments, "slug,name,enabled_features", "", "", &knownDepts); _dbErr != nil {
			slog.Error("db.QueryRows failed (best-effort)", "error", _dbErr)
		}
		deptMap := make(map[string]map[string]any, len(knownDepts))
		for _, d := range knownDepts {
			if s, ok2 := d["slug"].(string); ok2 && s != "" {
				deptMap[s] = d
			}
		}

		// Filter result departments to only those present in the DB.
		var validDepts []string
		var invalidDepts []string
		for _, dept := range result.Departments {
			if _, found := deptMap[dept]; found {
				validDepts = append(validDepts, dept)
			} else {
				invalidDepts = append(invalidDepts, dept)
			}
		}
		if len(invalidDepts) > 0 {
			slog.Warn("classifier returned unknown department slugs — filtered",
				"invalid", invalidDepts, "tenant_id", tenantID)
		}
		if len(validDepts) == 0 {
			// All classifier suggestions were invalid — fall back to compliance as the catch-all.
			// X-19 FIX: Was slog.Warn only — no platform event. Compliance team received cases
			// without knowing routing degraded. Now writes platform event for audit trail.
			slog.Warn("X-19: HITL routing fallback — no valid departments from classifier, defaulting to dept_compliance",
				"tenant_id", tenantID, "intent", result.Intent, "routing_source", result.RoutingSource)
			if _, exists := deptMap["dept_compliance"]; exists {
				validDepts = []string{"dept_compliance"}
				// Post audit event via ocx-core-svc API (boundary enforcement: no direct aocs_platform_events write).
				if coreClient != nil {
					concurrent.Go("hitl-routing-fallback-event", func() {
						_ = coreClient.PostEvent(context.Background(), map[string]any{
							"tenant_id":   tenantID,
							"event_type":  "HITL_ROUTING_CATCHALL",
							"entity_type": "department_routing",
							"action":      "FALLBACK_TO_COMPLIANCE",
							"new_value":   fmt.Sprintf(`{"intent":%q,"routing_source":%q,"invalid_depts":%d}`, result.Intent, result.RoutingSource, len(invalidDepts)),
							"created_at":  time.Now().UTC().Format(time.RFC3339),
						})
					})
				} else if _wErr := db.InsertRow(database.TblPlatformEvents, map[string]any{
					"tenant_id":   tenantID,
					"event_type":  "HITL_ROUTING_CATCHALL",
					"entity_type": "department_routing",
					"action":      "FALLBACK_TO_COMPLIANCE",
					"new_value":   fmt.Sprintf(`{"intent":%q,"routing_source":%q,"invalid_depts":%d}`, result.Intent, result.RoutingSource, len(invalidDepts)),
					"created_at":  time.Now().UTC().Format(time.RFC3339),
				}); _wErr != nil {
					slog.Error("SILENT_DROP_FIXED: InsertRow",
						"table", database.TblPlatformEvents, "file", "aocs-compliance/handlers/compliance/department_routing.go", "err", _wErr)
				}
			}
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
				if _dbErr := db.QueryRowsCompound(database.TblHITLDecisions, "decision_id",
					"department_id", dept, "status", "PENDING", &pendingRows); _dbErr != nil {
					slog.Error("db.QueryRowsCompound failed (best-effort)", "error", _dbErr)
				}
				available := len(pendingRows) < maxCases
				capacityStatus[dept] = map[string]any{
					"available": available,
					"pending":   len(pendingRows),
					"max":       maxCases,
				}
				if !available {
					slog.Warn("department at capacity",
						"dept", dept, "pending", len(pendingRows), "max", maxCases)
				}
			}
		}

		concurrent.Go("department_routing", func() {
			if _dbErr := db.InsertRow(database.TblPlatformEvents, map[string]any{
				"event_type": "department_route_query",
				"tenant_id":  tenantID,
				"agent_id":   req.AgentID,
				"metadata": map[string]any{
					"decision_type": req.CaseType,
					"intent":      result.Intent,
					"confidence":  result.Confidence,
					"source":      result.Source,
					"departments": validDepts,
				},
			}); _dbErr != nil {
				slog.Error("db.InsertRow failed (best-effort)", "error", _dbErr)
			}
		})

		// ── Response ───────────────────────────────────────────────────────────
		// F-HITL-03 FIX: UI had no easy way to detect degraded routing — add routing_degraded bool.
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
			"capacity_status":  capacityStatus,
			"filtered_out":     invalidDepts,
			"note": fmt.Sprintf(
				"Routing driven by AI intent classification (P-06). Source: %s. Degraded: %v.",
				result.Source, routingDegraded,
			),
		})
	}
}
