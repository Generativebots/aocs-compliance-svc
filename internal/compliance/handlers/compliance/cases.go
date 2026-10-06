// Package compliance — HITL / edge-case resolution handlers.
// Cases CRUD: this file | ZKP proof chain + batch: see cases_proof.go
package compliance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/concurrent"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/eventbus"
	"github.com/ocx/shared/infra/serviceclient"

	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/types"
	"github.com/ocx/shared/validate"
)

// HandleListCases returns compliance / HITL cases for the current tenant.
// GET /hitl/cases  |  GET /cases
//
// the browser just for client-side filtering (expensive at scale).
//
// Supported query params:
//
//	?case_type=SELF_HEAL|AGENT_ESC|JURY_DEADLOCK
//	?department_id=<slug>
//	?status=PENDING|APPROVED|REJECTED|TIMEOUT
//	?agent_id=<uuid>
func HandleListCases(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		isSuperAdmin := false
		if tenantID == "" {
			au, authErr := auth.GetAuthUser(r.Context())
			if authErr != nil || au == nil || au.Role != auth.RoleSuperAdmin {
				auRole := ""
				if au != nil {
					auRole = string(au.Role)
				}
				slog.Warn("ListCases: missing tenant_id and caller is not super_admin",
					"role", auRole, "remote_addr", r.RemoteAddr)
				respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized, "tenant context required")
				return
			}
			isSuperAdmin = true
		}

		// ── JOIN query: enrich each case with agent name + policy name ──────────
		// AOCS's first multi-table JOIN — previously every handler issued single-table
		// Supabase REST calls with no cross-table enrichment.  QueryRawCtx uses pgxPool
		// directly and falls back to nil (empty) when the pool is unavailable.
		var rows []map[string]any
		var joinSQL string
		var joinArgs []any

		// Parse pagination parameters (GAP-CRUD-8)
		limit := 100
		if lv := r.URL.Query().Get("limit"); lv != "" {
			if n, err := strconv.Atoi(lv); err == nil && n > 0 && n <= 500 {
				limit = n
			}
		}
		offset := 0
		if ov := r.URL.Query().Get("offset"); ov != "" {
			if n, err := strconv.Atoi(ov); err == nil && n >= 0 {
				offset = n
			}
		}

		if isSuperAdmin {
			joinSQL = `
				SELECT
					h.decision_id, h.decision_id          AS case_id,
					h.tenant_id,   h.agent_id,            h.request_id,
					h.decision_type, h.status,            h.case_type,
					h.priority,    h.context_data,        h.decision_data,
					h.action_payload, h.financial_value,  h.financial_exposure,
					h.risk_score,  h.identity_score       AS trust_score,
					h.entropy_score, h.cognitive_score,
					h.quorum_required, h.quorum_achieved, h.jury_pool_size,
					h.assigned_to, h.policy_id,           h.gate_tool_name,
					h.reason,      h.result,              h.source,
					h.created_at,  h.updated_at,          h.expires_at,
					h.sla_breach_at, h.sla_breached,      h.sla_breached_at,
					h.auto_escalated, h.override_verdict,
					h.verdict_id,  h.jury_case_id,
					-- JOINed enrichment
					COALESCE(a.name, '')         AS agent_name,
					COALESCE(p.name, '')         AS policy_name
				FROM core_hitl h
				LEFT JOIN core_agents         a ON a.agent_id  = h.agent_id  AND a.tenant_id = h.tenant_id
				LEFT JOIN core_policies      p ON p.policy_id = h.policy_id AND p.tenant_id = h.tenant_id
				ORDER BY h.created_at DESC
				LIMIT $1 OFFSET $2`
			joinArgs = []any{limit, offset}
		} else {
			//nolint:tenant_filter — tenantID injected as $1
			joinSQL = `
				SELECT
					h.decision_id, h.decision_id          AS case_id,
					h.tenant_id,   h.agent_id,            h.request_id,
					h.decision_type, h.status,            h.case_type,
					h.priority,    h.context_data,        h.decision_data,
					h.action_payload, h.financial_value,  h.financial_exposure,
					h.risk_score,  h.identity_score       AS trust_score,
					h.entropy_score, h.cognitive_score,
					h.quorum_required, h.quorum_achieved, h.jury_pool_size,
					h.assigned_to, h.policy_id,           h.gate_tool_name,
					h.reason,      h.result,              h.source,
					h.created_at,  h.updated_at,          h.expires_at,
					h.sla_breach_at, h.sla_breached,      h.sla_breached_at,
					h.auto_escalated, h.override_verdict,
					h.verdict_id,  h.jury_case_id,
					-- JOINed enrichment: agent display name + policy name in one round-trip
					COALESCE(a.name, '')         AS agent_name,
					COALESCE(p.name, '')         AS policy_name
				FROM core_hitl h
				LEFT JOIN core_agents         a ON a.agent_id  = h.agent_id  AND a.tenant_id = h.tenant_id
				LEFT JOIN core_policies      p ON p.policy_id = h.policy_id AND p.tenant_id = h.tenant_id
				WHERE h.tenant_id = $1
				ORDER BY h.created_at DESC
				LIMIT $2 OFFSET $3`
			joinArgs = []any{tenantID, limit, offset}
		}

		joinErr := db.QueryRawCtx(r.Context(), joinSQL, &rows, joinArgs...)
		if joinErr != nil || rows == nil {
			// Fallback to plain single-table query when pgxPool unavailable
			slog.Warn("ListCases: JOIN query failed or pool unavailable, falling back",
				"tenant_id", tenantID, "join_err", joinErr)
			var plainErr error
			if tenantID != "" {
				plainErr = db.QueryRowsCtx(r.Context(), database.TblCoreHitl, database.ColsHITLDecision, "tenant_id", tenantID, &rows)
			} else {
				// SECURITY: tenantID is empty — this means the JWT claim is missing or
				// malformed. Returning unscoped data would be a cross-tenant data leak.
				// Deny by default (Google/AWS IAM zero-trust principle).
				slog.Error("ListCases: tenantID empty in fallback path — aborting to prevent cross-tenant leak")
				respond.InternalError(w, http.StatusBadRequest, "missing tenant context", nil)
				return
			}
			if plainErr != nil {
				slog.Error("ListCases fallback failed", "tenant_id", tenantID, "error", plainErr)
				respond.InternalError(w, http.StatusInternalServerError, "list cases", plainErr)
				return
			}
		}

		if rows == nil {
			rows = []map[string]any{}
		}

		// doesn't support JSONB WHERE or multi-column AND in a single QueryRows call.
		// Eliminates full-dataset browser downloads at scale (10k+ cases).
		caseTypeFilter := r.URL.Query().Get("case_type")
		deptFilter := r.URL.Query().Get("department_id")
		statusFilter := r.URL.Query().Get("status")
		agentIDFilter := r.URL.Query().Get("agent_id")

		// (9.4): Deduplicate by decision_id + apply query filters in one pass.
		seen := make(map[string]bool, len(rows))
		deduped := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			id, _ := row["decision_id"].(string)
			if id != "" {
				if seen[id] {
					continue
				}
				seen[id] = true
			}
			if caseTypeFilter != "" {
				ct, _ := row["case_type"].(string)
				if ct != caseTypeFilter {
					continue
				}
			}
			if deptFilter != "" {
				did, _ := row["department_id"].(string)
				if did != deptFilter {
					continue
				}
			}
			if statusFilter != "" {
				st, _ := row["status"].(string)
				if st != statusFilter {
					continue
				}
			}
			if agentIDFilter != "" {
				ai, _ := row["agent_id"].(string)
				if ai != agentIDFilter {
					continue
				}
			}
			deduped = append(deduped, row)
		}
		respond.OK(w, map[string]any{
			"cases":  deduped,
			"total":  len(deduped),
			"limit":  limit,
			"offset": offset,
		})
	}
}

// HandleResolveCase submits an arbitration decision for a case.

// POST /hitl/cases/{case_id}/arbitrate  |  POST /cases/{id}/arbitrate
//
// psBroker is optional — if non-nil, the verdict is published to
// TopicVerdictRecorded so SDK polling clients can resume the blocked agent action.
func HandleResolveCase(db database.DB, psBroker *eventbus.PubSubBroker, coreClients ...*serviceclient.Client) http.HandlerFunc {
	var coreClient *serviceclient.Client
	if len(coreClients) > 0 {
		coreClient = coreClients[0]
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		vars := mux.Vars(r)
		caseID := vars["case_id"]
		if caseID == "" {
			caseID = vars["id"]
		}
		if caseID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing case id")
			return
		}
		respond.LimitBody(r)
		var body map[string]any
		if !validate.Bind(w, r, &body) {
			return
		}

		// Read verdict or vote from body and map to the CHECK-constrained values.
		verdict, _ := body["verdict"].(string)
		if verdict == "" {
			vote, _ := body["vote"].(string)
			switch vote {
			case "reject", "REJECT", "REJECTED":
				verdict = "REJECTED"
			default:
				verdict = "APPROVED"
			}
		}
		if verdict != "APPROVED" && verdict != "REJECTED" {
			verdict = "APPROVED" // safe fallback
		}

		rationale, _ := body["rationale"].(string)
		// X-User-Id is a client-supplied header and is trivially spoofable without mTLS.
		var reviewerID string
		if au, auErr := auth.GetAuthUser(r.Context()); auErr == nil && au != nil && au.UserID != "" {
			reviewerID = au.UserID
		} else {
			// Fallback for legacy clients still sending the header; log the event.
			reviewerID = auth.GetUserID(r.Context())
			if reviewerID != "" {
				slog.Warn("ArbitrateCase: reviewer from X-User-Id header (JWT missing user claim)",
					"case_id", caseID, "reviewer", reviewerID)
			}
		}
		now := time.Now().UTC().Format(time.RFC3339)

		// Build clean update — only schema-valid core_hitl columns.
		// decision_data JSONB stores the full arbitration record (rationale, reviewer, timestamp).
		ddBytes, _ := json.Marshal(map[string]any{
			"decision":   verdict,
			"rationale":  rationale,
			"reviewer":   reviewerID,
			"decided_at": now,
		})
		update := map[string]any{
			"status":        verdict,
			"responded_at":  now,
			"decision_data": string(ddBytes), // serialised JSONB
		}

		// Without this, a network retry or double-submit overwrites the audit-logged verdict.
		// Mirrors the RecordVerdict idempotency pattern in the Python jury service.

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		// transaction. Without this, two concurrent verdict submissions can both pass
		// the terminal-status check and both overwrite the decided verdict (TOCTOU race).
		// Pattern: WithTransaction → QueryRowsCompoundForUpdate (lock) → UpdateRowCompound.
		var txErr error
		txErr = db.WithTransaction(r.Context(), func(tx database.DB) error {
			var existing []map[string]any
			if err := tx.QueryRowsCompoundForUpdate(database.TblCoreHitl, "decision_id,status",
				"decision_id", caseID, "tenant_id", tenantID, &existing); err != nil {
				return fmt.Errorf("lock decision row: %w", err)
			}
			if len(existing) == 0 {
				return fmt.Errorf("not_found")
			}
			curStatus, _ := existing[0]["status"].(string)
			switch curStatus {
			case "APPROVED", "REJECTED", "MERGED", "RESOLVED":
				return fmt.Errorf("terminal:%s", curStatus)
			}
			if err := tx.UpdateRowCompound(database.TblCoreHitl, "decision_id", caseID, "tenant_id", tenantID, update); err != nil {
				return fmt.Errorf("update verdict: %w", err)
			}
			// Audit row written durably in the same transaction as the verdict update
			capturedAgent, _ := body["agent_id"].(string)
			auditRow := map[string]any{
				"action":    "HITL_VERDICT",
				"tenant_id": tenantID,
				"entity_id": caseID,
				"agent_id":  capturedAgent,
				"user_id":   reviewerID,
				"verdict":   verdict,
			}
			if aErr := tx.InsertRow(database.TblCoreEvents, auditRow); aErr != nil {
				slog.Warn("ArbitrateCase: failed to write audit row in tx (non-fatal)", "error", aErr)
			}
			return nil
		})
		if txErr != nil {
			if txErr.Error() == "not_found" {
				respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "case not found")
				return
			}
			if strings.HasPrefix(txErr.Error(), "terminal:") {
				curStatus := strings.TrimPrefix(txErr.Error(), "terminal:")
				respond.JSON(w, http.StatusConflict, map[string]any{
					"case_id": caseID,
					"status":  curStatus,
					"note":    "case already decided — re-arbitration not permitted (idempotency)",
				})
				return
			}
			slog.Error("ArbitrateCase failed", "case_id", caseID, "error", txErr)
			respond.InternalError(w, http.StatusInternalServerError, "arbitrate case", txErr)
			return
		}
		capturedVerdict := verdict
		capturedReviewer := reviewerID
		capturedCase := caseID
		capturedAgent, _ := body["agent_id"].(string)
		capturedTenant := tenantID // tenantID already fetched above for idempotency check

		// If coreClient is configured, also notify core service asynchronously
		if coreClient != nil {
			concurrent.GoDetached(r.Context(), 10*time.Second, "cases/hitl_verdict_core_event", func(bgCtx context.Context) {
				auditRow := map[string]any{
					"action":    "HITL_VERDICT",
					"tenant_id": capturedTenant,
					"entity_id": capturedCase, "agent_id": capturedAgent,
					"user_id": capturedReviewer, "verdict": capturedVerdict,
				}
				if _err := coreClient.PostEvent(bgCtx, auditRow); _err != nil {
					slog.Error("coreClient.PostEvent HITL_VERDICT failed", "error", _err)
				}
			})
		}

		// 4: Publish verdict to TopicVerdictRecorded so SDK polling clients
		// and jury consumers can unblock the suspended agent action.
		// Without this, the gate has no feedback loop after HITL approval.
		// Best-effort: if publish fails, the audit log above still captures the verdict.
		if psBroker != nil {
			concurrent.GoDetached(r.Context(), 10*time.Second, "cases/hitl_verdict_publish", func(bgCtx context.Context) {
				payload, _ := json.Marshal(map[string]any{
					"schema_version": "1",
					"event":          "HITL_VERDICT",
					"case_id":        capturedCase,
					"tenant_id":      capturedTenant,
					"agent_id":       capturedAgent,
					"verdict":        capturedVerdict,
					"reviewer":       capturedReviewer,
					"decided_at":     time.Now().UTC().Format(time.RFC3339),
				})
				orderKey := capturedTenant + ":" + capturedAgent
				if err := psBroker.PublishOrdered(bgCtx, eventbus.TopicVerdictRecorded(), orderKey, payload); err != nil {
					slog.Error("post-verdict publish failed (best-effort)", "case_id", capturedCase, "error", err)
				}
			})
		}

		respond.OK(w, map[string]string{"status": verdict, "case_id": caseID})
	}
}

// HandleAssignCase assigns a case to a reviewer/agent.
// POST /hitl/cases/{case_id}/assign  |  POST /cases/{id}/assign
//
// assigned_to may be either:
//   - A user UUID  → stored in user_id column
//   - A role slug  → stored in context_data.assigned_role (UUID validation prevents 500)
//
// HandleAssignCase assigns a HITL case to a user/role and auto-routes to departments.
// When department_ids is not provided in the request body, the IntentClassifier is used
// to determine routing via AI (falling back to local keyword scoring if AI is unavailable).
var (
	errAssignNotFound = errors.New("case not found")
	errAssignTerminal = errors.New("case is in terminal status")
	// assignTerminalStatuses — chk_hitl_status values after which a case can no longer be (re)assigned.
	assignTerminalStatuses = map[string]bool{
		"RESOLVED": true, "APPROVED": true, "REJECTED": true, "CANCELLED": true, "CLOSED": true,
		"OVERRIDDEN": true, "COURSE_CORRECTED": true, "TIMED_OUT": true, "TIMEOUT": true,
	}
)

func HandleAssignCase(db database.DB, classifier types.IntentClassifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		vars := mux.Vars(r)
		caseID := vars["case_id"]
		if caseID == "" {
			caseID = vars["id"]
		}
		if caseID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing case id")
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		respond.LimitBody(r)
		var req struct {
			AssignedTo     string   `json:"assigned_to"`
			ReviewerID     string   `json:"reviewer_id"`
			DepartmentID   string   `json:"department_id"`
			DepartmentIDs  []string `json:"department_ids"`
			Reason         string   `json:"reason"`
			CaseType       string   `json:"case_type"`
			PolicyCategory string   `json:"policy_category"`
			RuleType       string   `json:"rule_type"`
			Description    string   `json:"description"`
		}
		if !validate.Bind(w, r, &req) {
			return
		}
		operatorID := auth.GetUserID(r.Context())
		// assigned_to (user UUID or role slug) | reviewer_id (alias) | the caller ("Assign to Me").
		assignedTo := strings.TrimSpace(req.AssignedTo)
		if assignedTo == "" {
			assignedTo = strings.TrimSpace(req.ReviewerID)
		}
		if assignedTo == "" {
			assignedTo = operatorID
		}
		if assignedTo == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "assigned_to (or reviewer_id) is required")
			return
		}
		now := time.Now().UTC().Format(time.RFC3339)

		update := map[string]any{
			"status":      "ASSIGNED",
			"assigned_to": assignedTo,
			"assigned_at": now,
			"updated_at":  now,
		}
		if operatorID != "" {
			update["updated_by"] = operatorID
		}

		// Accept department_ids[] for multi-department routing.
		// When department_ids is empty, auto-route using AI-driven classification.
		deptIDs := req.DepartmentIDs
		if d := strings.TrimSpace(req.DepartmentID); d != "" {
			deptIDs = append(deptIDs, d)
		}
		// Auto-route when no departments specified: use AI IntentClassifier.

		// department routing. Falls back to local TF-IDF keyword scoring when AI
		// is unavailable. Both paths are deterministic and audited.
		// Only classify when there is something to classify — a bare reviewer
		// assignment carries no case_type/description signal.
		hasClassSignal := req.CaseType != "" || req.PolicyCategory != "" || req.RuleType != "" || req.Description != ""
		if len(deptIDs) == 0 && hasClassSignal {
			classResult := classifier.Classify(r.Context(), req.CaseType, req.PolicyCategory, req.RuleType, req.Description)
			deptIDs = classResult.Departments
			// ai_intent, ai_confidence, routing_source are NOT real DB columns.
			// Store classification metadata in context_data JSONB to avoid 500s.
			classificationMeta := map[string]any{
				"ai_intent":      classResult.Intent,
				"ai_confidence":  classResult.Confidence,
				"routing_source": classResult.Source,
			}
			// Merge into context_data later (after body parse section)
			update["_classification_meta"] = classificationMeta
			slog.Info("department routing",
				"case_id", caseID, "intent", classResult.Intent,
				"confidence", classResult.Confidence, "source", classResult.Source,
				"departments", deptIDs)
		}
		// Assigns to non-existent departments leave cases permanently unrouted.
		// Skipped for AI-routed depts (classifier is responsible for its own slug validity).
		if len(deptIDs) > 0 {
			var knownDepts []map[string]any
			// nolint:tenant_filter — syst_departments is GLOBAL by design.
			// Standard departments (Engineering, Compliance, Finance, Legal…) are shared
			// across ALL tenants — same model as global roles/permissions.
			// Only member association (syst_user_roles) is tenant-scoped.
			if _dbErr := db.QueryRowsCtx(r.Context(), database.TblSystDepartments, "slug,enabled_features", "", "", &knownDepts); _dbErr != nil {
				slog.Error("db.QueryRows failed (best-effort)", "error", _dbErr)
			}
			deptMap := make(map[string]map[string]any, len(knownDepts))
			for _, d := range knownDepts {
				if s, ok := d["slug"].(string); ok && s != "" {
					deptMap[s] = d
				}
			}
			var invalid []string
			for _, dept := range deptIDs {
				if _, found := deptMap[dept]; !found {
					invalid = append(invalid, dept)
				}
			}
			if len(invalid) > 0 {
				respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest,
					fmt.Sprintf("department(s) not found in syst_departments: %v", invalid))
				return
			}

			// A HITL case assigned to a department with HITL disabled will sit
			// unactioned indefinitely with no error — prevent this at assignment time.
			for _, dept := range deptIDs {
				d := deptMap[dept]
				ef, _ := d["enabled_features"].(map[string]any)
				if ef != nil {
					hitlEnabled, hasKey := ef["hitl"]
					if hasKey {
						switch v := hitlEnabled.(type) {
						case bool:
							if !v {
								respond.ErrorWithCode(w, http.StatusUnprocessableEntity, respond.ErrCodeValidation,
									fmt.Sprintf("department '%s' has HITL disabled (enabled_features.hitl=false) — enable it before assigning cases", dept))
								return
							}
						case string:
							if v == "false" || v == "0" {
								respond.ErrorWithCode(w, http.StatusUnprocessableEntity, respond.ErrCodeValidation,
									fmt.Sprintf("department '%s' has HITL disabled — enable it before assigning cases", dept))
								return
							}
						}
					}
				}
			}

			// DEPT_MAX_HITL_CASES configures the maximum number of open PENDING cases
			// a department can hold before new assignments are rejected. Default: 200.
			maxCases := 200
			if v := os.Getenv("DEPT_MAX_HITL_CASES"); v != "" {
				if n, err2 := strconv.Atoi(v); err2 == nil && n > 0 {
					maxCases = n
				}
			}
			for _, dept := range deptIDs {
				var pendingRows []map[string]any
				if _dbErr := db.QueryRowsCompound(database.TblCoreHitl, "decision_id",
					"department_id", dept, "status", "PENDING", &pendingRows); _dbErr != nil {
					slog.Error("db.QueryRowsCompound failed (best-effort)", "error", _dbErr)
				}
				if len(pendingRows) >= maxCases {
					respond.JSON(w, http.StatusTooManyRequests, map[string]any{
						"error":         fmt.Sprintf("department '%s' has reached the HITL case capacity limit (%d pending). Resolve existing cases or reassign to another department.", dept, maxCases),
						"department":    dept,
						"pending_count": len(pendingRows),
						"max_capacity":  maxCases,
					})
					return
				}
			}
		}

		// (8.5): Persist case_type for self-heal classification and FA-03 §7 server-side filter.
		if req.CaseType != "" {
			update["case_type"] = req.CaseType
		}

		// Validate whether assigned_to is a UUID (user) or a role slug.
		// Writing a non-UUID into user_id causes downstream UUID joins to fail,
		// so only real user UUIDs go to user_id; role slugs go to assigned_role.
		if _, uuidErr := uuid.Parse(assignedTo); uuidErr == nil {
			update["user_id"] = assignedTo
			update["reviewer_id"] = assignedTo
		} else {
			update["assigned_role"] = assignedTo
		}
		if len(deptIDs) == 1 {
			update["department_id"] = deptIDs[0]
		}
		classMeta, _ := update["_classification_meta"].(map[string]any)
		delete(update, "_classification_meta") // temp key — never a DB column

		// Lock the case, reject missing/terminal cases honestly, merge
		// assignment metadata into context_data, update and write the audit row
		// in one transaction.
		var caseRows []map[string]any
		if txErr := db.WithTransaction(r.Context(), func(tx database.DB) error {
			if qErr := tx.QueryRowsCompoundForUpdate(database.TblCoreHitl, "status,context_data",
				"decision_id", caseID, "tenant_id", tenantID, &caseRows); qErr != nil {
				return qErr
			}
			if len(caseRows) == 0 {
				return errAssignNotFound
			}
			if st, _ := caseRows[0]["status"].(string); assignTerminalStatuses[strings.ToUpper(st)] {
				return fmt.Errorf("%w: %s", errAssignTerminal, st)
			}
			ctxData := map[string]any{}
			if cd, ok := caseRows[0]["context_data"].(map[string]any); ok {
				for k, v := range cd {
					ctxData[k] = v
				}
			}
			ctxData["assigned_to"] = assignedTo
			ctxData["assigned_by"] = operatorID
			ctxData["assigned_at"] = now
			if len(deptIDs) > 0 {
				ctxData["department_ids"] = deptIDs
			}
			if req.Reason != "" {
				ctxData["assignment_reason"] = req.Reason
			}
			for k, v := range classMeta {
				ctxData[k] = v
			}
			// pgx cannot encode nested map[string]any → JSONB directly.
			cdBytes, jsonErr := json.Marshal(ctxData)
			if jsonErr != nil {
				return fmt.Errorf("marshal context_data: %w", jsonErr)
			}
			update["context_data"] = string(cdBytes)

			if err := tx.UpdateRowCompound(database.TblCoreHitl, "decision_id", caseID, "tenant_id", tenantID, update); err != nil {
				return err
			}
			assignEvent := map[string]any{
				"event_id":    generatePlatformID(),
				"entity_id":   caseID,
				"entity_type": "hitl_case",
				"tenant_id":   tenantID,
				"event_type":  "CASE_ASSIGNED",
				"payload": map[string]any{
					"case_id":        caseID,
					"assigned_to":    assignedTo,
					"assigned_by":    operatorID,
					"department_ids": deptIDs,
					"reason":         req.Reason,
					"occurred_at":    now,
				},
			}
			if err := tx.InsertRow(database.TblCoreEvents, assignEvent); err != nil {
				slog.Warn("AssignCase: audit insert failed in tx (non-fatal)", "case_id", caseID, "error", err)
			}
			return nil
		}); txErr != nil {
			switch {
			case errors.Is(txErr, errAssignNotFound):
				respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "case not found")
			case errors.Is(txErr, errAssignTerminal):
				respond.ErrorWithCode(w, http.StatusConflict, respond.ErrCodeConflict, txErr.Error()+" — assignment not permitted")
			default:
				slog.Error("AssignCase failed", "case_id", caseID, "error", txErr)
				respond.InternalError(w, http.StatusInternalServerError, "assign case", txErr)
			}
			return
		}
		respond.OK(w, map[string]any{"status": "ASSIGNED", "case_id": caseID, "assigned_to": assignedTo, "department_ids": deptIDs})
	}
}

// HandleCreateCase — POST /api/v1/cases
//
// Canonical path: delegates to CreateCase() in case_lifecycle.go which
// provides SLA deadline tracking (CIP-2), lifecycle events, CIP-4 Sentinel
// escalation marking, Copilot context push, and Pub/Sub schema v2 payload.
//
// The old inline implementation has been superseded — do NOT reintroduce a
// raw db.InsertRow here.
func HandleCreateCase(db database.DB, psBroker *eventbus.PubSubBroker, coreClients ...*serviceclient.Client) http.HandlerFunc {
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
		respond.LimitBody(r)

		var input CreateCaseInput
		if !validate.Bind(w, r, &input) {
			return
		}
		input.TenantID = tenantID // always trust JWT tenant — never body

		if input.CaseType == "" || input.AgentID == "" || input.Reason == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "case_type, agent_id, and reason are required")
			return
		}
		validTypes := map[string]bool{
			"SELF_HEAL": true, "AGENT_ESC": true, "JURY_DEADLOCK": true,
			"COMPLIANCE": true, "MANUAL": true, "SOP_DRIFT_VIOLATION": true,
			"SENTINEL_ALERT": true, "GRA_VIOLATION": true,
		}
		if !validTypes[input.CaseType] {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest,
				"case_type must be one of: SELF_HEAL, AGENT_ESC, JURY_DEADLOCK, COMPLIANCE, MANUAL, SOP_DRIFT_VIOLATION, SENTINEL_ALERT, GRA_VIOLATION")
			return
		}

		created, err := CreateCase(r.Context(), db, psBroker, input, coreClient)
		if err != nil {
			slog.Error("HandleCreateCase failed", "tenant_id", tenantID, "err", err)
			respond.InternalError(w, http.StatusInternalServerError, "failed to create case", err)
			return
		}

		respond.JSON(w, http.StatusCreated, map[string]any{
			"case_id":         created.CaseID,
			"tenant_id":       created.TenantID,
			"status":          string(created.Status),
			"priority":        string(created.Priority),
			"sla_deadline_at": created.SLADeadline.Format(time.RFC3339),
			"created_at":      created.CreatedAt.Format(time.RFC3339),
		})
	}
}

// HandleCreateCaseComment — see internal/handlers/compliance/case_comments.go
// (moved to avoid redeclaration; cases.go previously contained a stub)
