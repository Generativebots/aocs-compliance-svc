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
//	?department_id=<syst_departments.department_id>
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
			if authErr != nil || au == nil || !au.IsSuperAdmin {
				auRole := ""
				if au != nil {
					auRole = au.RoleName
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

		// Row 9 (CM-01): read compliance's own event-fed projection of core_hitl
		// (compl_core_projection, kind='hitl_case'); agent/policy display names are
		// already resolved in the payload. No core_* table is read here.
		if isSuperAdmin {
			joinSQL = hitlCaseSelect + hitlCaseOrder + ` LIMIT $1 OFFSET $2`
			joinArgs = []any{limit, offset}
		} else {
			//nolint:tenant_filter — tenantID injected as $1
			joinSQL = hitlCaseSelect + ` AND p.tenant_id = $1` + hitlCaseOrder + ` LIMIT $2 OFFSET $3`
			joinArgs = []any{tenantID, limit, offset}
		}

		var projRows []map[string]any
		joinErr := db.QueryRawCtx(r.Context(), joinSQL, &projRows, joinArgs...)
		if joinErr != nil {
			// No degraded single-table fallback (it silently dropped agent/policy
			// names, filters and paging). Report the real failure.
			slog.Error("ListCases: query failed", "tenant_id", tenantID, "error", joinErr)
			respond.InternalError(w, http.StatusServiceUnavailable, "list cases: database query failed", joinErr)
			return
		}

		rows = make([]map[string]any, 0, len(projRows))
		for _, pr := range projRows {
			rows = append(rows, hitlCaseRow(pr))
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
		if respond.RequireDBWrite(w, db) {
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

		// Read verdict / decision / vote from body and map to the CHECK-constrained
		// values. Fail closed: an absent or unrecognised verdict is rejected (422),
		// never silently recorded as APPROVED.
		verdict, ok := arbitrationVerdict(body)
		if !ok {
			respond.ErrorWithCode(w, http.StatusUnprocessableEntity, respond.ErrCodeUnprocessable,
				"verdict is required: APPROVED or REJECTED (fields: verdict | decision | vote)")
			return
		}

		rationale, _ := body["rationale"].(string)
		if rationale == "" {
			rationale, _ = body["reason"].(string)
		}
		// X-User-Id is a client-supplied header and is trivially spoofable without mTLS.
		var reviewerID string
		if au, auErr := auth.GetAuthUser(r.Context()); auErr == nil && au != nil && au.UserID != "" {
			reviewerID = au.UserID
		} else {
			// No spoofable X-User-Id fallback: the reviewer must come from the JWT.
			respond.Error(w, http.StatusUnauthorized, "reviewer identity missing from token")
			return
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

		// Verdict write, terminal-status guard and HITL_VERDICT audit row are applied by core
		// in ONE transaction under the row lock (ocx-core-svc owns core_hitl / core_events).
		cc := hitlCore(coreClient)
		if !requireHITLCore(w, cc) {
			return
		}
		capturedAgentID, _ := body["agent_id"].(string)
		update[serviceclient.HITLPatchAuditEvent] = map[string]any{
			"event_type": "HITL_VERDICT",
			"action":     "HITL_VERDICT",
			"entity_id":  caseID,
			"agent_id":   capturedAgentID,
			"actor_id":   reviewerID,
			"metadata":   map[string]any{"verdict": verdict, "reviewer": reviewerID},
		}
		if txErr := cc.PatchHITLCaseIf(r.Context(), tenantID, caseID, update, nil,
			[]string{"APPROVED", "REJECTED", "MERGED", "RESOLVED"}); txErr != nil {
			var conflict *serviceclient.HITLConflictError
			switch {
			case errors.Is(txErr, serviceclient.ErrHITLNotFound):
				respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "case not found")
			case errors.As(txErr, &conflict):
				respond.JSON(w, http.StatusConflict, map[string]any{
					"case_id": caseID,
					"status":  conflict.Status,
					"note":    "case already decided — re-arbitration not permitted (idempotency)",
				})
			default:
				slog.Error("ArbitrateCase failed", "case_id", caseID, "error", txErr)
				respond.InternalError(w, http.StatusBadGateway, "arbitrate case", txErr)
			}
			return
		}
		capturedVerdict := verdict
		capturedReviewer := reviewerID
		capturedCase := caseID
		capturedAgent, _ := body["agent_id"].(string)
		capturedTenant := tenantID // tenantID already fetched above for idempotency check

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
//   - A role key   → stored in context_data.assigned_role (UUID validation prevents 500)
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

func HandleAssignCase(db database.DB, classifier types.IntentClassifier, coreClients ...*serviceclient.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cc := hitlCore(coreClients...)
		if respond.RequireDBWrite(w, db) || !requireHITLCore(w, cc) {
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
		// assigned_to (user UUID or role key) | reviewer_id (alias) | the caller ("Assign to Me").
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
			if classResult == nil || len(classResult.Departments) == 0 {
				respond.ErrorWithCode(w, http.StatusUnprocessableEntity, "department_required",
					"automatic department routing is unavailable — pass department_ids explicitly")
				return
			}
			deptIDs = classResult.Departments // resolved to department_id PKs below
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
		// Every department is validated against syst_departments.department_id (PK);
		// classifier output (id or name) is resolved to the PK first.
		var depts deptIndex
		if len(deptIDs) > 0 {
			var loadErr error
			depts, loadErr = loadTenantDepartments(r.Context(), db, tenantID)
			if loadErr != nil {
				slog.Error("department lookup failed", "error", loadErr)
				respond.ErrorWithCode(w, http.StatusServiceUnavailable, "departments_unavailable", "could not load departments")
				return
			}
			resolved := make([]string, 0, len(deptIDs))
			var invalid []string
			for _, key := range deptIDs {
				d, found := depts.resolve(key)
				if !found {
					invalid = append(invalid, key)
					continue
				}
				resolved = append(resolved, d.ID)
			}
			if len(invalid) > 0 {
				respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest,
					fmt.Sprintf("%d department(s) not found for this tenant", len(invalid)))
				return
			}
			deptIDs = resolved

			// A HITL case assigned to a department with HITL disabled will sit
			// unactioned indefinitely with no error — prevent this at assignment time.
			for _, id := range deptIDs {
				if d := depts[id]; !d.hitlEnabled() {
					respond.ErrorWithCode(w, http.StatusUnprocessableEntity, respond.ErrCodeValidation,
						fmt.Sprintf("department %q has HITL disabled (enabled_features.hitl=false) — enable it before assigning cases", d.Name))
					return
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
				pendingRows, _lErr := cc.ListHITLCases(r.Context(), tenantID, map[string]string{"department_id": dept, "status": "PENDING"}, 1000)
				if _lErr != nil {
					slog.Error("core ListHITLCases failed (best-effort)", "error", _lErr)
				}
				if len(pendingRows) >= maxCases {
					respond.JSON(w, http.StatusTooManyRequests, map[string]any{
						"error":           fmt.Sprintf("department %q has reached the HITL case capacity limit (%d pending). Resolve existing cases or reassign to another department.", depts.name(dept), maxCases),
						"department_id":   dept,
						"department_name": depts.name(dept),
						"pending_count":   len(pendingRows),
						"max_capacity":    maxCases,
					})
					return
				}
			}
		}

		// (8.5): Persist case_type for self-heal classification and FA-03 §7 server-side filter.
		if req.CaseType != "" {
			update["case_type"] = req.CaseType
		}

		// Validate whether assigned_to is a UUID (user) or a role key.
		// Writing a non-UUID into user_id causes downstream UUID joins to fail,
		// so only real user UUIDs go to user_id; role keys go to assigned_role.
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

		// Core applies, in ONE transaction under the row lock: terminal-status guard, merge of the
		// assignment metadata into context_data, the update and the CASE_ASSIGNED audit row.
		ctxMerge := map[string]any{
			"assigned_to": assignedTo,
			"assigned_by": operatorID,
			"assigned_at": now,
		}
		if len(deptIDs) > 0 {
			ctxMerge["department_ids"] = deptIDs
		}
		if req.Reason != "" {
			ctxMerge["assignment_reason"] = req.Reason
		}
		for k, v := range classMeta {
			ctxMerge[k] = v
		}
		update[serviceclient.HITLPatchMergeContext] = ctxMerge
		update[serviceclient.HITLPatchAuditEvent] = map[string]any{
			"event_id":    generatePlatformID(),
			"entity_id":   caseID,
			"entity_type": "hitl_case",
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
		terminal := make([]string, 0, len(assignTerminalStatuses))
		for st := range assignTerminalStatuses {
			terminal = append(terminal, st)
		}
		if txErr := cc.PatchHITLCaseIf(r.Context(), tenantID, caseID, update, nil, terminal); txErr != nil {
			var conflict *serviceclient.HITLConflictError
			switch {
			case errors.Is(txErr, serviceclient.ErrHITLNotFound):
				respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "case not found")
			case errors.As(txErr, &conflict):
				respond.ErrorWithCode(w, http.StatusConflict, respond.ErrCodeConflict,
					fmt.Sprintf("case is in terminal status %s — assignment not permitted", conflict.Status))
			default:
				slog.Error("AssignCase failed", "case_id", caseID, "error", txErr)
				respond.InternalError(w, http.StatusBadGateway, "assign case", txErr)
			}
			return
		}
		respond.OK(w, map[string]any{"status": "ASSIGNED", "case_id": caseID, "assigned_to": assignedTo, "department_ids": deptIDs, "department_names": depts.names(deptIDs)})
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
		if respond.RequireDBWrite(w, db) {
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

// arbitrationVerdict extracts the reviewer's verdict from an arbitrate body.
// Accepted keys (first non-empty wins): verdict, decision, vote. Accepted
// values (case-insensitive): APPROVE/APPROVED, REJECT/REJECTED. Anything else
// — including no verdict at all — returns ok=false so the caller fails closed.
func arbitrationVerdict(body map[string]any) (string, bool) {
	for _, k := range []string{"verdict", "decision", "vote"} {
		s, _ := body[k].(string)
		s = strings.ToUpper(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		switch s {
		case "APPROVE", "APPROVED":
			return "APPROVED", true
		case "REJECT", "REJECTED":
			return "REJECTED", true
		default:
			return "", false
		}
	}
	return "", false
}

// hitlCaseSelect / hitlCaseOrder — ListCases reads compliance's own projection of core_hitl.
const hitlCaseSelect = `
	SELECT p.payload, COALESCE(d.name, '') AS department_name
	FROM compl_core_projection p
	LEFT JOIN syst_departments d
	       ON d.department_id = p.payload->>'department_id' AND d.tenant_id = p.tenant_id
	WHERE p.kind = 'hitl_case'`

const hitlCaseOrder = ` ORDER BY (p.payload->>'created_at')::timestamptz DESC NULLS LAST, p.entity_id`

// hitlCaseColumns is the case shape ListCases has always returned (core_hitl columns).
var hitlCaseColumns = []string{
	"decision_id", "tenant_id", "agent_id", "request_id", "decision_type", "status", "case_type",
	"priority", "context_data", "decision_data", "action_payload", "financial_value",
	"financial_exposure", "risk_score", "entropy_score", "cognitive_score", "quorum_required",
	"quorum_achieved", "jury_pool_size", "assigned_to", "policy_id", "gate_tool_name", "reason",
	"result", "source", "created_at", "updated_at", "expires_at", "sla_breach_at", "sla_breached",
	"sla_breached_at", "auto_escalated", "override_verdict", "verdict_id", "jury_case_id",
	"department_id", "agent_name", "policy_name",
}

// hitlCaseRow flattens a compl_core_projection row (payload jsonb + department_name) into the
// legacy ListCases row: case_id aliases decision_id and trust_score aliases identity_score.
func hitlCaseRow(pr map[string]any) map[string]any {
	payload := map[string]any{}
	switch v := pr["payload"].(type) {
	case map[string]any:
		payload = v
	case []byte:
		_ = json.Unmarshal(v, &payload)
	case string:
		_ = json.Unmarshal([]byte(v), &payload)
	}
	out := make(map[string]any, len(hitlCaseColumns)+3)
	for _, c := range hitlCaseColumns {
		out[c] = payload[c] // absent -> nil, same as a NULL column
	}
	out["case_id"] = payload["decision_id"]
	out["trust_score"] = payload["identity_score"]
	out["department_name"] = pr["department_name"]
	return out
}
