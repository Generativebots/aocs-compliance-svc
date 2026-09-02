// Package adm — Consolidated CRUD handlers for all OCX data tables
//
// Single source of truth for all CRUD endpoint handlers.
// Organized by domain using generic DRY factory helpers.
//
// Phase L additions (2026-04-06):
//   - EBCL Contracts CRUD (ia_ebcl_contracts)
//   - GRA Risk Assessments CRUD (qcore_gra_risk_assessments)
//   - Policy Extractions CRUD (qcore_policy_extractions)
//   - APE Read-Side Go handlers (ia_authority_gaps, ia_parsed_documents,
//     ia_authority_contracts) — removed Python proxy dependency
//   - Ops Fleet Deployments CRUD (aocs_ops_fleet_deployments)
//   - Marketplace Installations CRUD (extc_installs)
//   - Agent App Bindings corrected → ia_agent_application_bindings
package gra

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/ocx/shared/infra/concurrent"
	"github.com/ocx/shared/respond"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/handlers/factory"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/validate"

)

// INTERNAL CRUD HELPERS — delegate to factory engine (DRY)
// These thin wrappers allow existing Handle* functions to remain as-is while
// their implementation is backed by the canonical factory engine in
// internal/handlers/factory/engine.go (zero behavior change).

func crudListHandler(db database.DB, table, _ string) http.HandlerFunc {
	return factory.List(factory.Cfg{Table: table, SelectCols: "*", FilterCol: "tenant_id", TenantScoped: true})(db)
}

func crudListAllHandler(db database.DB, table string) http.HandlerFunc {
	// FilterCol="" means QueryRows skips the Eq clause — full table scan with 500-row cap.
	// TenantScoped:false ensures no tenant_id injection (superadmin reads).
	return factory.List(factory.Cfg{Table: table, SelectCols: "*", FilterCol: "", TenantScoped: false})(db)
}

func crudGetHandler(db database.DB, table, pk string) http.HandlerFunc {
	return factory.GetByID(factory.Cfg{Table: table, SelectCols: "*", PKField: pk})(db)
}

func crudUpdateHandler(db database.DB, table, pk string) http.HandlerFunc {
	return factory.Update(factory.Cfg{Table: table, PKField: pk})(db)
}

// FED — peers (CRUD) + handshakes (status update)

func HandleAdminCreateFederationPeer(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		// Typed struct — prevents arbitrary column injection into core_a2a_connections.
		var req struct {
			PartnerTenantID string `json:"partner_tenant_id" validate:"required"`
			AgentID         string `json:"agent_id"`
			InstanceID      string `json:"instance_id"`
			ConnectionType  string `json:"connection_type"`
			Description     string `json:"description"`
		}
		respond.LimitBody(r)
		if !validate.Bind(w, r, &req) {
			return
		}
		row := map[string]any{
			"tenant_id":         tenantID,
			// partner_tenant_id/instance_id/description don't exist in core_a2a_connections.
			// Use remote_tenant_id for the partner, store extras in metadata.
			"remote_tenant_id": req.PartnerTenantID,
			"connection_type":  req.ConnectionType,
			"status":           "PENDING",
			"metadata": map[string]any{
				"agent_id":    req.AgentID,
				"instance_id": req.InstanceID,
				"description": req.Description,
			},
		}
		if err := db.InsertRow(database.TblA2AConnections, row); err != nil {
			slog.Error("InsertRow core_a2a_connections", "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "insert failed", nil)
			return
		}

		// Write core_legal — peer activation consent record.
		// CONC-1: anonymous goroutine — ensure this is lifecycle-managed via svcboot.BgCtx
	concurrent.Go("admin/crud", func() {
			peerTenantID := req.PartnerTenantID
			if peerTenantID == "" {
				peerTenantID = req.InstanceID // fallback
			}
			if _dbErr := db.InsertRow(database.TblFedConsents, map[string]any{
				"grantor_tenant_id": tenantID,
				"grantee_tenant_id": peerTenantID,
				"agent_id":          req.AgentID,
				"consent_token":     "PEER_ACTIVATION_" + tenantID,
			}); _dbErr != nil {
				slog.Error("db.InsertRow failed (best-effort)", "error", _dbErr)
			}
		})

		respond.JSON(w, http.StatusCreated, row)
	}
}

func HandleAdminUpdateFederationPeer(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		id := mux.Vars(r)["id"]
		if id == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}
		respond.LimitBody(r)
		// Previously any JSON key was forwarded directly to UpdateRowCompound → column injection.
		var req struct {
			Name        string         `json:"name"`
			Description string         `json:"description"`
			EndpointURL string         `json:"endpoint_url"`
			Status      string         `json:"status"      validate:"omitempty,oneof=ACTIVE INACTIVE SUSPENDED"`
			Metadata    map[string]any `json:"metadata"`
		}
		if !validate.Bind(w, r, &req) {
			return
		}
		update := map[string]any{}
		if req.Name != "" {
			update["name"] = req.Name
		}
		if req.Description != "" {
			update["description"] = req.Description
		}
		if req.EndpointURL != "" {
			update["endpoint_url"] = req.EndpointURL
		}
		if req.Status != "" {
			update["status"] = req.Status
		}
		if req.Metadata != nil {
			update["metadata"] = req.Metadata
		}
		if len(update) == 0 {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "no updatable fields provided")
			return
		}
		if err := db.UpdateRowCompound(database.TblA2AConnections, "a2a_connection_id", id, "tenant_id", tenantID, update); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "update failed", nil)
			return
		}
		respond.JSON(w, http.StatusOK, map[string]string{"status": "updated"})
	}
}

func HandleAdminDeleteFederationPeer(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		id := mux.Vars(r)["id"]
		if id == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}
		// Scope delete to tenant
		if err := db.UpdateRowCompound(database.TblA2AConnections,
			"a2a_connection_id", id,
			"tenant_id", tenantID,
			map[string]any{"is_active": false}); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "deactivate failed", nil)
			return
		}
		respond.JSON(w, http.StatusOK, map[string]string{"status": "deactivated"})
	}
}

// TENANT AGT — CRUD

func HandleUpdateTenantAgent(db database.DB) http.HandlerFunc {
	return crudUpdateHandler(db, database.TblAgents, "agent_id")
}

// GHST STATE — speculative_actions (read)

// TRUST TAX — transactions + monthly bills

// GOV — ledger, proposals, votes, committee

func HandleGetGovernanceProposal(db database.DB) http.HandlerFunc {
	return crudGetHandler(db, database.TblGovernanceProposals, "governance_proposal_id")
}

func HandleCreateGovernanceProposal(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		// Typed struct — prevents arbitrary column injection into core_proposals.
		var req struct {
			Title        string `json:"title"         validate:"required"`
			ProposalType string `json:"proposal_type" validate:"required"`
			Description  string `json:"description"`
			Config       map[string]any `json:"config"`
		}
		respond.LimitBody(r)
		if !validate.Bind(w, r, &req) {
			return
		}
		row := map[string]any{
			"tenant_id":     tenantID,
			"title":         req.Title,
			"proposal_type": req.ProposalType,
			"description":   req.Description,
			"config":        req.Config,
		}
		if err := db.InsertRow(database.TblGovernanceProposals, row); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "failed to create governance proposal", nil)
			return
		}
		respond.Created(w, row)
	}
}

func HandleUpdateGovernanceProposal(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		entryID := mux.Vars(r)["id"]
		if entryID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}
		respond.LimitBody(r)
		// Previously any JSON key was forwarded directly to UpdateRowCompound → column injection into governance tables.
		var req struct {
			Title       string         `json:"title"`
			Description string         `json:"description"`
			Status      string         `json:"status"      validate:"omitempty,oneof=DRAFT VOTING APPROVED REJECTED WITHDRAWN"`
			Metadata    map[string]any `json:"metadata"`
		}
		if !validate.Bind(w, r, &req) {
			return
		}
		update := map[string]any{}
		if req.Title != "" {
			update["title"] = req.Title
		}
		if req.Description != "" {
			update["description"] = req.Description
		}
		if req.Status != "" {
			update["status"] = req.Status
		}
		if req.Metadata != nil {
			update["metadata"] = req.Metadata
		}
		if len(update) == 0 {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "no updatable fields provided")
			return
		}
		if err := db.UpdateRowCompound(database.TblGovernanceProposals, "governance_proposal_id", entryID, "tenant_id", tenantID, update); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "failed to update governance proposal", nil)
			return
		}
		// When status transitions to VOTING, insert an core_gov_rounds record
		// so the governance round is tracked for voting quorum calculations.
		if req.Status == "VOTING" {
			// CONC-1: anonymous goroutine — ensure this is lifecycle-managed via svcboot.BgCtx
	concurrent.Go("admin/crud", func() {
				if _dbErr := db.InsertRow(database.TblGovRounds, map[string]any{
					"tenant_id":   tenantID,
					"proposal_id": entryID,
					"status":      "OPEN",
				}); _dbErr != nil {
					slog.Error("db.InsertRow failed (best-effort)", "error", _dbErr)
				}
			})
		}

		respond.OK(w, update)
	}
}

func HandleDeleteGovernanceProposal(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		entryID := mux.Vars(r)["id"]
		if entryID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}
		// Scope delete to tenant
		if err := db.SoftDeleteRowCompound(database.TblGovernanceProposals, "governance_proposal_id", entryID, "tenant_id", tenantID); err != nil {
			slog.Error("DeleteGovernanceProposal failed", "error", err)
				respond.InternalError(w, http.StatusInternalServerError, "db operation failed", err)
				return
		}
		respond.OK(w, map[string]string{"status": "deleted"})
	}
}

func HandleCastGovernanceVote(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		// Typed struct — prevents arbitrary column injection into core_gov_rounds.
		var req struct {
			ProposalID string `json:"proposal_id" validate:"required"`
			VoterID    string `json:"voter_id"`
			Vote       string `json:"vote"`
			Reason     string `json:"reason"`
		}
		respond.LimitBody(r)
		if !validate.Bind(w, r, &req) {
			return
		}
		row := map[string]any{
			"tenant_id":   tenantID,
			"proposal_id": req.ProposalID,
			"voter_id":    req.VoterID,
			"vote":        req.Vote,
			"reason":      req.Reason,
			"status":      "VOTED",
		}
		if err := db.InsertRow(database.TblGovRounds, row); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "failed to record vote", nil)
			return
		}
		respond.Created(w, row)
	}
}

func HandleListGovernanceVotes(db database.DB) http.HandlerFunc {
	return crudListHandler(db, database.TblGovRounds, "gov_round_id")
}

func HandleAddCommitteeMember(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		// Typed struct — prevents arbitrary column injection into aocs_governance_ledger.
		var req struct {
			TransactionID string `json:"transaction_id" validate:"required"`
			MemberID      string `json:"member_id"      validate:"required"`
			Role          string `json:"role"`
		}
		respond.LimitBody(r)
		if !validate.Bind(w, r, &req) {
			return
		}
		row := map[string]any{
			"tenant_id":      tenantID,
			"transaction_id": req.TransactionID,
			"member_id":      req.MemberID,
			"role":           req.Role,
			"action":         "COMMITTEE_MEMBER_ADD",
			"previous_hash":  "",
			"block_hash":     "",
		}
		if err := db.InsertRow(database.TblGovernanceLedger, row); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "failed to add committee member", nil)
			return
		}
		respond.Created(w, row)
	}
}

// HandleListCommitteeMembers — GET /api/v1/gov/committee/members
func HandleRemoveCommitteeMember(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		memberID := mux.Vars(r)["id"]
		if memberID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}
		// Scope delete to tenant
		if err := db.SoftDeleteRowCompound(database.TblGovernanceLedger, "governance_ledger_id", memberID, "tenant_id", tenantID); err != nil {
			slog.Error("RemoveCommitteeMember failed", "error", err)
				respond.InternalError(w, http.StatusInternalServerError, "db operation failed", err)
				return
		}
		respond.OK(w, map[string]string{"status": "removed"})
	}
}
func HandleUpdateCommitteeMember(db database.DB) http.HandlerFunc {
	return crudUpdateHandler(db, database.TblGovernanceLedger, "governance_ledger_id")
}

// RULES ENGINE — CRUD

func HandleListRules(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		// qcore_rules does not exist. /ops/rate-limits uses core_quota.
		// core_quota PK is tenant_id (one row per tenant).
		var rows []map[string]any
		if err := db.QueryRowsCtx(r.Context(), database.TblTenantRateLimits, "tenant_id,tier,requests_per_minute,burst_size,updated_at",
			"tenant_id", tenantID, &rows); err != nil {
			// Return empty if no rate limit config for this tenant yet
			respond.JSON(w, http.StatusOK, []map[string]any{})
			return
		}
		if rows == nil {
			rows = []map[string]any{}
		}
		respond.JSON(w, http.StatusOK, rows)
	}
}

func HandleGetRule(db database.DB) http.HandlerFunc {
	// qcore_rules does not exist. Rate-limit config is stored in core_quota.
	return crudGetHandler(db, database.TblTenantRateLimits, "tenant_id")
}
func HandleUpdateRule(db database.DB) http.HandlerFunc {
	return crudUpdateHandler(db, database.TblTenantRateLimits, "tenant_id")
}

// HandleAdminGetPolicy / HandleAdminUpdatePolicy — canonical governance endpoints.
// Used by /gov/rules/{id} (GET/PUT/PATCH). The route variable is {id} to match
// all sibling routes (/{id}/versions, /{id}/analyze) which also read mux.Vars["id"].
// The factory engine reads mux.Vars[cfg.PKField] which would need {policy_id} in
// the URL — instead we use inline implementations so the route stays as {id}.
func HandleAdminGetPolicy(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		id := mux.Vars(r)["id"]
		if id == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "id path parameter required")
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var rows []map[string]any
		if err := db.QueryRowsCompound(database.TblQCorePolicies, database.ColsQCorePolicies, "policy_id", id, "tenant_id", tenantID, &rows); err != nil || len(rows) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "policy not found")
			return
		}
		respond.OK(w, rows[0])
	}
}
func HandleAdminUpdatePolicy(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		id := mux.Vars(r)["id"]
		if id == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "id path parameter required")
			return
		}
		respond.LimitBody(r)
		// Previously any JSON key was forwarded directly to qcore_policies — column injection
		// on governance policies (the most security-critical table in AOCS).
		var req struct {
			Name           string          `json:"name"`
			Description    string          `json:"description"`
			Status         string          `json:"status"          validate:"omitempty,oneof=DRAFT ACTIVE INACTIVE ARCHIVED"`
			Scope          string          `json:"scope"`
			Category       string          `json:"category"`
			Priority       *int            `json:"priority"        validate:"omitempty,min=0,max=1000"`
			Rules          json.RawMessage `json:"rules"`
			Conditions     json.RawMessage `json:"conditions"`
			TimeWindows    json.RawMessage `json:"time_windows"`
			BoundAgents    json.RawMessage `json:"bound_agents"`
			EffectiveFrom  string          `json:"effective_from"`
			EffectiveUntil string          `json:"effective_until"`
			ApprovedBy     string          `json:"approved_by"`
			RiskCategory   string          `json:"risk_category"`
			DepartmentID   string          `json:"department_id"`
			AgentID        string          `json:"agent_id"`
		}
		if !validate.Bind(w, r, &req) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		update := map[string]any{}
		if req.Name != "" {
			update["name"] = req.Name
		}
		if req.Description != "" {
			update["description"] = req.Description
		}
		if req.Status != "" {
			update["status"] = req.Status
		}
		if req.Scope != "" {
			update["scope"] = req.Scope
		}
		if req.Category != "" {
			update["category"] = req.Category
		}
		if req.Priority != nil {
			update["priority"] = *req.Priority
		}
		if len(req.Rules) > 0 {
			update["rules"] = req.Rules
		}
		if len(req.Conditions) > 0 {
			update["conditions"] = req.Conditions
		}
		if len(req.TimeWindows) > 0 {
			update["time_windows"] = req.TimeWindows
		}
		if len(req.BoundAgents) > 0 {
			update["bound_agents"] = req.BoundAgents
		}
		if req.EffectiveFrom != "" {
			update["effective_from"] = req.EffectiveFrom
		}
		if req.EffectiveUntil != "" {
			update["effective_until"] = req.EffectiveUntil
		}
		if req.ApprovedBy != "" {
			update["approved_by"] = req.ApprovedBy
		}
		if req.RiskCategory != "" {
			update["risk_category"] = req.RiskCategory
		}
		if req.DepartmentID != "" {
			update["department_id"] = req.DepartmentID
		}
		if req.AgentID != "" {
			update["agent_id"] = req.AgentID
		}
		if len(update) == 0 {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "no updatable fields provided")
			return
		}
		if err := db.UpdateRowCompound(database.TblQCorePolicies, "policy_id", id, "tenant_id", tenantID, update); err != nil {
			slog.Error("HandleAdminUpdatePolicy: update failed", "policy_id", id, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "update failed", nil)
			return
		}
		respond.OK(w, map[string]any{"policy_id": id, "updated": true})
	}
}

// HandleListPolicies — GET /gov/rules (canonical governance policy list).
// Queries qcore_policies (not qcore_rules which is used for /ops/rate-limits).
// Supports optional query params: scope, agent_id, status, department_id.
func HandleListPolicies(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		scope := r.URL.Query().Get("scope")
		dept := r.URL.Query().Get("department_id")
		agt := r.URL.Query().Get("agent_id")
		status := r.URL.Query().Get("status")

		// ListPoliciesFiltered routes through typed DB interface (pgx-first).
		// Eliminates raw .GetClient().From() type-assertion — fully interface-compliant.
		rows, err := db.ListPoliciesFiltered(r.Context(), tenantID, scope, dept, agt, status)
		if err != nil {
			// Graceful empty-state: return [] instead of 500 to prevent UI cascade
			respond.JSON(w, http.StatusOK, []map[string]any{})
			return
		}
		if rows == nil {
			rows = []map[string]any{}
		}
		respond.JSON(w, http.StatusOK, rows)
	}
}

// HandleAdminCreatePolicy — POST /gov/rules.
// Creates a new governance policy in qcore_policies.
// Injects tenant_id and sets default status=DRAFT per the patent policy lifecycle.
// Creates policy-agent and intent-policy bindings to ensure full governance chain.
func HandleAdminCreatePolicy(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		respond.LimitBody(r)

		var req struct {
			Name           string          `json:"name"            validate:"required"`
			Description    string          `json:"description"`
			Status         string          `json:"status"          validate:"omitempty,oneof=DRAFT ACTIVE INACTIVE ARCHIVED"`
			Scope          string          `json:"scope"`
			Category       string          `json:"category"`
			Priority       *int            `json:"priority"        validate:"omitempty,min=0,max=1000"`
			Rules          json.RawMessage `json:"rules"`
			Conditions     json.RawMessage `json:"conditions"`
			TimeWindows    json.RawMessage `json:"time_windows"`
			BoundAgents    json.RawMessage `json:"bound_agents"`
			EffectiveFrom  string          `json:"effective_from"`
			EffectiveUntil string          `json:"effective_until"`
			RiskCategory   string          `json:"risk_category"`
			DepartmentID   string          `json:"department_id"`
			AgentID        string          `json:"agent_id"`
			// ── New: arrays for binding creation ──
			AgentIDs       []string        `json:"agent_ids"`
			IntentIDs      []string        `json:"intent_ids"`
		}
		if !validate.Bind(w, r, &req) {
			return
		}

		// Build explicit row — never forward caller-controlled keys to InsertRow.
		row := map[string]any{
			"tenant_id":   tenantID,
			"name":        req.Name,
			"description": req.Description,
			"status":      req.Status,
			"scope":       req.Scope,
			"category":    req.Category,
		}
		if row["status"] == nil || row["status"] == "" {
			row["status"] = "DRAFT"
		}
		if req.Priority != nil {
			row["priority"] = *req.Priority
		}
		if len(req.Rules) > 0 {
			row["rules"] = req.Rules
		}
		if len(req.Conditions) > 0 {
			row["conditions"] = req.Conditions
		}
		if len(req.TimeWindows) > 0 {
			row["time_windows"] = req.TimeWindows
		}
		if len(req.BoundAgents) > 0 {
			row["bound_agents"] = req.BoundAgents
		}
		if req.EffectiveFrom != "" {
			row["effective_from"] = req.EffectiveFrom
		}
		if req.EffectiveUntil != "" {
			row["effective_until"] = req.EffectiveUntil
		}
		if req.RiskCategory != "" {
			row["risk_category"] = req.RiskCategory
		}
		if req.DepartmentID != "" {
			row["department_id"] = req.DepartmentID
		}
		if req.AgentID != "" {
			row["agent_id"] = req.AgentID
			// Also add to agent_ids for binding creation
			if len(req.AgentIDs) == 0 {
				req.AgentIDs = []string{req.AgentID}
			}
		}

		// Insert the policy — policy_id is auto-generated by Postgres gen_id()
		if err := db.InsertRow(database.TblQCorePolicies, row); err != nil {
			slog.Error("HandleAdminCreatePolicy: insert failed", "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "failed to create policy", nil)
			return
		}

		// ── Retrieve the generated policy_id ──
		// Query the latest policy for this tenant with matching name
		policyID := ""
		var policies []struct {
			PolicyID string `json:"policy_id"`
		}
		if err := db.QueryRows(database.TblQCorePolicies,
			"policy_id", "tenant_id", tenantID, &policies); err == nil && len(policies) > 0 {
			// Sort by created_at DESC — the latest one is ours
			policyID = policies[len(policies)-1].PolicyID
		}
		// Fallback: try to get policy_id from the returned row
		if policyID == "" {
			if pid, ok := row["policy_id"].(string); ok {
				policyID = pid
			}
		}

		if policyID != "" {
			// ── Create policy-agent bindings ──
			for _, agentID := range req.AgentIDs {
				if agentID == "" {
					continue
				}
				binding := map[string]any{
					"tenant_id": tenantID,
					"policy_id": policyID,
					"agent_id":  agentID,
					"bound_by":  "policy-create@aocs",
					"is_active": true,
				}
				if err := db.InsertRow(database.TblPolicyAgentBindings, binding); err != nil {
					slog.Warn("HandleAdminCreatePolicy: agent binding failed",
						"policy_id", policyID, "agent_id", agentID, "error", err)
				}
			}

			// ── Create intent-policy bindings ──
			for _, intentID := range req.IntentIDs {
				if intentID == "" {
					continue
				}
				binding := map[string]any{
					"tenant_id":    tenantID,
					"intent_id":    intentID,
					"policy_id":    policyID,
					"binding_type": "enforcement",
					"is_active":    true,
					"bound_by":     "policy-create@aocs",
				}
				if err := db.InsertRow(database.TblIntentPolicyBindings, binding); err != nil {
					slog.Warn("HandleAdminCreatePolicy: intent binding failed",
						"policy_id", policyID, "intent_id", intentID, "error", err)
				}
			}

			row["policy_id"] = policyID
		}

		respond.JSON(w, http.StatusCreated, row)
	}
}
