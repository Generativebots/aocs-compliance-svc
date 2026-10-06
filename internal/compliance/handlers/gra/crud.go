// Package adm — Consolidated CRUD handlers for all OCX data tables
//
// Single source of truth for all CRUD endpoint handlers.
// Organized by domain using generic DRY factory helpers.
//
// Phase L additions (2026-04-06):
//   - EBCL Contracts CRUD (ia_ebcl_contracts)
//   - GRA Risk Assessments CRUD (gra_cases)
//   - Policy Extractions CRUD (core_policies)
//   - APE Read-Side Go handlers (ia_authority_gaps, ia_parsed_documents,
//     ia_authority_contracts) — removed Python proxy dependency
//   - Ops Fleet Deployments CRUD (aocs_ops_fleet_deployments)
//   - Marketplace Installations CRUD (extc_installs)
//   - Agent App Bindings corrected → ia_agent_application_bindings
package gra

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/ocx/shared/idgen"
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

func crudGetHandler(db database.DB, table, pk string) http.HandlerFunc {
	// TenantScoped:true — factory.GetByID fetches by PK then verifies row.tenant_id == JWT tenant.
	// Without this, any authenticated user can read any record across all tenants
	// by guessing or enumerating IDs (IDOR / cross-tenant object access).
	return factory.GetByID(factory.Cfg{Table: table, SelectCols: "*", PKField: pk, TenantScoped: true})(db)
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
			"tenant_id": tenantID,
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
		if err := db.InsertRow(database.TblCoreA2aConnections, row); err != nil {
			slog.Error("InsertRow core_a2a_connections", "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "insert failed", err)
			return
		}

		// Write core_legal — peer activation consent record.
		// anonymous goroutine — ensure this is lifecycle-managed via svcboot.BgCtx
		concurrent.Go("admin/crud", func() {
			peerTenantID := req.PartnerTenantID
			if peerTenantID == "" {
				peerTenantID = req.InstanceID // fallback
			}
			if _dbErr := db.InsertRow(database.TblCoreLegal, map[string]any{
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
		if err := db.UpdateRowCompound(database.TblCoreA2aConnections, "a2a_connection_id", id, "tenant_id", tenantID, update); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "update failed", err)
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
		if err := db.UpdateRowCompound(database.TblCoreA2aConnections,
			"a2a_connection_id", id,
			"tenant_id", tenantID,
			map[string]any{"is_active": false}); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "deactivate failed", err)
			return
		}
		respond.JSON(w, http.StatusOK, map[string]string{"status": "deactivated"})
	}
}

// TENANT AGT — CRUD

// GHST STATE — speculative_actions (read)

// TRUST TAX — transactions + monthly bills

// GOV — ledger, proposals, votes, committee

func HandleGetGovernanceProposal(db database.DB) http.HandlerFunc {
	return crudGetHandler(db, database.TblCoreProposals, "governance_proposal_id")
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
			Title        string         `json:"title"         validate:"required"`
			ProposalType string         `json:"proposal_type" validate:"required"`
			Description  string         `json:"description"`
			Config       map[string]any `json:"config"`
		}
		respond.LimitBody(r)
		if !validate.Bind(w, r, &req) {
			return
		}
		// core_proposals is shared by several proposal kinds; governance proposals
		// are identified by governance_proposal_id, a STORED generated column
		// that mirrors the PK proposal_id (so it must not be inserted).
		id := idgen.GenID()
		now := time.Now().UTC().Format(time.RFC3339)
		row := map[string]any{
			"proposal_id":   id,
			"tenant_id":     tenantID,
			"title":         req.Title,
			"proposal_type": req.ProposalType,
			"description":   req.Description,
			"config":        req.Config,
			"status":        "DRAFT",
			"subtype":       "governance",
			"proposed_at":   now,
		}
		if uid := auth.GetUserID(r.Context()); uid != "" {
			row["proposed_by"] = uid
			row["proposer_id"] = uid
		}
		if err := db.InsertRow(database.TblCoreProposals, row); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "failed to create governance proposal", err)
			return
		}
		row["id"] = id
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
		if err := db.UpdateRowCompound(database.TblCoreProposals, "governance_proposal_id", entryID, "tenant_id", tenantID, update); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "failed to update governance proposal", err)
			return
		}
		// When status transitions to VOTING, insert an core_gov_rounds record
		// so the governance round is tracked for voting quorum calculations.
		if req.Status == "VOTING" {
			// anonymous goroutine — ensure this is lifecycle-managed via svcboot.BgCtx
			concurrent.Go("admin/crud", func() {
				if _dbErr := db.InsertRow(database.TblCoreGovRounds, map[string]any{
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
		// Governance proposals are part of the audit trail: deleting withdraws
		// the proposal and deactivates it rather than removing the row.
		if err := db.UpdateRowCompound(database.TblCoreProposals, "governance_proposal_id", entryID, "tenant_id", tenantID, map[string]any{
			"status":         "WITHDRAWN",
			"is_active":      false,
			"deactivated_at": time.Now().UTC().Format(time.RFC3339),
		}); err != nil {
			if database.IsNotFound(err) {
				respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "governance proposal not found")
				return
			}
			slog.Error("DeleteGovernanceProposal failed", "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "db operation failed", err)
			return
		}
		respond.OK(w, map[string]string{"id": entryID, "status": "WITHDRAWN"})
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
		if err := db.InsertRow(database.TblCoreGovRounds, row); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "failed to record vote", err)
			return
		}
		respond.Created(w, row)
	}
}

// HandleListGovernanceProposals lists the tenant's active governance proposals.
// GET /api/v1/gra/proposals
func HandleListGovernanceProposals(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var rows []map[string]any
		if err := db.QueryRowsCtx(r.Context(), database.TblCoreProposals,
			"proposal_id,governance_proposal_id,title,description,proposal_type,status,config,metadata,proposed_by,proposed_at,vote_deadline,yes_votes,no_votes,abstain_votes,required_votes,is_active,created_at,updated_at",
			"tenant_id", tenantID, &rows); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "failed to list governance proposals", err)
			return
		}
		out := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			gid, _ := row["governance_proposal_id"].(string)
			if gid == "" {
				continue
			}
			if active, ok := row["is_active"].(bool); ok && !active {
				continue
			}
			row["id"] = gid
			out = append(out, row)
		}
		respond.OK(w, out)
	}
}

// RULES ENGINE — CRUD
