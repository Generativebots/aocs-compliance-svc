package compliance

// GRA (Governance Risk Assessment) Handlers — Group 4 Consolidated
// Tables: gra_frameworks, gra_cases, gra_tenant_status
// Canonical pattern:
//   - gra_frameworks absorbs: qcore_gra_regulatory_frameworks, compliance_regions, risk_config
//   - gra_cases absorbs: verification_intents, agent_actions, risk_assessments
//     case_type discriminator: 'verification_intent' | 'agent_action' | 'risk_assessment'
//   - gra_tenant_status: renamed from qcore_gra_tenant_status
// Rule: type-specific fields packed into data JSONB.

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

func HandleCreateComplianceRegion(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var req CreateComplianceRegionRequest
		respond.LimitBody(r)
		if !validate.Bind(w, r, &req) {
			return
		}
		if req.RegionCode == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "region_code is required")
			return
		}
		isActive := true
		if req.IsActive != nil {
			isActive = *req.IsActive
		}

		regionsJSON, _ := json.Marshal([]interface{}{map[string]any{
			"region_code":           req.RegionCode,
			"region_name":           req.RegionName,
			"countries":             req.Countries,
			"risk_weight":           req.RiskWeight,
			"description":           req.Description,
			"applicable_frameworks": req.ApplicableFrameworks,
		}})
		fw := database.GRAFramework{
			TenantID:     tenantID,
			Name:         req.RegionCode + "_region",
			Jurisdiction: req.RegionCode,
			RegionCode:   req.RegionCode,
			Regions:      regionsJSON,
			IsActive:     isActive,
		}
		if err := db.InsertRow(database.TblGRAFrameworks, fw.InsertPayload()); err != nil {
			slog.Error("CreateComplianceRegion: insert failed", "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "create compliance region", err)
			return
		}
		respond.JSON(w, http.StatusCreated, fw)
	}
}

// GET /api/v1/gra/compliance-regions
func HandleListComplianceRegions(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var rows []database.GRAFramework
		if err := db.QueryRowsCtx(r.Context(), database.TblGRAFrameworks, database.ColsGRAFramework, "tenant_id", tenantID, &rows); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "list compliance regions", err)
			return
		}
		respond.JSON(w, http.StatusOK, rows)
	}
}
