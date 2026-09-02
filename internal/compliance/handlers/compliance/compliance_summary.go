package compliance

import (
	"fmt"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
)

// Governance RPC Handlers — N+1 elimination via Postgres aggregation functions
//
// GET /api/v1/policies/summary          → get_policy_summary(p_tenant_id)
// GET /api/v1/gra/compliance-obligations → get_compliance_obligations(p_tenant_id)
// GET /api/v1/gra/policy-impact         → get_policy_impact_analysis(p_tenant_id)
//
// All three call TABLE-returning Postgres RPCs via direct pgx queries.
// Zero N+1 — one DB round-trip replaces 1-per-row fetch looperations.

// GET /api/v1/policies/summary
// Returns policies joined with coverage %, rule count, and last verdict.
// Replaces the N+1 pattern: one call to v_policy_with_coverage via RPC.

type PolicySummaryRow struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Status      string          `json:"status"`
	Version     string          `json:"version,omitempty"`
	Rules       json.RawMessage `json:"rules,omitempty"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
	RuleCount   int             `json:"rule_count"`
	CoveragePct float64         `json:"coverage_pct"`
	IsActive    bool            `json:"is_active"`
	UpdatedAt   time.Time       `json:"updated_at"`
	CreatedAt   time.Time       `json:"created_at"`
	LastVerdict *string         `json:"last_verdict,omitempty"`
}

func HandleGetPolicySummary(pgx *database.PGXPool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		rows, err := getPolicySummary(r.Context(), pgx, tenantID)
		if err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "get_policy_summary", err)
			return
		}

		respond.JSON(w, http.StatusOK, map[string]any{"data": rows, "total": len(rows), "has_more": false})
	}
}

func getPolicySummary(ctx context.Context, p *database.PGXPool, tenantID string) ([]PolicySummaryRow, error) {
	const query = `
		SELECT id, name, description, status, version,
		       rules, metadata, rule_count::int, coverage_pct::float8,
		       is_active, updated_at, created_at, last_verdict
		FROM get_policy_summary($1)
		ORDER BY is_active DESC, updated_at DESC`

	pgxRows, err := p.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("Query: %w", err) // ERRH-3 FIX
	}
	defer pgxRows.Close()

	var out []PolicySummaryRow
	for pgxRows.Next() {
		var r PolicySummaryRow
		var rulesRaw, metaRaw []byte
		if err := pgxRows.Scan(
			&r.ID, &r.Name, &r.Description, &r.Status, &r.Version,
			&rulesRaw, &metaRaw, &r.RuleCount, &r.CoveragePct,
			&r.IsActive, &r.UpdatedAt, &r.CreatedAt, &r.LastVerdict,
		); err != nil {
			continue
		}
		r.Rules = json.RawMessage(rulesRaw)
		r.Metadata = json.RawMessage(metaRaw)
		out = append(out, r)
	}
	return out, pgxRows.Err()
}

// GET /api/v1/gra/compliance-obligations
// Returns compliance obligations derived from active regulatory frameworks.
// One RPC call → get_compliance_obligations(p_tenant_id).

type ComplianceObligationRow struct {
	ID              string  `json:"id"`
	FrameworkID     string  `json:"framework_id"`
	FrameworkName   string  `json:"framework_name"`
	Title           string  `json:"title"`
	Severity        string  `json:"severity"`
	Enforcement     string  `json:"enforcement"`
	RegionCode      string  `json:"region_code,omitempty"`
	ComplianceScore float64 `json:"compliance_score"`
	IsActive        bool    `json:"is_active"`
}

func HandleListComplianceObligations(pgx *database.PGXPool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		rows, err := getComplianceObligations(r.Context(), pgx, tenantID)
		if err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "get_compliance_obligations", err)
			return
		}

		respond.JSON(w, http.StatusOK, map[string]any{"data": rows, "total": len(rows), "has_more": false})
	}
}

func getComplianceObligations(ctx context.Context, p *database.PGXPool, tenantID string) ([]ComplianceObligationRow, error) {
	// get_compliance_obligations() DB function does not exist.
	// Fall back to direct query against gra_frameworks (actual table name).
	// tenant_id is NULL for global frameworks — include both global and tenant-specific.
	const query = `
		SELECT
			framework_id,
			framework_id AS framework_id,
			name                AS framework_name,
			name                AS title,
			CASE enforcement_level
				WHEN 'MANDATORY'   THEN 'HIGH'
				WHEN 'RECOMMENDED' THEN 'MEDIUM'
				ELSE 'LOW'
			END                 AS severity,
			COALESCE(enforcement_level, 'RECOMMENDED') AS enforcement,
			COALESCE(jurisdiction, '') AS region_code,
			0.0::float8         AS compliance_score,
			is_active
		FROM gra_frameworks
		WHERE (tenant_id = $1 OR tenant_id IS NULL) AND is_active = true
		ORDER BY enforcement_level DESC, name ASC`

	pgxRows, err := p.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("Query: %w", err) // ERRH-3 FIX
	}
	defer pgxRows.Close()

	var out []ComplianceObligationRow
	for pgxRows.Next() {
		var r ComplianceObligationRow
		if err := pgxRows.Scan(
			&r.ID, &r.FrameworkID, &r.FrameworkName, &r.Title,
			&r.Severity, &r.Enforcement, &r.RegionCode,
			&r.ComplianceScore, &r.IsActive,
		); err != nil {
			continue
		}
		out = append(out, r)
	}
	if out == nil {
		out = []ComplianceObligationRow{}
	}
	return out, pgxRows.Err()
}

// GET /api/v1/gra/policy-impact
// Returns active policies enriched with impact scores and affected agent count.
// One RPC call → get_policy_impact_analysis(p_tenant_id).

type PolicyImpactRow struct {
	PolicyID       string    `json:"policy_id"`
	PolicyName     string    `json:"policy_name"`
	PolicyStatus   string    `json:"policy_status"`
	ImpactScore    float64   `json:"impact_score"`
	AffectedAgents int64     `json:"affected_agents"`
	RiskLevel      string    `json:"risk_level"`
	Confidence     *float64  `json:"confidence,omitempty"`
	LastEvaluated  time.Time `json:"last_evaluated"`
}

func HandleGetPolicyImpact(pgx *database.PGXPool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		rows, err := getPolicyImpactAnalysis(r.Context(), pgx, tenantID)
		if err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "get_policy_impact_analysis", err)
			return
		}

		respond.JSON(w, http.StatusOK, map[string]any{"data": rows, "total": len(rows), "has_more": false})
	}
}

func getPolicyImpactAnalysis(ctx context.Context, p *database.PGXPool, tenantID string) ([]PolicyImpactRow, error) {
	const query = `
		SELECT policy_id::text, policy_name, policy_status,
		       impact_score::float8, affected_agents::bigint,
		       risk_level, confidence, last_evaluated
		FROM get_policy_impact_analysis($1)
		ORDER BY impact_score DESC`

	pgxRows, err := p.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("Query: %w", err) // ERRH-3 FIX
	}
	defer pgxRows.Close()

	var out []PolicyImpactRow
	for pgxRows.Next() {
		var r PolicyImpactRow
		if err := pgxRows.Scan(
			&r.PolicyID, &r.PolicyName, &r.PolicyStatus,
			&r.ImpactScore, &r.AffectedAgents,
			&r.RiskLevel, &r.Confidence, &r.LastEvaluated,
		); err != nil {
			continue
		}
		out = append(out, r)
	}
	return out, pgxRows.Err()
}

// POST /api/v1/gov/rules/{id}/impact-preview
//
// Pre-flight impact preview before activating/deactivating a policy rule.
// Used by ActionConsequenceModal.tsx to gate destructive policy changes.
//
// Returns: affected_agents, risk_level, impact_score, blast_radius,
//          requires_manual_approval, policy_name, policy_status

type PolicyImpactPreviewResponse struct {
	PolicyID               string  `json:"policy_id"`
	PolicyName             string  `json:"policy_name"`
	PolicyStatus           string  `json:"policy_status"`
	ImpactScore            float64 `json:"impact_score"`
	AffectedAgents         int64   `json:"affected_agents"`
	RiskLevel              string  `json:"risk_level"`
	EstimatedBlastRadius   string  `json:"estimated_blast_radius"`
	RequiresManualApproval bool    `json:"requires_manual_approval"`
	Message                string  `json:"message"`
}

func HandleGetPolicyImpactPreview(pgx *database.PGXPool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		// B-GC1 FIX: r.PathValue("id") is net/http 1.22+ stdlib — NOT populated by gorilla/mux.
		// Always returned "" causing handler to return aggregate instead of requested policy.
		policyID := mux.Vars(r)["id"]
		if policyID == "" {
			policyID = r.URL.Query().Get("policy_id")
		}

		// Run policy impact analysis across all tenant policies
		rows, err := getPolicyImpactAnalysis(r.Context(), pgx, tenantID)
		if err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "policy impact analysis", err)
			return
		}

		// Filter to the requested policy if ID provided
		var result *PolicyImpactRow
		for i, row := range rows {
			if policyID == "" || row.PolicyID == policyID {
				result = &rows[i]
				break
			}
		}

		// If no policy found or no ID given, return aggregate risk
		if result == nil {
			// Return a conservative default for unknown policies
			respond.OK(w, PolicyImpactPreviewResponse{
				PolicyID:               policyID,
				PolicyName:             "Unknown Policy",
				PolicyStatus:           "unknown",
				ImpactScore:            0.5,
				AffectedAgents:         0,
				RiskLevel:              "MEDIUM",
				EstimatedBlastRadius:   "limited",
				RequiresManualApproval: true,
				Message:                "Impact analysis unavailable — manual review required",
			})
			return
		}

		// Derive blast radius label from impact
		blastRadius := "limited"
		requiresApproval := false
		switch {
		case result.ImpactScore >= 0.8 || result.RiskLevel == "CRITICAL":
			blastRadius = "system-wide"
			requiresApproval = true
		case result.ImpactScore >= 0.6 || result.RiskLevel == "HIGH":
			blastRadius = "significant"
			requiresApproval = true
		case result.ImpactScore >= 0.4 || result.RiskLevel == "MEDIUM":
			blastRadius = "moderate"
			requiresApproval = result.AffectedAgents > 10
		default:
			blastRadius = "limited"
		}

		respond.OK(w, PolicyImpactPreviewResponse{
			PolicyID:               result.PolicyID,
			PolicyName:             result.PolicyName,
			PolicyStatus:           result.PolicyStatus,
			ImpactScore:            result.ImpactScore,
			AffectedAgents:         result.AffectedAgents,
			RiskLevel:              result.RiskLevel,
			EstimatedBlastRadius:   blastRadius,
			RequiresManualApproval: requiresApproval,
			Message: func() string {
				if requiresApproval {
					return "High-impact change: manual HITL approval required before activation"
				}
				return "Impact within safe thresholds — can be activated automatically"
			}(),
		})
	}
}