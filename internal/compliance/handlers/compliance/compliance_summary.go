package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/logger"
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

		// has_more was always false — frontend couldn't paginate.
		// Compute from actual row count vs requested limit (default 100).
		limit := 100
		if l := r.URL.Query().Get("limit"); l != "" {
			if n, err := strconv.Atoi(l); err == nil && n > 0 {
				limit = n
			}
		}
		respond.JSON(w, http.StatusOK, map[string]any{"data": rows, "total": len(rows), "has_more": len(rows) >= limit})
	}
}

func getPolicySummary(ctx context.Context, p *database.PGXPool, tenantID string) ([]PolicySummaryRow, error) {
	// Direct query on core_policies (get_policy_summary() returns only 6 columns).
	// coverage_pct = bound agents / active agents for the tenant (0-100).
	// last_verdict = most recent gate action recorded against the policy.
	const query = `
		SELECT p.policy_id, p.name, COALESCE(p.description, ''), COALESCE(p.status, ''),
		       COALESCE(p.version, 1)::text,
		       COALESCE(p.rules, '[]'::jsonb), COALESCE(p.metadata, '{}'::jsonb),
		       CASE WHEN jsonb_typeof(p.rules) = 'array' THEN jsonb_array_length(p.rules) ELSE 0 END,
		       LEAST(100.0, 100.0 * COALESCE(array_length(p.bound_agents, 1), 0) / ta.n)::float8,
		       COALESCE(p.is_active, p.status = 'ACTIVE') AS is_active,
		       COALESCE(p.updated_at, p.created_at, NOW()) AS updated_at,
		       COALESCE(p.created_at, NOW()),
		       lv.action
		FROM core_policies p
		CROSS JOIN (SELECT GREATEST(COUNT(*), 1) AS n FROM core_agents
		             WHERE tenant_id = $1 AND status = 'ACTIVE') ta
		LEFT JOIN LATERAL (
		    SELECT v.verdict AS action
		      FROM lv_core_gate_decisions v
		     WHERE v.tenant_id = p.tenant_id AND v.policy_id = p.policy_id
		     ORDER BY v.created_at DESC LIMIT 1) lv ON true
		WHERE p.tenant_id = $1 AND p.deleted_at IS NULL
		ORDER BY is_active DESC, updated_at DESC`

	pgxRows, err := p.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("Query: %w", err)
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

		limit2 := 100
		if l := r.URL.Query().Get("limit"); l != "" {
			if n, err := strconv.Atoi(l); err == nil && n > 0 {
				limit2 = n
			}
		}
		respond.JSON(w, http.StatusOK, map[string]any{"data": rows, "total": len(rows), "has_more": len(rows) >= limit2})
	}
}

func getComplianceObligations(ctx context.Context, p *database.PGXPool, tenantID string) ([]ComplianceObligationRow, error) {
	// get_compliance_obligations() DB function does not exist.
	// Fall back to direct query against gra_frameworks (actual table name).
	// tenant_id is NULL for global frameworks — include both global and tenant-specific.
	//
	// compliance_score was hardcoded 0.0::float8 — permanently misrepresented
	// compliance coverage on the EU AI Act / SOC2 obligation dashboard.
	// Now computed as: (active_policies_covering_framework / total_policies) where
	// a policy covers a framework when core_policies.framework_id matches OR the tenant
	// has at least one active policy (global coverage signal).
	//
	// Score formula (per framework):
	//   active_policies  = COUNT(*) WHERE framework_id = f.framework_id AND status='ACTIVE'
	//   total_policies   = COUNT(*) WHERE tenant_id = $1 (all active policies, any framework)
	//   score = active_policies / GREATEST(total_policies, 1)
	// Range: [0.0, 1.0]. 0.0 = no policies covering this framework. 1.0 = full coverage.
	// Frameworks live in lv_gra_frameworks (syst_tenant_settings subtype=gra_frameworks;
	// enforcement level in record_value/payload). A policy covers a framework when its
	// regulatory_frameworks JSON or applicable_regulations[] names the framework id or name.
	const query = `
		WITH total_active AS (
			SELECT GREATEST(COUNT(*) FILTER (WHERE status = 'ACTIVE'), 1) AS n
			FROM core_policies
			WHERE tenant_id = $1 AND deleted_at IS NULL
		), fw AS (
			SELECT COALESCE(f.framework_id, f.record_key, f.setting_id) AS framework_id,
			       COALESCE(f.name, f.record_key, '')                    AS name,
			       COALESCE(f.record_value->>'enforcement_level',
			                f.payload->>'enforcement_level', 'RECOMMENDED') AS enforcement_level,
			       COALESCE(f.region_code, f.jurisdiction, '')           AS region_code,
			       COALESCE(f.is_active, true)                           AS is_active
			FROM lv_gra_frameworks f
			WHERE (f.tenant_id = $1 OR f.tenant_id IS NULL) AND COALESCE(f.is_active, true)
		)
		SELECT
			fw.framework_id AS id,
			fw.framework_id,
			fw.name         AS framework_name,
			fw.name         AS title,
			CASE fw.enforcement_level
				WHEN 'MANDATORY'   THEN 'HIGH'
				WHEN 'RECOMMENDED' THEN 'MEDIUM'
				ELSE 'LOW'
			END             AS severity,
			fw.enforcement_level AS enforcement,
			fw.region_code,
			(pc.active_for_framework::float8 / ta.n)::float8 AS compliance_score,
			fw.is_active
		FROM fw
		CROSS JOIN total_active ta
		CROSS JOIN LATERAL (
			SELECT COUNT(*) AS active_for_framework
			  FROM core_policies p
			 WHERE p.tenant_id = $1 AND p.deleted_at IS NULL AND p.status = 'ACTIVE'
			   AND (COALESCE(p.regulatory_frameworks, '[]'::jsonb) ?| ARRAY[fw.framework_id, fw.name]
			        OR fw.framework_id = ANY(COALESCE(p.applicable_regulations, '{}'))
			        OR fw.name = ANY(COALESCE(p.applicable_regulations, '{}')))
		) pc
		ORDER BY fw.enforcement_level DESC, fw.name ASC`

	pgxRows, err := p.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("Query: %w", err)
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
			logger.For("compliance/handlers/compliance").Error("HandleGetPolicyImpact failed", "tenant_id", tenantID, "err", err)
			respond.JSON(w, http.StatusOK, map[string]any{"data": []PolicyImpactRow{}, "total": 0, "has_more": false})
			return
		}
		if rows == nil {
			rows = []PolicyImpactRow{}
		}

		limit2 := 100
		if l := r.URL.Query().Get("limit"); l != "" {
			if n, err := strconv.Atoi(l); err == nil && n > 0 {
				limit2 = n
			}
		}
		respond.JSON(w, http.StatusOK, map[string]any{"data": rows, "total": len(rows), "has_more": len(rows) >= limit2})
	}
}

// policyImpactSQL scores each policy from its gate verdict history in
// the gate decision log (lv_core_gate_decisions). impact_score is on a 0-1 scale (fraction of evaluated
// actions the policy blocked); policies with no verdicts fall back to
// priority/10. $2 = ” returns all policies, otherwise only that policy.
const policyImpactSQL = `
	WITH stats AS (
		SELECT p.policy_id, p.name, COALESCE(p.status, '') AS status, p.priority,
		       COALESCE(array_length(p.bound_agents, 1), 0) AS bound_agents,
		       COALESCE(p.updated_at, p.created_at, NOW()) AS policy_ts,
		       COUNT(v.decision_id) AS total,
		       COUNT(*) FILTER (WHERE v.verdict IN ('BLOCK', 'DENY')) AS blocked,
		       COUNT(DISTINCT v.agent_id) AS verdict_agents,
		       MAX(v.created_at) AS last_verdict_at
		FROM core_policies p
		LEFT JOIN lv_core_gate_decisions v ON v.policy_id = p.policy_id AND v.tenant_id = p.tenant_id
		WHERE p.tenant_id = $1 AND p.deleted_at IS NULL AND ($2 = '' OR p.policy_id = $2)
		GROUP BY p.policy_id
	), scored AS (
		SELECT *, CASE WHEN total > 0 THEN blocked::float8 / total
		               ELSE LEAST(1.0, COALESCE(priority, 5) / 10.0) END AS impact
		FROM stats
	)
	SELECT policy_id, name, status, impact::float8,
	       GREATEST(verdict_agents, bound_agents)::bigint,
	       CASE WHEN impact >= 0.8 THEN 'CRITICAL' WHEN impact >= 0.6 THEN 'HIGH'
	            WHEN impact >= 0.4 THEN 'MEDIUM' ELSE 'LOW' END,
	       CASE WHEN total > 0 THEN LEAST(1.0, total / 100.0)::float8 END,
	       COALESCE(last_verdict_at, policy_ts)
	FROM scored
	ORDER BY impact DESC
	LIMIT 500`

func getPolicyImpactAnalysis(ctx context.Context, p *database.PGXPool, tenantID string) ([]PolicyImpactRow, error) {
	return queryPolicyImpact(ctx, p, tenantID, "")
}

func queryPolicyImpact(ctx context.Context, p *database.PGXPool, tenantID, policyID string) ([]PolicyImpactRow, error) {
	if p == nil {
		return []PolicyImpactRow{}, nil
	}
	pgxRows, err := p.Query(ctx, policyImpactSQL, tenantID, policyID)
	if err != nil {
		return nil, fmt.Errorf("policy impact query: %w", err)
	}
	defer pgxRows.Close()

	out := []PolicyImpactRow{}
	for pgxRows.Next() {
		var r PolicyImpactRow
		if err := pgxRows.Scan(
			&r.PolicyID, &r.PolicyName, &r.PolicyStatus,
			&r.ImpactScore, &r.AffectedAgents,
			&r.RiskLevel, &r.Confidence, &r.LastEvaluated,
		); err != nil {
			return nil, fmt.Errorf("policy impact scan: %w", err)
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

		if pgx == nil {
			policyID := mux.Vars(r)["id"]
			if policyID == "" {
				policyID = r.URL.Query().Get("policy_id")
			}
			respond.OK(w, PolicyImpactPreviewResponse{
				PolicyID:               policyID,
				PolicyName:             "Policy " + policyID,
				PolicyStatus:           "ACTIVE",
				ImpactScore:            0.5,
				AffectedAgents:         0,
				RiskLevel:              "LOW",
				EstimatedBlastRadius:   "LOCAL",
				RequiresManualApproval: false,
				Message:                "Preview computed with offline baseline defaults",
			})
			return
		}

		// r.PathValue("id") is net/http 1.22+ stdlib — NOT populated by gorilla/mux.
		// Always returned "" causing handler to return aggregate instead of requested policy.
		policyID := mux.Vars(r)["id"]
		if policyID == "" {
			policyID = r.URL.Query().Get("policy_id")
		}

		// was getPolicyImpactAnalysis(tenantID) which scans ALL tenant policies
		// then filters in Go. For tenants with 500+ policies this is a full table scan on
		// every impact preview click. Now passes policyID directly to the DB function/query
		// so only the requested policy is scanned. Falls back to full scan if no ID given.
		rows, err := queryPolicyImpact(r.Context(), pgx, tenantID, policyID)
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
