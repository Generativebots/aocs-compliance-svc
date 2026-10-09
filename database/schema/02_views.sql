-- Ring 3 Compliance Views

-- ── vw_compliance_kpis ─────────────────────────────────────────────────────
-- SCHEMA FIX (normalization pass): GET /analytics/compliance-kpis reads
-- vw_compliance_kpis (database.TblVwComplianceKpis). The view never existed and
-- the constant pointed at core_compliance, which has none of these columns.
-- KPIs are derived data, so they are computed here instead of being stored.
--   violation_count / open_violations / violations_30d / resolved_30d
--                                      ← compl_policy_violations
--   evidence_count / verified_evidence ← compl_evidence (verified = signed)
--   pending_hitl                       ← core_hitl (status PENDING)
--   overall_score = 100 × (1 − open / total violations), 100 when none.
CREATE OR REPLACE VIEW public.vw_compliance_kpis WITH (security_invoker='true') AS
SELECT t.tenant_id,
       t.tenant_name,
       COALESCE(v.violation_count, 0)    AS violation_count,
       COALESCE(v.open_violations, 0)    AS open_violations,
       COALESCE(e.evidence_count, 0)     AS evidence_count,
       COALESCE(e.verified_evidence, 0)  AS verified_evidence,
       CASE WHEN COALESCE(v.violation_count, 0) = 0 THEN 100.0
            ELSE round(100.0 * (1 - v.open_violations::numeric / v.violation_count), 1)
       END                               AS overall_score,
       COALESCE(v.violations_30d, 0)     AS violations_30d,
       COALESCE(v.resolved_30d, 0)       AS resolved_30d,
       COALESCE(h.pending_hitl, 0)       AS pending_hitl,
       now()                             AS computed_at
FROM public.syst_tenants t
LEFT JOIN LATERAL (
    SELECT count(*)                                                          AS violation_count,
           count(*) FILTER (WHERE upper(pv.status) NOT IN ('REMEDIATED', 'WAIVED', 'CLOSED'))
                                                                             AS open_violations,
           count(*) FILTER (WHERE pv.detected_at >= now() - interval '30 days') AS violations_30d,
           count(*) FILTER (WHERE pv.resolved_at >= now() - interval '30 days') AS resolved_30d
    FROM public.compl_policy_violations pv
    WHERE pv.tenant_id = t.tenant_id
) v ON true
LEFT JOIN LATERAL (
    SELECT count(*)                                         AS evidence_count,
           count(*) FILTER (WHERE ev.signature IS NOT NULL) AS verified_evidence
    FROM public.compl_evidence ev
    WHERE ev.tenant_id = t.tenant_id
) e ON true
LEFT JOIN LATERAL (
    SELECT count(*) AS pending_hitl
    FROM public.core_hitl hd
    WHERE hd.tenant_id = t.tenant_id AND upper(hd.status) = 'PENDING'
) h ON true;

COMMENT ON VIEW public.vw_compliance_kpis IS
    'Per-tenant compliance KPIs derived from compl_policy_violations, compl_evidence and core_hitl (no stored aggregates).';

-- ============================================================================
-- Logical views (lv_*): one entity presented over a shared host table.
-- Subtype views filter the host on its discriminator (subtype/case_type/
-- record_type); subtype-only attributes are read from the host's JSONB
-- payload. Writes go through the INSTEAD OF trigger lv_dml (04_triggers).
-- ============================================================================

CREATE OR REPLACE VIEW public.lv_core_disputes WITH (security_invoker = true) AS
 SELECT case_id,
    tenant_id,
    agent_id,
    enforcement_action_id,
    hitl_decision_id,
    policy_id,
    platform_config_id,
    assessment_id,
    case_type,
    status,
    severity,
    title,
    description,
    evidence_ids,
    remediations,
    case_comments,
    assigned_to,
    assigned_at,
    required_votes,
    sla_breach_at,
    closed_at,
    closed_by,
    decision,
    retired_at,
    dedup_key,
    gra_case_id,
    dispute_id,
    violation_id,
    violated_policy_id,
    final_reputation_score,
    jurisdiction,
    is_internal,
    duration,
    metadata,
    created_at,
    updated_at,
    control_ref,
    framework,
    resolved_at,
    description AS reason,
    decision AS resolution,
    metadata ->> 'evidence_url'::text AS evidence_url,
    metadata ->> 'dispute_status'::text AS dispute_status,
    metadata ->> 'disputed_case_id'::text AS disputed_case_id
   FROM compl_cases h
  WHERE case_type = 'DISPUTE'::text;

CREATE OR REPLACE VIEW public.lv_core_gdpr_requests WITH (security_invoker = true) AS
 SELECT case_id,
    tenant_id,
    agent_id,
    enforcement_action_id,
    hitl_decision_id,
    policy_id,
    platform_config_id,
    assessment_id,
    case_type,
    status,
    severity,
    title,
    description,
    evidence_ids,
    remediations,
    case_comments,
    assigned_to,
    assigned_at,
    required_votes,
    sla_breach_at,
    closed_at,
    closed_by,
    decision,
    retired_at,
    dedup_key,
    gra_case_id,
    dispute_id,
    violation_id,
    violated_policy_id,
    final_reputation_score,
    jurisdiction,
    is_internal,
    duration,
    metadata,
    created_at,
    updated_at,
    control_ref,
    framework,
    resolved_at,
    case_id AS request_id,
    lv_ts(metadata ->> 'erased_at'::text) AS erased_at
   FROM compl_cases h
  WHERE case_type = 'GDPR_REQUEST'::text;

CREATE OR REPLACE VIEW public.vw_compliance_posture WITH (security_invoker=true) AS
 SELECT tenant_id,
    framework,
    count(*) AS total_controls,
    count(*) FILTER (WHERE upper(status) = 'COMPLIANT'::text) AS compliant_controls,
    count(*) FILTER (WHERE upper(status) = ANY (ARRAY['NON_COMPLIANT'::text, 'FAILED'::text, 'GAP'::text])) AS non_compliant_controls,
    round(100.0 * count(*) FILTER (WHERE upper(status) = 'COMPLIANT'::text)::numeric / NULLIF(count(*), 0)::numeric, 1) AS compliance_pct,
    COALESCE(sum(evidence_count), 0::bigint) AS evidence_count,
    max(last_assessed_at) AS last_assessed_at,
    min(next_review_at) AS next_review_at
   FROM compl_obligations o
  GROUP BY tenant_id, framework;
