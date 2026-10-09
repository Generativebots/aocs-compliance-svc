-- GX-15: gate BLOCK / ESC decisions become compliance violations, and
-- HIGH/CRITICAL violations open (or join) a compliance case.
--
-- compl_policy_violations
--   policy_id     nullable: most gate refusals are not a policy match (trust
--                 floor, unknown tool, guardian, anomaly). Inventing a policy
--                 id would be false evidence.
--   source_tx_id  the gate decision (core_gate_decisions.tx_id) the violation
--                 was harvested from. Unique per tenant: the harvester is
--                 idempotent and safe on every replica.
--   case_id       the compl_cases row the violation belongs to (if any).
ALTER TABLE public.compl_policy_violations ALTER COLUMN policy_id DROP NOT NULL;
ALTER TABLE public.compl_policy_violations ADD COLUMN IF NOT EXISTS source_tx_id TEXT;
ALTER TABLE public.compl_policy_violations ADD COLUMN IF NOT EXISTS case_id TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS uq_compl_policy_violations_source_tx
    ON public.compl_policy_violations (tenant_id, source_tx_id) WHERE source_tx_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_compl_policy_violations_case
    ON public.compl_policy_violations (tenant_id, case_id) WHERE case_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_compl_policy_violations_open
    ON public.compl_policy_violations (tenant_id, detected_at DESC) WHERE status = 'OPEN';

-- Open-case lookup for a violation group (agent + policy/tool).
CREATE INDEX IF NOT EXISTS idx_compl_cases_gate_group
    ON public.compl_cases (tenant_id, (metadata->>'gate_group'))
    WHERE metadata ? 'gate_group' AND status IN ('OPEN', 'INVESTIGATING');

-- vw_compliance_kpis counted REMEDIATED and WAIVED violations as open: the
-- filter listed statuses the table does not have (RESOLVED, DISMISSED). The
-- table's closed statuses are REMEDIATED, WAIVED and CLOSED.
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
