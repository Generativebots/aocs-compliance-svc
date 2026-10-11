-- A2.3 / UX-21: Command Center facts from compliance tables, same columns as
-- public.v_cc_core_facts (ocx-core-svc). GET /api/v1/command-center/view
-- (aocs-system) reads both in one statement; it only reads the 'violations'
-- section when the caller has compliance:read and the compliance module.
CREATE OR REPLACE VIEW public.v_cc_compl_facts WITH (security_invoker=true) AS
 SELECT v.tenant_id,
    'violations'::text AS section,
    lower(COALESCE(v.violation_type, 'violation')) AS kind,
    CASE WHEN v.resolved_at IS NULL AND upper(COALESCE(v.status, 'OPEN')) NOT IN ('RESOLVED', 'CLOSED', 'DISMISSED')
         THEN 'open' ELSE 'closed' END AS state,
    upper(v.severity) AS severity,
    v.agent_id,
    NULL::text AS label,
    COALESCE(v.detected_at, v.created_at) AS occurred_at,
    NULL::numeric AS amount,
    false AS flag
   FROM compl_policy_violations v;

COMMENT ON VIEW public.v_cc_compl_facts IS
  'A2.3 Command Center facts (compliance tables). Same shape as v_cc_core_facts; read by GET /api/v1/command-center/view.';
