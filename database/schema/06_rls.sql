-- =============================================================================
-- 06_rls.sql — aocs-compliance-svc
-- RLS policies on compl_* tables (all in PUBLIC schema, Decision 2026-09-05).
-- Run AFTER 01_tables.sql.
-- =============================================================================

-- ── Enable & Force RLS on all compliance tables ──────────────────────────────
ALTER TABLE compl_records              ENABLE ROW LEVEL SECURITY;
ALTER TABLE compl_records              FORCE  ROW LEVEL SECURITY;
ALTER TABLE compl_obligations  ENABLE ROW LEVEL SECURITY;
ALTER TABLE compl_obligations  FORCE  ROW LEVEL SECURITY;
ALTER TABLE compl_evidence                ENABLE ROW LEVEL SECURITY;
ALTER TABLE compl_evidence                FORCE  ROW LEVEL SECURITY;
ALTER TABLE compl_evidence_anchors        ENABLE ROW LEVEL SECURITY;
ALTER TABLE compl_evidence_anchors        FORCE  ROW LEVEL SECURITY;
ALTER TABLE compl_dlp_integrations        ENABLE ROW LEVEL SECURITY;
ALTER TABLE compl_dlp_integrations        FORCE  ROW LEVEL SECURITY;
ALTER TABLE compl_reports     ENABLE ROW LEVEL SECURITY;
ALTER TABLE compl_reports     FORCE  ROW LEVEL SECURITY;
ALTER TABLE compl_case_comments     ENABLE ROW LEVEL SECURITY;
ALTER TABLE compl_case_comments     FORCE  ROW LEVEL SECURITY;
ALTER TABLE compl_signing_keys        ENABLE ROW LEVEL SECURITY;
ALTER TABLE compl_signing_keys        FORCE  ROW LEVEL SECURITY;
ALTER TABLE compl_anomaly       ENABLE ROW LEVEL SECURITY;
ALTER TABLE compl_anomaly       FORCE  ROW LEVEL SECURITY;
ALTER TABLE compl_policy_violations       ENABLE ROW LEVEL SECURITY;
ALTER TABLE compl_policy_violations       FORCE  ROW LEVEL SECURITY;
ALTER TABLE compl_regulatory  ENABLE ROW LEVEL SECURITY;
ALTER TABLE compl_regulatory  FORCE  ROW LEVEL SECURITY;
ALTER TABLE compl_policy_exceptions       ENABLE ROW LEVEL SECURITY;
ALTER TABLE compl_policy_exceptions       FORCE  ROW LEVEL SECURITY;
ALTER TABLE compl_risk_assessments    ENABLE ROW LEVEL SECURITY;
ALTER TABLE compl_risk_assessments    FORCE  ROW LEVEL SECURITY;
ALTER TABLE compl_cases             ENABLE ROW LEVEL SECURITY;
ALTER TABLE compl_cases             FORCE  ROW LEVEL SECURITY;
-- GAP-RLS-01 FIX: new tables from cross-ring propagation work
ALTER TABLE compl_tenant_baselines             ENABLE ROW LEVEL SECURITY;
ALTER TABLE compl_tenant_baselines             FORCE  ROW LEVEL SECURITY;
ALTER TABLE compl_evidence_vault         ENABLE ROW LEVEL SECURITY;
ALTER TABLE compl_evidence_vault         FORCE  ROW LEVEL SECURITY;
ALTER TABLE compl_idempotency_log              ENABLE ROW LEVEL SECURITY;
ALTER TABLE compl_idempotency_log              FORCE  ROW LEVEL SECURITY;

-- ── Tenant isolation + superadmin bypass (all tenant-scoped compl_* tables) ──
DO $$ DECLARE t TEXT; BEGIN
  FOREACH t IN ARRAY ARRAY[
    'compl_records',
    'compl_obligations',
    'compl_evidence',
    'compl_evidence_anchors',
    'compl_dlp_integrations',
    'compl_reports',
    'compl_case_comments',
    'compl_policy_violations',
    'compl_regulatory',
    'compl_policy_exceptions',
    'compl_risk_assessments',
    'compl_cases',
    'compl_tenant_baselines',
    'compl_evidence_vault'
  ] LOOP
    EXECUTE format('DROP POLICY IF EXISTS superadmin_all ON %I', t);
    EXECUTE format(
      'CREATE POLICY superadmin_all ON %I '
      'USING ((auth.jwt()->>''app_metadata''->>''is_super_admin'')::boolean = true)',
      t
    );
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I '
      'USING (tenant_id = (auth.jwt()->''app_metadata''->>''tenant_id''))',
      t
    );
  END LOOP;
END $$;

-- ── idempotency_log — service_role only (internal dedup table, no auth access) ─
DROP POLICY IF EXISTS idempotency_log_service_role ON compl_idempotency_log;
CREATE POLICY idempotency_log_service_role ON compl_idempotency_log
    FOR ALL TO service_role USING (true) WITH CHECK (true);


-- ── platform_signing_keys — superadmin only (no tenant_id column) ────────────
DROP POLICY IF EXISTS signing_keys_superadmin_only ON compl_signing_keys;
CREATE POLICY signing_keys_superadmin_only ON compl_signing_keys
    FOR ALL TO authenticated
    USING ((current_setting('request.jwt.claims', true)::jsonb->>'is_superadmin')::boolean = true);

-- ── core_anomaly_detection — service role only (CollusionStore) ──────────────
DROP POLICY IF EXISTS collusion_ip_service_role_only ON compl_anomaly;
CREATE POLICY collusion_ip_service_role_only ON compl_anomaly
    FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── Grants — per-table (public schema, not compliance schema) ───────────────
-- svc_compliance: full access to all compl_* tables
GRANT SELECT, INSERT, UPDATE, DELETE ON
    compl_records, compl_obligations, compl_evidence, compl_evidence_anchors,
    compl_dlp_integrations, compl_reports, compl_case_comments, compl_signing_keys,
    compl_anomaly, compl_policy_violations, compl_regulatory, compl_policy_exceptions,
    compl_risk_assessments, compl_cases, compl_tenant_baselines, compl_evidence_vault,
    compl_idempotency_log
    TO svc_compliance, service_role;
GRANT SELECT ON
    compl_records, compl_obligations, compl_evidence, compl_evidence_anchors,
    compl_dlp_integrations, compl_reports, compl_case_comments,
    compl_policy_violations, compl_regulatory, compl_policy_exceptions,
    compl_risk_assessments, compl_cases, compl_tenant_baselines, compl_evidence_vault
    TO authenticated, svc_platform;
