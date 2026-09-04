-- =============================================================================
-- 06_rls.sql — aocs-compliance-svc
-- RLS policies on compliance schema tables.
-- Run AFTER 01_tables.sql. All tables in the compliance schema.
-- =============================================================================

-- ── Enable & Force RLS on all compliance tables ──────────────────────────────
ALTER TABLE compliance.core_compliance              ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.core_compliance              FORCE  ROW LEVEL SECURITY;
ALTER TABLE compliance.core_compliance_obligations  ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.core_compliance_obligations  FORCE  ROW LEVEL SECURITY;
ALTER TABLE compliance.core_evidence                ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.core_evidence                FORCE  ROW LEVEL SECURITY;
ALTER TABLE compliance.core_evidence_anchors        ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.core_evidence_anchors        FORCE  ROW LEVEL SECURITY;
ALTER TABLE compliance.shar_dlp_integrations        ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.shar_dlp_integrations        FORCE  ROW LEVEL SECURITY;
ALTER TABLE compliance.nexus_compliance_reports     ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.nexus_compliance_reports     FORCE  ROW LEVEL SECURITY;
ALTER TABLE compliance.core_compliance_comments     ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.core_compliance_comments     FORCE  ROW LEVEL SECURITY;
ALTER TABLE compliance.platform_signing_keys        ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.platform_signing_keys        FORCE  ROW LEVEL SECURITY;
ALTER TABLE compliance.core_anomaly_detection       ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.core_anomaly_detection       FORCE  ROW LEVEL SECURITY;
ALTER TABLE compliance.core_policy_violations       ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.core_policy_violations       FORCE  ROW LEVEL SECURITY;
ALTER TABLE compliance.core_regulatory_obligations  ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.core_regulatory_obligations  FORCE  ROW LEVEL SECURITY;
ALTER TABLE compliance.core_policy_exceptions       ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.core_policy_exceptions       FORCE  ROW LEVEL SECURITY;
ALTER TABLE compliance.core_gra_risk_assessments    ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.core_gra_risk_assessments    FORCE  ROW LEVEL SECURITY;
ALTER TABLE compliance.compliance_cases             ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.compliance_cases             FORCE  ROW LEVEL SECURITY;
-- GAP-RLS-01 FIX: new tables from cross-ring propagation work
ALTER TABLE compliance.tenant_baselines             ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.tenant_baselines             FORCE  ROW LEVEL SECURITY;
ALTER TABLE compliance.agent_evidence_vault         ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.agent_evidence_vault         FORCE  ROW LEVEL SECURITY;
ALTER TABLE compliance.idempotency_log              ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.idempotency_log              FORCE  ROW LEVEL SECURITY;

-- ── Tenant isolation + superadmin bypass (all tenant-scoped tables) ──────────
DO $$ DECLARE t TEXT; BEGIN
  FOREACH t IN ARRAY ARRAY[
    'core_compliance',
    'core_compliance_obligations',
    'core_evidence',
    'core_evidence_anchors',
    'shar_dlp_integrations',
    'nexus_compliance_reports',
    'core_compliance_comments',
    'core_policy_violations',
    'core_regulatory_obligations',
    'core_policy_exceptions',
    'core_gra_risk_assessments',
    'compliance_cases',
    'tenant_baselines',
    'agent_evidence_vault'
  ] LOOP
    EXECUTE format('DROP POLICY IF EXISTS superadmin_all ON compliance.%I', t);
    EXECUTE format(
      'CREATE POLICY superadmin_all ON compliance.%I '
      'USING ((auth.jwt()->>''app_metadata''->>''is_super_admin'')::boolean = true)',
      t
    );
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON compliance.%I', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON compliance.%I '
      'USING (tenant_id = (auth.jwt()->''app_metadata''->>''tenant_id''))',
      t
    );
  END LOOP;
END $$;

-- ── idempotency_log — service_role only (internal dedup table, no auth access) ─
DROP POLICY IF EXISTS idempotency_log_service_role ON compliance.idempotency_log;
CREATE POLICY idempotency_log_service_role ON compliance.idempotency_log
    FOR ALL TO service_role USING (true) WITH CHECK (true);


-- ── platform_signing_keys — superadmin only (no tenant_id column) ────────────
DROP POLICY IF EXISTS signing_keys_superadmin_only ON compliance.platform_signing_keys;
CREATE POLICY signing_keys_superadmin_only ON compliance.platform_signing_keys
    FOR ALL TO authenticated
    USING ((current_setting('request.jwt.claims', true)::jsonb->>'is_superadmin')::boolean = true);

-- ── core_anomaly_detection — service role only (CollusionStore) ──────────────
DROP POLICY IF EXISTS collusion_ip_service_role_only ON compliance.core_anomaly_detection;
CREATE POLICY collusion_ip_service_role_only ON compliance.core_anomaly_detection
    FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── Grants ───────────────────────────────────────────────────────────────────
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA compliance TO svc_compliance;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA compliance TO service_role;
GRANT SELECT ON ALL TABLES IN SCHEMA compliance TO authenticated;
-- Ring 0 (svc_platform) reads compliance tables for dashboard summaries
GRANT SELECT ON ALL TABLES IN SCHEMA compliance TO svc_platform;
