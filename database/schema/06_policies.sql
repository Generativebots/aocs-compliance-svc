-- =============================================================================
-- 06_policies.sql — aocs-compliance-svc
-- RLS policies on compliance schema tables
-- =============================================================================

ALTER TABLE compliance.core_compliance        ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.aocs_compliance_controls     ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.aocs_evidence                ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.aocs_zkp_proofs              ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.aocs_dlp_findings            ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.nexus_compliance_reports     ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.core_compliance_comments           ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.shar_trust  ENABLE ROW LEVEL SECURITY;

-- Tenant isolation policy (applies to all compliance tables)
-- Superadmin bypass + tenant isolation pattern (same as Ring 0)
DO $$ DECLARE t TEXT; BEGIN
  FOREACH t IN ARRAY ARRAY[
    'core_compliance','aocs_compliance_controls','aocs_evidence',
    'aocs_zkp_proofs','aocs_dlp_findings','nexus_compliance_reports',
    'core_compliance_comments','shar_trust'
  ] LOOP
    EXECUTE format('DROP POLICY IF EXISTS superadmin_all ON compliance.%I', t);
    EXECUTE format('CREATE POLICY superadmin_all ON compliance.%I USING ((auth.jwt()->>''app_metadata''->>''is_super_admin'')::boolean = true)', t);

    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON compliance.%I', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON compliance.%I USING (tenant_id = (auth.jwt()->''app_metadata''->>''tenant_id''))', t);
  END LOOP;
END $$;

-- Grant table access to svc_compliance role
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA compliance TO svc_compliance;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA compliance TO service_role;
GRANT SELECT ON ALL TABLES IN SCHEMA compliance TO authenticated;

SELECT 'compliance RLS policies deployed' AS status;
