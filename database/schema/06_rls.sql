-- =============================================================================
-- 06_policies.sql — aocs-compliance-svc
-- RLS policies on compliance schema tables
-- =============================================================================

ALTER TABLE compliance.core_compliance        ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.core_compliance     ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.core_evidence                ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.core_evidence              ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.shar_dlp_integrations            ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.nexus_compliance_reports     ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.core_compliance_comments           ENABLE ROW LEVEL SECURITY;
-- shar_trust: removed from RLS — table merged into core_trust_events.

-- Tenant isolation policy (applies to all compliance tables)
-- Superadmin bypass + tenant isolation pattern (same as Ring 0)
DO $$ DECLARE t TEXT; BEGIN
  FOREACH t IN ARRAY ARRAY[
    'core_compliance','core_compliance','core_evidence',
    'core_evidence','shar_dlp_integrations','nexus_compliance_reports',
    'core_compliance_comments'
    -- shar_trust removed: merged into core_trust_events
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


-- ══ Superuser Roles & Grants (was superuser_runbook.sql §1-4) ───────────

--  database/schema/00_gen_id_function.sql     ← gen_id() (idempotent — skip if exists)
DO $$
BEGIN
  IF NOT EXISTS (
  ) THEN
  END IF;
  IF NOT EXISTS (
  ) THEN
  END IF;
  RAISE NOTICE 'Prerequisites met — Ring 0 tables exist, gen_id() available';
END $$;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = 'compliance') THEN
  END IF;
  RAISE NOTICE 'compliance schema exists';
END $$;
-- SECTION 3: Grant svc_compliance role access
DO $$
BEGIN
  IF EXISTS (
  ) THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA compliance TO svc_compliance;
    GRANT SELECT ON ALL TABLES IN SCHEMA compliance TO svc_platform;
    RAISE NOTICE 'Grants applied to svc_compliance and svc_platform';
  ELSE
    RAISE NOTICE 'compliance tables not found — run 01_tables.sql first';
  END IF;
END $$;