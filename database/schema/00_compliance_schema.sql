-- =============================================================================
-- 00_compliance_schema.sql — aocs-compliance-svc
-- =============================================================================
-- Creates the compliance schema and grants.
-- Run BEFORE any other compliance schema files.
-- Run AFTER Ring 0 (aocs-system-svc) schema is deployed.
--
-- Why compliance schema (not public)?
--   - Clean separation: compliance tables never pollute the Ring 0 public schema
--   - Supabase RLS policies are schema-scoped
--   - The Go DATABASE_URL includes search_path=compliance,public so both schemas
--     are visible: compliance.* for own tables, public.aocs_tenants for Ring 0 FKs
-- =============================================================================

-- Create compliance schema
CREATE SCHEMA IF NOT EXISTS compliance;

-- Grant schema usage to service roles
GRANT USAGE ON SCHEMA compliance TO postgres, anon, authenticated, service_role;
GRANT USAGE ON SCHEMA compliance TO svc_platform;

-- Create svc_compliance role (if it doesn't exist)
DO $$ BEGIN
    CREATE ROLE svc_compliance NOLOGIN NOINHERIT;
    COMMENT ON ROLE svc_compliance IS
        'Ring 0-adjacent — aocs-compliance-svc. ZKP, DLP, compliance cases, evidence vault. '
        'Runtime deps: Ring 0 (aocs-system for tenant data) + Ring 1 (aocs-core for agent data).';
EXCEPTION WHEN duplicate_object THEN
    RAISE NOTICE 'Role svc_compliance already exists — skipping';
END $$;

GRANT USAGE ON SCHEMA compliance TO svc_compliance;

-- Set default search_path for compliance role
ALTER ROLE svc_compliance SET search_path TO compliance, public;

SELECT 'compliance schema created' AS status;
