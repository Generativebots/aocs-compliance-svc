-- =============================================================================
-- aocs-compliance-svc — Superuser Runbook
-- Ring: 0-adjacent — always-on compliance observability + evidence layer
-- =============================================================================
-- WHO RUNS THIS: Platform engineer with Supabase postgres superuser access
-- WHERE TO RUN:  Supabase Dashboard → SQL Editor
-- WHEN TO RUN:   After Ring 0 (aocs-system-svc) tables are deployed.
--
-- RING DEPENDENCY:
--   DB Schema:  Same Supabase project as Ring 0 and Ring 1.
--               Tables live in compliance schema (not public).
--               FK to public.aocs_tenants (Ring 0) — hard FK.
--               FK to Ring 1 tables — TEXT only (app-level enforced).
--
--   Runtime:    Calls Ring 0 (aocs-system) for tenant validation.
--               Calls Ring 1 (aocs-core/aocs-hub) for agent execution data,
--               HITL decisions, enforcement actions.
--               Will START without Ring 1 running but report handlers 503
--               until Ring 1 is available.
--
-- STARTUP ORDER:
--   1. Run Ring 0 schema (aocs-system-svc) → aocs_tenants must exist
--   2. Run this file (compliance schema + tables)
--   3. Optionally run Ring 1 schema (ocx-core-svc) — compliance reads Ring 1 at runtime
--   4. Start Ring 0 docker compose
--   5. Start aocs-compliance docker compose
--   6. Start Ring 1 docker compose (compliance gains full functionality)
-- =============================================================================

-- =============================================================================
-- SCHEMA DEPLOY ORDER — aocs-compliance-svc
-- =============================================================================
--
--  FILE                                        PURPOSE
--  ─────────────────────────────────────────────────────────────────────────
--  database/schema/00_gen_id_function.sql     ← gen_id() (idempotent — skip if exists)
--  database/schema/00_compliance_schema.sql   ← CREATE SCHEMA compliance + grants
--  database/schema/01_tables.sql             ← all compliance tables
--  database/schema/04_triggers.sql           ← updated_at + evidence count sync
--  database/schema/05_indexes.sql            ← performance indexes
--  database/schema/06_policies.sql           ← RLS policies
--  database/seeds/00_seed_controls.sql       ← default SOC2/EU AI Act control framework
-- =============================================================================

-- ─────────────────────────────────────────────────────────────────────────────
-- SECTION 0: Prerequisite checks
-- ─────────────────────────────────────────────────────────────────────────────
DO $$
BEGIN
  -- gen_id() must exist in public schema
  IF NOT EXISTS (
    SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public' AND p.proname = 'gen_id'
  ) THEN
    RAISE EXCEPTION 'gen_id() not found. Run 00_gen_id_function.sql first.';
  END IF;

  -- Ring 0: aocs_tenants must exist
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'aocs_tenants'
  ) THEN
    RAISE EXCEPTION
      'public.aocs_tenants not found. Run aocs-system-svc Ring 0 schema first.';
  END IF;

  RAISE NOTICE 'Prerequisites met — Ring 0 tables exist, gen_id() available';
END $$;

-- ─────────────────────────────────────────────────────────────────────────────
-- SECTION 1: Verify compliance schema exists
-- ─────────────────────────────────────────────────────────────────────────────
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = 'compliance') THEN
    RAISE EXCEPTION 'compliance schema not found. Run 00_compliance_schema.sql first.';
  END IF;
  RAISE NOTICE 'compliance schema exists';
END $$;

-- ─────────────────────────────────────────────────────────────────────────────
-- SECTION 2: Verify compliance tables deployed
-- ─────────────────────────────────────────────────────────────────────────────
SELECT table_name, table_schema
FROM information_schema.tables
WHERE table_schema = 'compliance'
ORDER BY table_name;

-- ─────────────────────────────────────────────────────────────────────────────
-- SECTION 3: Grant svc_compliance role access
-- ─────────────────────────────────────────────────────────────────────────────
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'compliance' AND table_name = 'aocs_compliance_cases'
  ) THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA compliance TO svc_compliance;
    GRANT SELECT ON ALL TABLES IN SCHEMA compliance TO svc_platform;
    RAISE NOTICE 'Grants applied to svc_compliance and svc_platform';
  ELSE
    RAISE NOTICE 'compliance tables not found — run 01_tables.sql first';
  END IF;
END $$;
