-- Ring 3 Compliance Schema Comments
COMMENT ON TABLE core_compliance IS 'Compliance cases — violations, obligations, evidence. Owned by aocs-compliance-svc (Ring 3).';
COMMENT ON TABLE core_evidence IS 'Evidence vault entries with ZKP anchors. Owned by aocs-compliance-svc.';


-- ══ Superuser Runbook Deploy Notes (was superuser_runbook.sql) ──────────

-- =============================================================================
-- aocs-compliance-svc — Superuser Runbook
-- Ring: 3 — PAID compliance service (independently purchasable)
-- =============================================================================
-- WHO RUNS THIS: Platform engineer with Supabase postgres superuser access
-- WHERE TO RUN:  Supabase Dashboard → SQL Editor
-- WHEN TO RUN:   After Ring 0 (aocs-system-svc) tables are deployed.
--
-- RING DEPENDENCY:
--   DB Schema:  Same Supabase project as Ring 0, Ring 1, and Ring 2.
--               Tables live in compliance schema (not public).
--               FK to public.syst_tenants (Ring 0) — hard FK.
--               FK to Ring 2 tables (core: agents, HITL) — TEXT only (app-level enforced).
--
--   Runtime:    Calls Ring 0 (aocs-system) for tenant validation.
--               Calls Ring 2 (ocx-core-svc/aocs-hub) for agent execution data,
--               HITL decisions, enforcement actions.
--               Will START without Ring 1 running but report handlers 503
--               until Ring 2 (ocx-core-svc) is available.
--
-- STARTUP ORDER:
--   1. Run Ring 0 schema (aocs-system-svc) → syst_tenants must exist
--   2. Run this file (compliance schema + tables)
--   3. Optionally run Ring 2 schema (ocx-core-svc) — compliance reads Ring 2 at runtime
--   4. Start Ring 0 docker compose
--   5. Start aocs-compliance docker compose
--   6. Start Ring 2 docker compose — ocx-core-svc (compliance gains full agent data)
-- =============================================================================

-- =============================================================================
-- SCHEMA DEPLOY ORDER — aocs-compliance-svc
-- =============================================================================
--
--  FILE                                        PURPOSE
--  ─────────────────────────────────────────────────────────────────────────
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
  -- gen_id() must exist in public schema
    SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public' AND p.proname = 'gen_id'
    RAISE EXCEPTION 'gen_id() not found. Run 00_gen_id_function.sql first.';

  -- Ring 0: syst_tenants must exist
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'syst_tenants'
    RAISE EXCEPTION
      'public.syst_tenants not found. Run aocs-system-svc Ring 0 schema first.';


-- ─────────────────────────────────────────────────────────────────────────────
-- SECTION 1: Verify compliance schema exists
-- ─────────────────────────────────────────────────────────────────────────────
    RAISE EXCEPTION 'compliance schema not found. Run 00_compliance_schema.sql first.';

-- ─────────────────────────────────────────────────────────────────────────────
-- SECTION 2: Verify compliance tables deployed
-- ─────────────────────────────────────────────────────────────────────────────
SELECT table_name, table_schema
FROM information_schema.tables
WHERE table_schema = 'compliance'
ORDER BY table_name;

-- ─────────────────────────────────────────────────────────────────────────────
-- ─────────────────────────────────────────────────────────────────────────────
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'compliance' AND table_name = 'core_compliance'