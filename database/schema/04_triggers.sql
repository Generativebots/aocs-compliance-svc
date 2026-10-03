-- =============================================================================
-- 04_triggers.sql — aocs-compliance-svc
-- All compliance tables now live in the PUBLIC schema (Decision 2026-09-05).
-- Function names use public schema prefix. Table names use compl_* prefix.
--
-- DBA AUDIT FIXES (2026-09-29):
--   Those two tables are defined at the BOTTOM of 01_tables.sql (after the other
--   compl_* tables). When 04_triggers.sql runs, the FOREACH loop must only reference
--   tables that already exist. The two late-defined tables are handled explicitly
--   below with DO $$ BEGIN ... EXCEPTION WHEN undefined_table guards.
--
--   FIXED fn_compl_sync_evidence_count: now handles UPDATE (control_id change)
--   to avoid evidence_count drift when an evidence row is re-filed.
-- =============================================================================

-- ── Canonical updated_at trigger function (compl_ domain) ───────────────────
CREATE OR REPLACE FUNCTION public.fn_compl_set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at := NOW(); RETURN NEW; END;
$$;

COMMENT ON FUNCTION public.fn_compl_set_updated_at() IS
    'Canonical updated_at setter for all compl_* tables. Single authoritative '
    'function — do not create per-table aliases.';

-- ── Apply updated_at trigger to early-defined compl_* tables ─────────────────
-- compl_tenant_baselines and compl_evidence_vault are excluded here —
-- they are defined later in 01_tables.sql and handled explicitly below.
DO $$ DECLARE t TEXT; BEGIN
  FOREACH t IN ARRAY ARRAY[
    'compl_records',
    'compl_obligations',
    'compl_evidence',
    'compl_dlp_integrations',
    'compl_reports',
    'compl_case_comments',
    'compl_signing_keys',
    'compl_anomaly',
    'compl_policy_violations',
    'compl_regulatory',
    'compl_policy_exceptions',
    'compl_risk_assessments',
    'compl_cases'
  ] LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS trg_%s_updated_at ON %I', t, t);
    EXECUTE format(
      'CREATE TRIGGER trg_%s_updated_at BEFORE UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION public.fn_compl_set_updated_at()',
      t, t
    );
  END LOOP;
END $$;

-- ── Late-defined tables: apply updated_at triggers with existence guard ───────
-- These tables are defined after the FOREACH block in 01_tables.sql.
DO $$ BEGIN
    DROP TRIGGER IF EXISTS trg_compl_tenant_baselines_updated_at ON compl_tenant_baselines;
    CREATE TRIGGER trg_compl_tenant_baselines_updated_at
        BEFORE UPDATE ON compl_tenant_baselines
        FOR EACH ROW EXECUTE FUNCTION public.fn_compl_set_updated_at();
EXCEPTION WHEN undefined_table THEN
    RAISE NOTICE 'compl_tenant_baselines not yet created — trigger skipped';
END $$;

DO $$ BEGIN
    DROP TRIGGER IF EXISTS trg_compl_evidence_vault_updated_at ON compl_evidence_vault;
    CREATE TRIGGER trg_compl_evidence_vault_updated_at
        BEFORE UPDATE ON compl_evidence_vault
        FOR EACH ROW EXECUTE FUNCTION public.fn_compl_set_updated_at();
EXCEPTION WHEN undefined_table THEN
    RAISE NOTICE 'compl_evidence_vault not yet created — trigger skipped';
END $$;

-- ── Evidence control count sync trigger ───────────────────────────────────────
-- Keeps compl_records.evidence_count accurate when evidence items are filed,
-- deleted, or re-filed to a different control.
CREATE OR REPLACE FUNCTION public.fn_compl_sync_evidence_count()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  -- SCHEMA FIX: counter lives on compl_obligations (control_id PK), not compl_records.
  IF TG_OP = 'INSERT' AND NEW.control_id IS NOT NULL THEN
    UPDATE compl_obligations SET evidence_count = COALESCE(evidence_count, 0) + 1
     WHERE control_id = NEW.control_id;
  ELSIF TG_OP = 'DELETE' AND OLD.control_id IS NOT NULL THEN
    UPDATE compl_obligations SET evidence_count = GREATEST(0, COALESCE(evidence_count, 0) - 1)
     WHERE control_id = OLD.control_id;
  ELSIF TG_OP = 'UPDATE' AND OLD.control_id IS DISTINCT FROM NEW.control_id THEN
    IF OLD.control_id IS NOT NULL THEN
      UPDATE compl_obligations SET evidence_count = GREATEST(0, COALESCE(evidence_count, 0) - 1)
       WHERE control_id = OLD.control_id;
    END IF;
    IF NEW.control_id IS NOT NULL THEN
      UPDATE compl_obligations SET evidence_count = COALESCE(evidence_count, 0) + 1
       WHERE control_id = NEW.control_id;
    END IF;
  END IF;
  RETURN COALESCE(NEW, OLD);
END;
$$;

COMMENT ON FUNCTION public.fn_compl_sync_evidence_count() IS
    'Keeps compl_records.evidence_count in sync with compl_evidence row changes. '
    'Handles INSERT (increment), DELETE (decrement), and UPDATE with control_id change '
    '(decrement old + increment new). Floor at 0 prevents negative counts.';

DROP TRIGGER IF EXISTS trg_evidence_count_sync ON compl_evidence;
CREATE TRIGGER trg_evidence_count_sync
  AFTER INSERT OR UPDATE OR DELETE ON compl_evidence
  FOR EACH ROW EXECUTE FUNCTION public.fn_compl_sync_evidence_count();


-- Moved from ocx-extension-svc 04_triggers.sql (2026-10-03): compl_cases is compliance-owned.
-- fn_compliance_case_event / sync_agent_open_cases are defined in ocx-core-svc 03_functions/04_triggers.
-- ── compl_cases: lifecycle events + open_cases sync + updated_at ─────────────
DROP TRIGGER IF EXISTS trg_compliance_case_events ON compl_cases;
CREATE TRIGGER trg_compliance_case_events
    AFTER INSERT OR UPDATE ON compl_cases
    FOR EACH ROW EXECUTE FUNCTION public.fn_compliance_case_event();

DROP TRIGGER IF EXISTS trg_sync_agent_open_cases ON compl_cases;
CREATE TRIGGER trg_sync_agent_open_cases
    AFTER INSERT OR DELETE OR UPDATE ON compl_cases
    FOR EACH ROW EXECUTE FUNCTION public.sync_agent_open_cases();

DROP TRIGGER IF EXISTS trg_compl_cases_updated_at ON compl_cases;
CREATE TRIGGER trg_compl_cases_updated_at
    BEFORE UPDATE ON compl_cases
    FOR EACH ROW EXECUTE FUNCTION public.trg_set_updated_at();

-- ============================================================================
-- Logical views (lv_*): INSTEAD OF triggers route INSERT/UPDATE/DELETE
-- to the host table. lv_dml args: host, host PK, discriminator column,
-- discriminator value, payload column, {view_column: host_column} synonyms.
-- ============================================================================
CREATE OR REPLACE TRIGGER lv_core_disputes_dml INSTEAD OF INSERT OR DELETE OR UPDATE ON public.lv_core_disputes FOR EACH ROW EXECUTE FUNCTION public.lv_dml('compl_cases', 'case_id', 'case_type', 'DISPUTE', 'metadata', '{"reason": "description", "resolution": "decision"}');
CREATE OR REPLACE TRIGGER lv_core_gdpr_requests_dml INSTEAD OF INSERT OR DELETE OR UPDATE ON public.lv_core_gdpr_requests FOR EACH ROW EXECUTE FUNCTION public.lv_dml('compl_cases', 'case_id', 'case_type', 'GDPR_REQUEST', 'metadata', '{"request_id": "case_id"}');
