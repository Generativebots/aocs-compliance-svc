-- =============================================================================
-- 04_triggers.sql — aocs-compliance-svc
-- All compliance tables now live in the PUBLIC schema (Decision 2026-09-05).
-- Function names use public schema prefix. Table names use compl_* prefix.
-- =============================================================================

-- updated_at trigger function (dedicated compl_ version in public schema)
CREATE OR REPLACE FUNCTION public.fn_compl_set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at := NOW(); RETURN NEW; END;
$$;

-- Apply updated_at trigger to all compl_* tables with updated_at column
-- (compl_evidence_anchors and compl_idempotency_log are excluded — no updated_at)
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
    'compl_cases',
    'compl_tenant_baselines',
    'compl_evidence_vault'
  ] LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS trg_%s_updated_at ON %I', t, t);
    EXECUTE format(
      'CREATE TRIGGER trg_%s_updated_at BEFORE UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION public.fn_compl_set_updated_at()',
      t, t
    );
  END LOOP;
END $$;

-- Evidence control count sync trigger
CREATE OR REPLACE FUNCTION public.fn_compl_sync_evidence_count()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP IN ('INSERT') AND NEW.control_id IS NOT NULL THEN
    UPDATE compl_records
    SET evidence_count = evidence_count + 1
    WHERE control_id = NEW.control_id;
  END IF;
  IF TG_OP = 'DELETE' AND OLD.control_id IS NOT NULL THEN
    UPDATE compl_records
    SET evidence_count = GREATEST(0, evidence_count - 1)
    WHERE control_id = OLD.control_id;
  END IF;
  RETURN COALESCE(NEW, OLD);
END;
$$;
DROP TRIGGER IF EXISTS trg_evidence_count_sync ON compl_evidence;
CREATE TRIGGER trg_evidence_count_sync
  AFTER INSERT OR DELETE ON compl_evidence
  FOR EACH ROW EXECUTE FUNCTION public.fn_compl_sync_evidence_count();

SELECT 'compliance triggers deployed' AS status;
