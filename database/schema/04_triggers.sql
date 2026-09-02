-- =============================================================================
-- 04_triggers.sql — aocs-compliance-svc
-- compliance schema triggers
-- =============================================================================

-- updated_at trigger function (reuse public.fn_set_updated_at if exists, else create)
CREATE OR REPLACE FUNCTION compliance.fn_set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at := NOW(); RETURN NEW; END;
$$;

-- Apply updated_at trigger to all compliance tables with updated_at column
DO $$ DECLARE t TEXT; BEGIN
  FOREACH t IN ARRAY ARRAY[
    'core_compliance',
    'aocs_compliance_controls',
    'aocs_evidence',
    'nexus_compliance_reports'
  ] LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS trg_%s_updated_at ON compliance.%I', t, t);
    EXECUTE format(
      'CREATE TRIGGER trg_%s_updated_at BEFORE UPDATE ON compliance.%I FOR EACH ROW EXECUTE FUNCTION compliance.fn_set_updated_at()',
      t, t
    );
  END LOOP;
END $$;

-- Evidence control count sync trigger
CREATE OR REPLACE FUNCTION compliance.fn_sync_evidence_count()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP IN ('INSERT') AND NEW.control_id IS NOT NULL THEN
    UPDATE compliance.aocs_compliance_controls
    SET evidence_count = evidence_count + 1
    WHERE control_id = NEW.control_id;
  END IF;
  IF TG_OP = 'DELETE' AND OLD.control_id IS NOT NULL THEN
    UPDATE compliance.aocs_compliance_controls
    SET evidence_count = GREATEST(0, evidence_count - 1)
    WHERE control_id = OLD.control_id;
  END IF;
  RETURN COALESCE(NEW, OLD);
END;
$$;
DROP TRIGGER IF EXISTS trg_evidence_count_sync ON compliance.aocs_evidence;
CREATE TRIGGER trg_evidence_count_sync
  AFTER INSERT OR DELETE ON compliance.aocs_evidence
  FOR EACH ROW EXECUTE FUNCTION compliance.fn_sync_evidence_count();

SELECT 'compliance triggers deployed' AS status;
