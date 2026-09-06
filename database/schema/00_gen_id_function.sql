-- =============================================================================
-- 00_gen_id_function.sql — MUST run BEFORE 01_tables.sql
-- =============================================================================
-- PURPOSE:
--   Creates gen_id(), the universal ID generator used as DEFAULT on ALL PKs.
--   Single overload: gen_id(prefix TEXT DEFAULT '') — no separate no-arg function.
--   M-05 FIX: Removed the no-arg gen_id() overload that caused 42725 ambiguity.
--   Column defaults using gen_id() without args resolve via DEFAULT param.
--
-- IDEMPOTENT: CREATE OR REPLACE — safe to re-run.
-- =============================================================================

-- ── Single canonical overload: gen_id('ten') → 'ten_<uuid>', gen_id() → '<uuid>' ─
CREATE OR REPLACE FUNCTION public.gen_id(prefix TEXT DEFAULT '')
RETURNS TEXT
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
  SELECT CASE
    WHEN prefix <> '' THEN prefix || '_' || gen_random_uuid()::TEXT
    ELSE gen_random_uuid()::TEXT
  END;
$$;

COMMENT ON FUNCTION public.gen_id(TEXT) IS
  'Universal AOCS ID generator. Single overload handles both gen_id() and gen_id(prefix). '
  'M-05: No separate no-arg overload — avoids 42725 function ambiguity.';
