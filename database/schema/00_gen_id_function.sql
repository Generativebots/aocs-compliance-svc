-- =============================================================================
-- 00_gen_id_function.sql — aocs-compliance-svc
-- =============================================================================
-- This is a COPY of the canonical gen_id() function.
-- It is idempotent — safe to run even if gen_id() already exists in this DB.
-- The compliance schema uses the SAME Supabase project as Ring 0 and Ring 1.
-- gen_id() lives in public schema, compliance tables live in compliance schema.
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE OR REPLACE FUNCTION public.gen_id(prefix TEXT DEFAULT '')
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    raw_bytes  BYTEA := gen_random_bytes(9);
    b64        TEXT;
    clean      TEXT;
BEGIN
    b64   := encode(raw_bytes, 'base64');
    clean := replace(replace(replace(b64, '+', 'x'), '/', 'y'), '=', '');
    IF prefix <> '' THEN
        RETURN prefix || '_' || clean;
    END IF;
    RETURN clean;
END;
$$;

COMMENT ON FUNCTION public.gen_id IS
    'Generates a URL-safe, non-sequential, opaque identifier. '
    'Shared across all AOCS services in the same Supabase project. '
    'Must exist in public schema before any compliance schema tables are created.';
