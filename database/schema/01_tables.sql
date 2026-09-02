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
--     are visible: compliance.* for own tables, public.syst_tenants for Ring 0 FKs
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
        'Ring 3 (PAID) — aocs-compliance-svc. ZKP, DLP, compliance cases, evidence vault. '
        'Runtime deps: Ring 0 (aocs-system for tenant data) + Ring 1 (aocs-core for agent data).';
EXCEPTION WHEN duplicate_object THEN
    RAISE NOTICE 'Role svc_compliance already exists — skipping';
END $$;

GRANT USAGE ON SCHEMA compliance TO svc_compliance;

-- Set default search_path for compliance role
ALTER ROLE svc_compliance SET search_path TO compliance, public;

SELECT 'compliance schema created' AS status;

-- ── Ring 3 Compliance Tables ────────────────────────────────────
-- =============================================================================
-- 01_tables.sql — aocs-compliance-svc
-- compliance schema — compliance cases, evidence, ZKP, DLP, reports
-- =============================================================================
-- Run AFTER: 00_compliance_schema.sql
-- Schema: compliance (all tables prefixed with compliance schema)
-- FK to Ring 0 tables: public.syst_tenants (cross-schema FK, same Supabase DB)
-- FK to Ring 1 tables: TEXT-only (cross-schema, DEFERRABLE, app-level enforced)
-- =============================================================================

-- ── compliance.core_compliance ─────────────────────────────────────────
-- Primary compliance case tracking table.
-- Links to Ring 1 via TEXT IDs (agent_id, hitl_decision_id, policy_id).
-- These are TEXT-only — no hard FK to Ring 1 tables (different schema boundary).
CREATE TABLE IF NOT EXISTS compliance.core_compliance (
    case_id             TEXT        PRIMARY KEY DEFAULT public.gen_id(),
    tenant_id           TEXT        NOT NULL
                            REFERENCES public.syst_tenants(tenant_id) ON DELETE CASCADE,
    -- Ring 1 references — TEXT only, enforced at app layer
    agent_id            TEXT,
    hitl_decision_id    TEXT,
    policy_id           TEXT,
    enforcement_action_id TEXT,
    -- Case metadata
    case_type           TEXT        NOT NULL DEFAULT 'VIOLATION'
                            CHECK (case_type IN ('VIOLATION','AUDIT','DLP','ZKP','REGULATORY','SIEM','MANUAL')),
    severity            TEXT        NOT NULL DEFAULT 'MEDIUM'
                            CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    status              TEXT        NOT NULL DEFAULT 'OPEN'
                            CHECK (status IN ('OPEN','IN_REVIEW','ESCALATED','RESOLVED','CLOSED','DISPUTED')),
    title               TEXT        NOT NULL,
    description         TEXT,
    assigned_to         TEXT,
    department          TEXT,
    region              TEXT,
    jurisdiction        TEXT,
    regulatory_framework TEXT,
    risk_score          DOUBLE PRECISION CHECK (risk_score BETWEEN 0.0 AND 1.0),
    resolution_notes    TEXT,
    resolved_at         TIMESTAMPTZ,
    resolved_by         TEXT,
    due_at              TIMESTAMPTZ,
    escalated_at        TIMESTAMPTZ,
    escalated_by        TEXT,
    metadata            JSONB       NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── compliance.core_compliance ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS compliance.core_compliance_obligations (
    control_id          TEXT        PRIMARY KEY DEFAULT public.gen_id(),
    tenant_id           TEXT        NOT NULL
                            REFERENCES public.syst_tenants(tenant_id) ON DELETE CASCADE,
    framework           TEXT        NOT NULL,  -- SOC2, EU_AI_ACT, ISO27001, GDPR, HIPAA
    control_ref         TEXT        NOT NULL,
    name                TEXT        NOT NULL,
    description         TEXT,
    status              TEXT        NOT NULL DEFAULT 'NOT_STARTED'
                            CHECK (status IN ('NOT_STARTED','IN_PROGRESS','COMPLIANT','NON_COMPLIANT','WAIVED')),
    owner               TEXT,
    evidence_count      INTEGER     NOT NULL DEFAULT 0,
    last_assessed_at    TIMESTAMPTZ,
    next_review_at      TIMESTAMPTZ,
    metadata            JSONB       NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, framework, control_ref)
);

-- ── compliance.core_evidence ─────────────────────────────────────────────────
-- Evidence vault: ZKP proofs, DLP findings, audit screenshots, SOC2 artifacts.
CREATE TABLE IF NOT EXISTS compliance.core_evidence (
    evidence_id         TEXT        PRIMARY KEY DEFAULT public.gen_id(),
    tenant_id           TEXT        NOT NULL
                            REFERENCES public.syst_tenants(tenant_id) ON DELETE CASCADE,
    case_id             TEXT        REFERENCES compliance.core_compliance(case_id) ON DELETE SET NULL,
    control_id          TEXT        REFERENCES compliance.core_compliance(control_id) ON DELETE SET NULL,
    -- Ring 1 TEXT references
    agent_id            TEXT,
    execution_id        TEXT,
    -- Evidence content
    evidence_type       TEXT        NOT NULL DEFAULT 'DOCUMENT'
                            CHECK (evidence_type IN ('DOCUMENT','SCREENSHOT','ZKP_PROOF','DLP_SCAN','AUDIT_LOG','API_RESPONSE','SOC2_ARTIFACT','MANUAL')),
    title               TEXT        NOT NULL,
    description         TEXT,
    storage_url         TEXT,
    content_hash        TEXT,       -- SHA-256 of the evidence payload
    signature           TEXT,       -- Ed25519 signature (persisted — not ephemeral)
    signing_key_id      TEXT,       -- References public.platform_signing_keys.key_id
    chain_hash          TEXT,       -- Merkle chain hash (links to previous entry)
    prev_evidence_id    TEXT        REFERENCES compliance.core_evidence(evidence_id),
    collected_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    collected_by        TEXT        NOT NULL DEFAULT 'system',
    expires_at          TIMESTAMPTZ,
    framework           TEXT,       -- SOC2, EU_AI_ACT, etc.
    control_refs        TEXT[]      NOT NULL DEFAULT '{}',
    metadata            JSONB       NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── compliance.core_evidence ────────────────────────────────────────────────
-- Zero-Knowledge Proof records. Cryptographic proof that a governance action occurred.
CREATE TABLE IF NOT EXISTS compliance.core_evidence_anchors (
    proof_id            TEXT        PRIMARY KEY DEFAULT public.gen_id(),
    tenant_id           TEXT        NOT NULL
                            REFERENCES public.syst_tenants(tenant_id) ON DELETE CASCADE,
    evidence_id         TEXT        REFERENCES compliance.core_evidence(evidence_id),
    case_id             TEXT        REFERENCES compliance.core_compliance(case_id),
    -- Ring 1 TEXT references
    agent_id            TEXT,
    execution_id        TEXT,
    decision_id         TEXT,
    -- ZKP fields
    circuit_type        TEXT        NOT NULL DEFAULT 'groth16',
    proof_data          JSONB       NOT NULL DEFAULT '{}',
    public_inputs       JSONB       NOT NULL DEFAULT '{}',
    verifier_key        TEXT,
    verification_status TEXT        NOT NULL DEFAULT 'PENDING'
                            CHECK (verification_status IN ('PENDING','VERIFIED','FAILED','EXPIRED')),
    verified_at         TIMESTAMPTZ,
    expires_at          TIMESTAMPTZ,
    batch_id            TEXT,
    metadata            JSONB       NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── compliance.shar_dlp_integrations ─────────────────────────────────────────────
-- Data Loss Prevention scan results.
CREATE TABLE IF NOT EXISTS compliance.shar_dlp_integrations (
    finding_id          TEXT        PRIMARY KEY DEFAULT public.gen_id(),
    tenant_id           TEXT        NOT NULL
                            REFERENCES public.syst_tenants(tenant_id) ON DELETE CASCADE,
    case_id             TEXT        REFERENCES compliance.core_compliance(case_id) ON DELETE SET NULL,
    -- Ring 1 TEXT references
    agent_id            TEXT,
    execution_id        TEXT,
    -- DLP fields
    scan_type           TEXT        NOT NULL DEFAULT 'CONTENT'
                            CHECK (scan_type IN ('CONTENT','METADATA','NETWORK','FILE','EMAIL')),
    severity            TEXT        NOT NULL DEFAULT 'MEDIUM'
                            CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    data_type           TEXT,       -- PII, PHI, PCI, IP, CONFIDENTIAL
    match_count         INTEGER     NOT NULL DEFAULT 0,
    masked_snippet      TEXT,       -- Redacted — never stores actual PII
    action_taken        TEXT,       -- BLOCK, QUARANTINE, ALERT, LOG
    status              TEXT        NOT NULL DEFAULT 'OPEN'
                            CHECK (status IN ('OPEN','ACKNOWLEDGED','RESOLVED','FALSE_POSITIVE')),
    metadata            JSONB       NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── compliance.nexus_compliance_reports ──────────────────────────────────────
-- Daily generated compliance reports (SOC2, EU AI Act, GRC summaries).
CREATE TABLE IF NOT EXISTS compliance.nexus_compliance_reports (
    report_id           TEXT        PRIMARY KEY DEFAULT public.gen_id(),
    tenant_id           TEXT        NOT NULL
                            REFERENCES public.syst_tenants(tenant_id) ON DELETE CASCADE,
    report_type         TEXT        NOT NULL
                            CHECK (report_type IN ('SOC2','EU_AI_ACT','ISO27001','GDPR','HIPAA','GRC_SUMMARY','DAILY','WEEKLY','MONTHLY')),
    period_start        TIMESTAMPTZ NOT NULL,
    period_end          TIMESTAMPTZ NOT NULL,
    status              TEXT        NOT NULL DEFAULT 'DRAFT'
                            CHECK (status IN ('DRAFT','GENERATED','DELIVERED','ARCHIVED')),
    report_url          TEXT,
    summary             JSONB       NOT NULL DEFAULT '{}',
    case_count          INTEGER     NOT NULL DEFAULT 0,
    evidence_count      INTEGER     NOT NULL DEFAULT 0,
    control_count       INTEGER     NOT NULL DEFAULT 0,
    compliance_score    DOUBLE PRECISION,
    generated_at        TIMESTAMPTZ,
    generated_by        TEXT        NOT NULL DEFAULT 'system',
    metadata            JSONB       NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── compliance.core_compliance_comments ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS compliance.core_compliance_comments (
    comment_id      TEXT        PRIMARY KEY DEFAULT public.gen_id(),
    case_id         TEXT        NOT NULL REFERENCES compliance.core_compliance(case_id) ON DELETE CASCADE,
    tenant_id       TEXT        NOT NULL REFERENCES public.syst_tenants(tenant_id) ON DELETE CASCADE,
    author_id       TEXT        NOT NULL,
    content         TEXT        NOT NULL,
    is_internal     BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── compliance.shar_trust ───────────────────────────────────
-- P-16: Daily sybil detection results per tenant.
-- shar_trust removed: merged into core_trust_events with cross_org=true flag.
-- See ocx-shared-go/infra/database/models_tables.go TblSharTrust.

CREATE TABLE IF NOT EXISTS compliance.platform_signing_keys (
    key_id      TEXT        PRIMARY KEY DEFAULT public.gen_id('sk'),
    key_type    TEXT        NOT NULL DEFAULT 'ed25519',
    public_key  TEXT        NOT NULL,
    private_key TEXT        NOT NULL,
    is_active   BOOLEAN     NOT NULL DEFAULT TRUE,
    rotated_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uidx_platform_signing_keys_active
    ON compliance.platform_signing_keys (key_type)
    WHERE is_active = TRUE;

-- ── compliance.core_anomaly_detection ───────────────────────────────────────
-- S3 Fix (Palantir Gap): Cross-pod sybil collusion tracking.
-- CollusionStore.RecordAgentOnIP() upserts here for cross-pod shared state.
CREATE TABLE IF NOT EXISTS compliance.core_anomaly_detection (
    tenant_id   TEXT        NOT NULL REFERENCES public.syst_tenants(tenant_id) ON DELETE CASCADE,
    ip_address  TEXT        NOT NULL,
    agent_ids   JSONB       NOT NULL DEFAULT '[]',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, ip_address)
);

CREATE INDEX IF NOT EXISTS idx_collusion_ip_tenant
    ON compliance.core_anomaly_detection (tenant_id);

-- ── DBA Audit Fixes (2026-09-02) ──────────────────────────────────────────────
-- M2: Add default values to prevent null compliance fields
ALTER TABLE public.syst_tenants
    ALTER COLUMN data_residency_region SET DEFAULT 'us-central1',
    ALTER COLUMN last_config_changed_by SET DEFAULT 'SYSTEM';

-- H5: Add updated_at to compliance tables missing it (required for incremental sync + ETL)
-- Palantir standard: every mutable table must have an updated_at column with auto-trigger.
ALTER TABLE compliance.core_compliance_comments    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE compliance.shar_dlp_integrations     ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE compliance.shar_trust ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE compliance.core_evidence       ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE compliance.platform_signing_keys ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Auto-update trigger function (shared within compliance schema)
CREATE OR REPLACE FUNCTION compliance.set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE OR REPLACE TRIGGER trg_case_comments_updated_at
    BEFORE UPDATE ON compliance.core_compliance_comments
    FOR EACH ROW EXECUTE FUNCTION compliance.set_updated_at();

CREATE OR REPLACE TRIGGER trg_dlp_findings_updated_at
    BEFORE UPDATE ON compliance.shar_dlp_integrations
    FOR EACH ROW EXECUTE FUNCTION compliance.set_updated_at();

CREATE OR REPLACE TRIGGER trg_sybil_assessments_updated_at
    BEFORE UPDATE ON compliance.shar_trust
    FOR EACH ROW EXECUTE FUNCTION compliance.set_updated_at();

CREATE OR REPLACE TRIGGER trg_zkp_proofs_updated_at
    BEFORE UPDATE ON compliance.core_evidence
    FOR EACH ROW EXECUTE FUNCTION compliance.set_updated_at();

CREATE OR REPLACE TRIGGER trg_signing_keys_updated_at
    BEFORE UPDATE ON compliance.platform_signing_keys
    FOR EACH ROW EXECUTE FUNCTION compliance.set_updated_at();

-- H6: Add explicit ON DELETE to FK columns missing it
-- Palantir standard: every FK must declare ON DELETE behaviour explicitly.
ALTER TABLE compliance.platform_signing_keys
    DROP CONSTRAINT IF EXISTS platform_signing_keys_superseded_by_fkey,
    ADD CONSTRAINT platform_signing_keys_superseded_by_fkey
        FOREIGN KEY (superseded_by)
        REFERENCES compliance.platform_signing_keys (key_id)
        ON DELETE SET NULL;

-- H6 (system): syst_departments.parent_id
ALTER TABLE public.syst_departments
    DROP CONSTRAINT IF EXISTS ocx_departments_parent_id_fkey,
    ADD CONSTRAINT ocx_platform_departments_parent_id_fkey
        FOREIGN KEY (parent_id)
        REFERENCES public.syst_departments (department_id)
        ON DELETE SET NULL;

-- syst_audit: NOT NULL on tenant_id (data isolation)
ALTER TABLE public.syst_audit ALTER COLUMN tenant_id SET NOT NULL;

-- Compound index for dashboard query pattern (tenant_id, created_at DESC)
CREATE INDEX IF NOT EXISTS idx_ocx_audit_log_tenant_time
    ON public.syst_audit (tenant_id, created_at DESC);

-- syst_tenants + syst_tenants indexes
CREATE INDEX IF NOT EXISTS idx_notification_rules_tenant ON public.syst_tenants (tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_config_tenant      ON public.syst_tenants (tenant_id);
CREATE INDEX IF NOT EXISTS idx_platform_depts_parent     ON public.syst_departments (parent_id);

-- M5: pg_stat_statements for slow query identification (Google/Palantir monitoring standard)
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- RLS on new security-critical tables
ALTER TABLE compliance.core_anomaly_detection ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.platform_signing_keys    ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.syst_tenants      ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS signing_keys_superadmin_only ON compliance.platform_signing_keys
    FOR ALL TO authenticated
    USING ((current_setting('request.jwt.claims', true)::jsonb ->> 'is_superadmin')::boolean = true);

CREATE POLICY IF NOT EXISTS collusion_ip_service_role_only ON compliance.core_anomaly_detection
    FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY IF NOT EXISTS notification_rules_tenant ON public.syst_tenants
    FOR ALL TO authenticated
    USING (tenant_id = (current_setting('request.jwt.claims', true)::jsonb ->> 'tenant_id'));

-- ── Ring 2 → Ring 3 Migrations ───────────────────────────────────────────────
-- Tables below were moved from ocx-core-svc Ring 2 to aocs-compliance-svc Ring 3.
-- They belong in the compliance schema because compliance-svc owns all violation,
-- obligation, exception, and risk data. The public.core_* names are retained for
-- backward FK compatibility during the transition period.

CREATE TABLE IF NOT EXISTS core_policy_violations (
    violation_id        TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id           TEXT NOT NULL REFERENCES syst_tenants(tenant_id) ON DELETE CASCADE,
    policy_id           TEXT NOT NULL,
    agent_id            TEXT,
    execution_id        TEXT,
    violation_type      TEXT NOT NULL,
    severity            TEXT NOT NULL CHECK (severity = ANY (ARRAY['LOW','MEDIUM','HIGH','CRITICAL'])),
    description         TEXT,
    evidence            JSONB DEFAULT '{}',
    remediation         TEXT,
    status              TEXT NOT NULL DEFAULT 'OPEN' CHECK (status = ANY (ARRAY['OPEN','ACKNOWLEDGED','REMEDIATED','WAIVED','CLOSED'])),
    detected_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS core_regulatory_obligations (
    obligation_id       TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id           TEXT NOT NULL REFERENCES syst_tenants(tenant_id) ON DELETE CASCADE,
    framework           TEXT NOT NULL,
    control_id          TEXT NOT NULL,
    title               TEXT NOT NULL,
    description         TEXT,
    obligation_type     TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'PENDING' CHECK (status = ANY (ARRAY['PENDING','IN_PROGRESS','COMPLIANT','NON_COMPLIANT','WAIVED'])),
    due_date            TIMESTAMPTZ,
    owner               TEXT,
    evidence_refs       JSONB DEFAULT '[]',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS core_policy_exceptions (
    exception_id        TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id           TEXT NOT NULL REFERENCES syst_tenants(tenant_id) ON DELETE CASCADE,
    policy_id           TEXT NOT NULL,
    agent_id            TEXT,
    exception_type      TEXT NOT NULL,
    justification       TEXT NOT NULL,
    approved_by         TEXT,
    expires_at          TIMESTAMPTZ,
    status              TEXT NOT NULL DEFAULT 'PENDING' CHECK (status = ANY (ARRAY['PENDING','APPROVED','REJECTED','EXPIRED'])),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS core_gra_risk_assessments (
    gra_risk_assessment_id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id           TEXT NOT NULL REFERENCES syst_tenants(tenant_id) ON DELETE CASCADE,
    framework_id        TEXT,
    risk_level          TEXT NOT NULL CHECK (risk_level = ANY (ARRAY['LOW','MEDIUM','HIGH','CRITICAL'])),
    subject_type        TEXT NOT NULL,
    subject_id          TEXT NOT NULL,
    assessment_date     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    score               NUMERIC(5,2),
    findings            JSONB DEFAULT '{}',
    reviewer            TEXT,
    status              TEXT NOT NULL DEFAULT 'DRAFT' CHECK (status = ANY (ARRAY['DRAFT','UNDER_REVIEW','APPROVED','CLOSED'])),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
