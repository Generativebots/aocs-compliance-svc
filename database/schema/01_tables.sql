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
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- H5: updated_at required for incremental sync (Palantir standard)
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- H5: updated_at required for incremental sync (Palantir standard)
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
    -- H6: explicit ON DELETE for FK (Palantir standard)
    superseded_by   TEXT        REFERENCES compliance.platform_signing_keys (key_id) ON DELETE SET NULL
                                    CONSTRAINT platform_signing_keys_superseded_by_fkey,
    rotated_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- H5: updated_at required for incremental sync
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
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


-- ── DBA Audit Fixes (applied 2026-09-04) ─────────────────────────────────────────────
-- M2: syst_tenants defaults (data_residency_region, last_config_changed_by) → folded
--     inline into aocs-system-svc/database/schema/01_tables.sql
-- H5: updated_at columns → folded inline into each compliance CREATE TABLE above
-- H6: platform_signing_keys superseded_by FK → folded inline into CREATE TABLE above
-- H6 (system): syst_departments.parent_id FK → folded inline into aocs-system-svc
-- RLS (compliance tables): moved to 06_rls.sql
-- NOTE: pg_stat_statements extension should be created by a superuser separately.
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- ── Ring 2 → Ring 3 Migrations ───────────────────────────────────────────────
-- Tables below were moved from ocx-core-svc Ring 2 to aocs-compliance-svc Ring 3.
-- They belong in the compliance schema because compliance-svc owns all violation,
-- obligation, exception, and risk data. The public.core_* names are retained for
-- backward FK compatibility during the transition period.

CREATE TABLE IF NOT EXISTS compliance.core_policy_violations (
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

CREATE TABLE IF NOT EXISTS compliance.core_regulatory_obligations (
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

CREATE TABLE IF NOT EXISTS compliance.core_policy_exceptions (
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

CREATE TABLE IF NOT EXISTS compliance.core_gra_risk_assessments (
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

-- ── compliance.compliance_cases ──────────────────────────────────────────────
-- Moved from extc_compliance_cases in ocx-extension-svc (2026-09-04).
-- This is a Ring 3 PAID feature (FeatureCompliance guard).
-- FKs to Ring 2 (agent_id, hitl_decision_id, enforcement_action_id) are TEXT-only
-- (no hard FK) — enforced at application layer. Cross-DB FK forbidden.
CREATE TABLE IF NOT EXISTS compliance.compliance_cases (
    case_id             TEXT        PRIMARY KEY DEFAULT public.gen_id(),
    tenant_id           TEXT        NOT NULL REFERENCES public.syst_tenants(tenant_id) ON DELETE CASCADE,
    -- Ring 2 TEXT references (no hard FK — cross-DB boundary)
    agent_id            TEXT,
    enforcement_action_id TEXT,
    hitl_decision_id    TEXT,
    policy_id           TEXT,
    platform_config_id  TEXT,
    assessment_id       TEXT,
    -- Case fields
    case_type           TEXT        NOT NULL DEFAULT 'COMPLIANCE'
                            CHECK (case_type = ANY (ARRAY['COMPLIANCE','DISPUTE','ESCALATION','AUDIT','GOVERNANCE','RISK','SECURITY','FRAUD'])),
    status              TEXT        NOT NULL DEFAULT 'OPEN'
                            CHECK (status = ANY (ARRAY['OPEN','INVESTIGATING','RESOLVED','CLOSED','ARCHIVED'])),
    severity            TEXT        NOT NULL DEFAULT 'MEDIUM'
                            CHECK (severity = ANY (ARRAY['LOW','MEDIUM','HIGH','CRITICAL'])),
    title               TEXT        NOT NULL,
    description         TEXT,
    evidence_ids        JSONB       NOT NULL DEFAULT '[]',
    remediations        JSONB       NOT NULL DEFAULT '[]',
    case_comments       JSONB       NOT NULL DEFAULT '[]',
    -- Assignment
    assigned_to         TEXT,
    assigned_at         TIMESTAMPTZ,
    required_votes      INTEGER     NOT NULL DEFAULT 1,
    -- Lifecycle
    sla_breach_at       TIMESTAMPTZ,
    closed_at           TIMESTAMPTZ,
    closed_by           TEXT,
    decision            TEXT,
    retired_at          TIMESTAMPTZ,
    -- Deduplication
    dedup_key           TEXT,
    -- Additional refs
    gra_case_id         TEXT,
    dispute_id          TEXT,
    violation_id        TEXT,
    violated_policy_id  TEXT,
    final_reputation_score NUMERIC,
    jurisdiction        TEXT,
    is_internal         BOOLEAN     NOT NULL DEFAULT FALSE,
    duration            INTERVAL,
    -- Audit
    metadata            JSONB       NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE compliance.compliance_cases IS
    'Ring 3 (FeatureCompliance): Compliance cases moved from ocx-extension-svc/extc_compliance_cases. '
    'Requires FeatureCompliance in tenant JWT. All Ring 2 FKs are TEXT-only (cross-DB boundary).';

CREATE UNIQUE INDEX IF NOT EXISTS idx_compliance_cases_dedup
    ON compliance.compliance_cases (dedup_key) WHERE dedup_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_compliance_cases_tenant_status
    ON compliance.compliance_cases (tenant_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_compliance_cases_type
    ON compliance.compliance_cases (tenant_id, case_type, status);
CREATE INDEX IF NOT EXISTS idx_compliance_cases_agent_id
    ON compliance.compliance_cases (agent_id);
CREATE INDEX IF NOT EXISTS idx_compliance_cases_severity
    ON compliance.compliance_cases (tenant_id, severity, created_at DESC) WHERE severity IS NOT NULL;
