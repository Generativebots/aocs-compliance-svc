-- =============================================================================
-- 01_tables.sql — aocs-compliance-svc
-- compliance schema — compliance cases, evidence, ZKP, DLP, reports
-- =============================================================================
-- Run AFTER: 00_compliance_schema.sql
-- Schema: compliance (all tables prefixed with compliance schema)
-- FK to Ring 0 tables: public.aocs_tenants (cross-schema FK, same Supabase DB)
-- FK to Ring 1 tables: TEXT-only (cross-schema, DEFERRABLE, app-level enforced)
-- =============================================================================

-- ── compliance.aocs_compliance_cases ─────────────────────────────────────────
-- Primary compliance case tracking table.
-- Links to Ring 1 via TEXT IDs (agent_id, hitl_decision_id, policy_id).
-- These are TEXT-only — no hard FK to Ring 1 tables (different schema boundary).
CREATE TABLE IF NOT EXISTS compliance.aocs_compliance_cases (
    case_id             TEXT        PRIMARY KEY DEFAULT public.gen_id(),
    tenant_id           TEXT        NOT NULL
                            REFERENCES public.aocs_tenants(tenant_id) ON DELETE CASCADE,
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

-- ── compliance.aocs_compliance_controls ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS compliance.aocs_compliance_controls (
    control_id          TEXT        PRIMARY KEY DEFAULT public.gen_id(),
    tenant_id           TEXT        NOT NULL
                            REFERENCES public.aocs_tenants(tenant_id) ON DELETE CASCADE,
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

-- ── compliance.aocs_evidence ─────────────────────────────────────────────────
-- Evidence vault: ZKP proofs, DLP findings, audit screenshots, SOC2 artifacts.
CREATE TABLE IF NOT EXISTS compliance.aocs_evidence (
    evidence_id         TEXT        PRIMARY KEY DEFAULT public.gen_id(),
    tenant_id           TEXT        NOT NULL
                            REFERENCES public.aocs_tenants(tenant_id) ON DELETE CASCADE,
    case_id             TEXT        REFERENCES compliance.aocs_compliance_cases(case_id) ON DELETE SET NULL,
    control_id          TEXT        REFERENCES compliance.aocs_compliance_controls(control_id) ON DELETE SET NULL,
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
    prev_evidence_id    TEXT        REFERENCES compliance.aocs_evidence(evidence_id),
    collected_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    collected_by        TEXT        NOT NULL DEFAULT 'system',
    expires_at          TIMESTAMPTZ,
    framework           TEXT,       -- SOC2, EU_AI_ACT, etc.
    control_refs        TEXT[]      NOT NULL DEFAULT '{}',
    metadata            JSONB       NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── compliance.aocs_zkp_proofs ────────────────────────────────────────────────
-- Zero-Knowledge Proof records. Cryptographic proof that a governance action occurred.
CREATE TABLE IF NOT EXISTS compliance.aocs_zkp_proofs (
    proof_id            TEXT        PRIMARY KEY DEFAULT public.gen_id(),
    tenant_id           TEXT        NOT NULL
                            REFERENCES public.aocs_tenants(tenant_id) ON DELETE CASCADE,
    evidence_id         TEXT        REFERENCES compliance.aocs_evidence(evidence_id),
    case_id             TEXT        REFERENCES compliance.aocs_compliance_cases(case_id),
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

-- ── compliance.aocs_dlp_findings ─────────────────────────────────────────────
-- Data Loss Prevention scan results.
CREATE TABLE IF NOT EXISTS compliance.aocs_dlp_findings (
    finding_id          TEXT        PRIMARY KEY DEFAULT public.gen_id(),
    tenant_id           TEXT        NOT NULL
                            REFERENCES public.aocs_tenants(tenant_id) ON DELETE CASCADE,
    case_id             TEXT        REFERENCES compliance.aocs_compliance_cases(case_id) ON DELETE SET NULL,
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
                            REFERENCES public.aocs_tenants(tenant_id) ON DELETE CASCADE,
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

-- ── compliance.aocs_case_comments ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS compliance.aocs_case_comments (
    comment_id      TEXT        PRIMARY KEY DEFAULT public.gen_id(),
    case_id         TEXT        NOT NULL REFERENCES compliance.aocs_compliance_cases(case_id) ON DELETE CASCADE,
    tenant_id       TEXT        NOT NULL REFERENCES public.aocs_tenants(tenant_id) ON DELETE CASCADE,
    author_id       TEXT        NOT NULL,
    content         TEXT        NOT NULL,
    is_internal     BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── compliance.aocs_sybil_risk_assessments ───────────────────────────────────
-- P-16: Daily sybil detection results per tenant.
CREATE TABLE IF NOT EXISTS compliance.aocs_sybil_risk_assessments (
    assessment_id   TEXT        PRIMARY KEY DEFAULT public.gen_id(),
    tenant_id       TEXT        NOT NULL REFERENCES public.aocs_tenants(tenant_id) ON DELETE CASCADE,
    agent_id        TEXT,
    risk_score      DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    risk_level      TEXT        NOT NULL DEFAULT 'LOW' CHECK (risk_level IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    signals         JSONB       NOT NULL DEFAULT '{}',
    assessed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    worker_run_at   TIMESTAMPTZ
);

SELECT 'compliance tables created' AS status;
