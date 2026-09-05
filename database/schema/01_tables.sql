-- =============================================================================
-- 01_tables.sql — aocs-compliance-svc
-- All tables land in the PUBLIC schema (Architecture Decision 2026-09-05 Decision #2).
-- compliance.* schema prefix REMOVED — tables prefixed compl_* to avoid Ring 2 collisions.
-- FK to Ring 0: public.syst_tenants (same Supabase DB)
-- FK to Ring 2: TEXT-only (no hard FK — cross-ring boundary)
-- Run AFTER: Ring 0 (aocs-system-svc) migrations
-- =============================================================================


-- ── compl_records ─────────────────────────────────────────
-- Primary compliance case tracking table.
-- Links to Ring 1 via TEXT IDs (agent_id, hitl_decision_id, policy_id).
-- These are TEXT-only — no hard FK to Ring 1 tables (different schema boundary).
CREATE TABLE IF NOT EXISTS compl_records (
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

-- ── compl_records ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS compl_obligations (
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

-- ── compl_evidence ─────────────────────────────────────────────────
-- Evidence vault: ZKP proofs, DLP findings, audit screenshots, SOC2 artifacts.
CREATE TABLE IF NOT EXISTS compl_evidence (
    evidence_id         TEXT        PRIMARY KEY DEFAULT public.gen_id(),
    tenant_id           TEXT        NOT NULL
                            REFERENCES public.syst_tenants(tenant_id) ON DELETE CASCADE,
    case_id             TEXT        REFERENCES compl_records(case_id) ON DELETE SET NULL,
    control_id          TEXT        REFERENCES compl_records(control_id) ON DELETE SET NULL,
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
    prev_evidence_id    TEXT        REFERENCES compl_evidence(evidence_id),
    collected_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    collected_by        TEXT        NOT NULL DEFAULT 'system',
    expires_at          TIMESTAMPTZ,
    framework           TEXT,       -- SOC2, EU_AI_ACT, etc.
    control_refs        TEXT[]      NOT NULL DEFAULT '{}',
    metadata            JSONB       NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── compl_evidence ────────────────────────────────────────────────
-- Zero-Knowledge Proof records. Cryptographic proof that a governance action occurred.
CREATE TABLE IF NOT EXISTS compl_evidence_anchors (
    proof_id            TEXT        PRIMARY KEY DEFAULT public.gen_id(),
    tenant_id           TEXT        NOT NULL
                            REFERENCES public.syst_tenants(tenant_id) ON DELETE CASCADE,
    evidence_id         TEXT        REFERENCES compl_evidence(evidence_id),
    case_id             TEXT        REFERENCES compl_records(case_id),
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

-- ── compl_dlp_integrations ─────────────────────────────────────────────
-- Data Loss Prevention scan results.
CREATE TABLE IF NOT EXISTS compl_dlp_integrations (
    finding_id          TEXT        PRIMARY KEY DEFAULT public.gen_id(),
    tenant_id           TEXT        NOT NULL
                            REFERENCES public.syst_tenants(tenant_id) ON DELETE CASCADE,
    case_id             TEXT        REFERENCES compl_records(case_id) ON DELETE SET NULL,
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

-- ── compl_reports ──────────────────────────────────────
-- Daily generated compliance reports (SOC2, EU AI Act, GRC summaries).
CREATE TABLE IF NOT EXISTS compl_reports (
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

-- ── compl_case_comments ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS compl_case_comments (
    comment_id      TEXT        PRIMARY KEY DEFAULT public.gen_id(),
    case_id         TEXT        NOT NULL REFERENCES compl_records(case_id) ON DELETE CASCADE,
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

CREATE TABLE IF NOT EXISTS compl_signing_keys (
    key_id      TEXT        PRIMARY KEY DEFAULT public.gen_id('sk'),
    key_type    TEXT        NOT NULL DEFAULT 'ed25519',
    public_key  TEXT        NOT NULL,
    private_key TEXT        NOT NULL,
    is_active   BOOLEAN     NOT NULL DEFAULT TRUE,
    -- H6: explicit ON DELETE for FK (Palantir standard)
    superseded_by   TEXT        REFERENCES compl_signing_keys (key_id) ON DELETE SET NULL
                                    CONSTRAINT platform_signing_keys_superseded_by_fkey,
    rotated_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- H5: updated_at required for incremental sync
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uidx_platform_signing_keys_active
    ON compl_signing_keys (key_type)
    WHERE is_active = TRUE;

-- ── compl_anomaly ───────────────────────────────────────
-- S3 Fix (Palantir Gap): Cross-pod sybil collusion tracking.
-- CollusionStore.RecordAgentOnIP() upserts here for cross-pod shared state.
CREATE TABLE IF NOT EXISTS compl_anomaly (
    tenant_id   TEXT        NOT NULL REFERENCES public.syst_tenants(tenant_id) ON DELETE CASCADE,
    ip_address  TEXT        NOT NULL,
    agent_ids   JSONB       NOT NULL DEFAULT '[]',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, ip_address)
);

CREATE INDEX IF NOT EXISTS idx_collusion_ip_tenant
    ON compl_anomaly (tenant_id);


-- ── DBA Audit Fixes (applied 2026-09-04) ─────────────────────────────────────────────
-- M2: syst_tenants defaults (data_residency_region, last_config_changed_by) → folded
--     inline into aocs-system-svc/database/schema/01_tables.sql
-- H5: updated_at columns → folded inline into each compliance CREATE TABLE above
-- H6: platform_signing_keys superseded_by FK → folded inline into CREATE TABLE above
-- H6 (system): syst_departments.parent_id FK → folded inline into aocs-system-svc
-- RLS (compliance tables): moved to 06_rls.sql
-- NOTE: pg_stat_statements extension should be created by a superuser separately.
-- NOTE: pg_stat_statements extension should be created by a superuser separately.

-- ── Ring 2 → Ring 3 Migrations ───────────────────────────────────────────────
-- Tables below were moved from ocx-core-svc Ring 2 to aocs-compliance-svc Ring 3.
-- They belong in the compliance schema because compliance-svc owns all violation,
-- obligation, exception, and risk data. The public.core_* names are retained for
-- backward FK compatibility during the transition period.

CREATE TABLE IF NOT EXISTS compl_policy_violations (
    violation_id        TEXT PRIMARY KEY DEFAULT gen_id(),
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

CREATE TABLE IF NOT EXISTS compl_regulatory (
    obligation_id       TEXT PRIMARY KEY DEFAULT gen_id(),
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

CREATE TABLE IF NOT EXISTS compl_policy_exceptions (
    exception_id        TEXT PRIMARY KEY DEFAULT gen_id(),
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

CREATE TABLE IF NOT EXISTS compl_risk_assessments (
    gra_risk_assessment_id TEXT PRIMARY KEY DEFAULT gen_id(),
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

-- ── compl_cases ──────────────────────────────────────────────
-- Moved from extc_compliance_cases in ocx-extension-svc (2026-09-04).
-- This is a Ring 3 PAID feature (FeatureCompliance guard).
-- FKs to Ring 2 (agent_id, hitl_decision_id, enforcement_action_id) are TEXT-only
-- (no hard FK) — enforced at application layer. Cross-DB FK forbidden.
CREATE TABLE IF NOT EXISTS compl_cases (
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

COMMENT ON TABLE compl_cases IS
    'Ring 3 (FeatureCompliance): Compliance cases moved from ocx-extension-svc/extc_compliance_cases. '
    'Requires FeatureCompliance in tenant JWT. All Ring 2 FKs are TEXT-only (cross-DB boundary).';

CREATE UNIQUE INDEX IF NOT EXISTS idx_compliance_cases_dedup
    ON compl_cases (dedup_key) WHERE dedup_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_compliance_cases_tenant_status
    ON compl_cases (tenant_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_compliance_cases_type
    ON compl_cases (tenant_id, case_type, status);
CREATE INDEX IF NOT EXISTS idx_compliance_cases_agent_id
    ON compl_cases (agent_id);
CREATE INDEX IF NOT EXISTS idx_compliance_cases_severity
    ON compl_cases (tenant_id, severity, created_at DESC) WHERE severity IS NOT NULL;

-- ============================================================================
-- § CROSS-RING PROPAGATION — Layer 2 & Layer 3 Infrastructure (Ring 3)
-- ============================================================================

-- ── compl_tenant_baselines — seeded by TENANT_PROVISIONED ──────────────
-- Every tenant gets a compliance baseline row on provisioning.
-- Ring 0 TENANT_PROVISIONED → compliance UPSERT here.
-- Conflict key: (tenant_id) — idempotent on redelivery.
CREATE TABLE IF NOT EXISTS compl_tenant_baselines (
    baseline_id     TEXT        PRIMARY KEY DEFAULT gen_id(),
    tenant_id       TEXT        NOT NULL,
    jurisdiction    TEXT,                               -- from syst_tenants.jurisdiction
    frameworks      JSONB       NOT NULL DEFAULT '[]',  -- regulatory frameworks active
    enforcement_mode TEXT       NOT NULL DEFAULT 'OBSERVE'
                        CHECK (enforcement_mode IN ('OBSERVE','ENFORCE','AUDIT')),
    seeded_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_compliance_baseline_tenant UNIQUE (tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_compliance_baseline_tenant
    ON compl_tenant_baselines (tenant_id);

-- ── compl_evidence_vault — seeded by AGENT_REGISTERED ────────────
-- Per-agent evidence registry seeded when a new agent is registered in Ring 2.
-- Ring 2 AGENT_REGISTERED → compliance UPSERT here.
-- All evidence items (ZKP proofs, DLP scans) reference this anchor row.
CREATE TABLE IF NOT EXISTS compl_evidence_vault (
    vault_id        TEXT        PRIMARY KEY DEFAULT gen_id(),
    tenant_id       TEXT        NOT NULL,
    agent_id        TEXT        NOT NULL,               -- soft ref: Ring 2 core_agents.agent_id
    agent_name      TEXT,
    vault_status    TEXT        NOT NULL DEFAULT 'ACTIVE'
                        CHECK (vault_status IN ('ACTIVE','FROZEN','RETIRED')),
    evidence_count  INTEGER     NOT NULL DEFAULT 0,
    last_evidence_at TIMESTAMPTZ,
    seeded_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_vault_agent_tenant UNIQUE (agent_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_vault_tenant
    ON compl_evidence_vault (tenant_id, vault_status);
CREATE INDEX IF NOT EXISTS idx_vault_agent
    ON compl_evidence_vault (agent_id);

-- ── compl_idempotency_log — Layer 2 consumer guard ─────────────────────
CREATE TABLE IF NOT EXISTS compl_idempotency_log (
    message_id      TEXT        PRIMARY KEY,
    topic           TEXT        NOT NULL,
    tenant_id       TEXT,
    agent_id        TEXT,
    handler         TEXT        NOT NULL,
    result          TEXT        NOT NULL DEFAULT 'OK',
    processed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE compl_tenant_baselines IS
    'Ring 3 compliance baseline seeded by TENANT_PROVISIONED event. '
    'UPSERT (tenant_id) ensures idempotency on Pub/Sub redelivery.';
COMMENT ON TABLE compl_evidence_vault IS
    'Ring 3 evidence vault anchor seeded by AGENT_REGISTERED event. '
    'All ZKP proofs and DLP scan results reference this row.';
