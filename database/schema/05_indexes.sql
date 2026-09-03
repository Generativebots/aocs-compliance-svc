-- =============================================================================
-- 05_indexes.sql — aocs-compliance-svc
-- compliance schema indexes
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_comp_cases_tenant    ON compliance.core_compliance (tenant_id);
CREATE INDEX IF NOT EXISTS idx_comp_cases_status    ON compliance.core_compliance (status);
CREATE INDEX IF NOT EXISTS idx_comp_cases_severity  ON compliance.core_compliance (severity);
CREATE INDEX IF NOT EXISTS idx_comp_cases_agent     ON compliance.core_compliance (agent_id);
CREATE INDEX IF NOT EXISTS idx_comp_cases_created   ON compliance.core_compliance (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_comp_cases_type      ON compliance.core_compliance (case_type);

CREATE INDEX IF NOT EXISTS idx_comp_evidence_tenant ON compliance.core_evidence (tenant_id);
CREATE INDEX IF NOT EXISTS idx_comp_evidence_case   ON compliance.core_evidence (case_id);
CREATE INDEX IF NOT EXISTS idx_comp_evidence_agent  ON compliance.core_evidence (agent_id);
CREATE INDEX IF NOT EXISTS idx_comp_evidence_type   ON compliance.core_evidence (evidence_type);
CREATE INDEX IF NOT EXISTS idx_comp_evidence_date   ON compliance.core_evidence (collected_at DESC);

CREATE INDEX IF NOT EXISTS idx_comp_zkp_tenant      ON compliance.core_evidence (tenant_id);
CREATE INDEX IF NOT EXISTS idx_comp_zkp_status      ON compliance.core_evidence (verification_status);
CREATE INDEX IF NOT EXISTS idx_comp_zkp_batch       ON compliance.core_evidence (batch_id);

CREATE INDEX IF NOT EXISTS idx_comp_dlp_tenant      ON compliance.shar_dlp_integrations (tenant_id);
CREATE INDEX IF NOT EXISTS idx_comp_dlp_severity    ON compliance.shar_dlp_integrations (severity);
CREATE INDEX IF NOT EXISTS idx_comp_dlp_status      ON compliance.shar_dlp_integrations (status);

CREATE INDEX IF NOT EXISTS idx_comp_reports_tenant  ON compliance.nexus_compliance_reports (tenant_id);
CREATE INDEX IF NOT EXISTS idx_comp_reports_type    ON compliance.nexus_compliance_reports (report_type);
CREATE INDEX IF NOT EXISTS idx_comp_reports_date    ON compliance.nexus_compliance_reports (period_start DESC);

CREATE INDEX IF NOT EXISTS idx_comp_controls_tenant ON compliance.core_compliance (tenant_id);
CREATE INDEX IF NOT EXISTS idx_comp_controls_fw     ON compliance.core_compliance (framework);
CREATE INDEX IF NOT EXISTS idx_comp_controls_status ON compliance.core_compliance (status);

-- shar_trust indexes removed: table merged into core_trust_events.

SELECT 'compliance indexes created' AS status;

-- ── DBA Audit Fixes (2026-09-02) ──────────────────────────────────────────────
-- Google/Palantir DBA standard: every FK column must have a supporting index.
-- Missing these caused seq scans on cascade deletes and JOIN queries.

-- core_compliance_comments
CREATE INDEX IF NOT EXISTS idx_case_comments_case_id   ON compliance.core_compliance_comments (case_id);
CREATE INDEX IF NOT EXISTS idx_case_comments_tenant_id ON compliance.core_compliance_comments (tenant_id);

-- shar_dlp_integrations
CREATE INDEX IF NOT EXISTS idx_dlp_findings_tenant_id  ON compliance.shar_dlp_integrations (tenant_id);
CREATE INDEX IF NOT EXISTS idx_dlp_findings_case_id    ON compliance.shar_dlp_integrations (case_id);

-- core_evidence chain traversal
CREATE INDEX IF NOT EXISTS idx_evidence_control_id     ON compliance.core_evidence (control_id);
CREATE INDEX IF NOT EXISTS idx_evidence_prev_id        ON compliance.core_evidence (prev_evidence_id);

-- shar_trust compound index removed: table merged into core_trust_events.

-- core_evidence (ZKP batch jobs join on all three)
CREATE INDEX IF NOT EXISTS idx_zkp_proofs_tenant     ON compliance.core_evidence (tenant_id);
CREATE INDEX IF NOT EXISTS idx_zkp_proofs_case_id    ON compliance.core_evidence (case_id);
CREATE INDEX IF NOT EXISTS idx_zkp_proofs_evidence   ON compliance.core_evidence (evidence_id);

-- GIN index on agent_ids JSONB (for @> containment queries during collusion detection)
-- jsonb_path_ops operator class is 2-4x faster than default jsonb_ops for path queries.
CREATE INDEX IF NOT EXISTS idx_collusion_agent_ids_gin
    ON compliance.core_anomaly_detection USING GIN (agent_ids jsonb_path_ops);
