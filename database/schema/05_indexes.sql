-- =============================================================================
-- 05_indexes.sql — aocs-compliance-svc
-- compliance schema indexes
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_comp_cases_tenant    ON compl_records (tenant_id);
CREATE INDEX IF NOT EXISTS idx_comp_cases_status    ON compl_records (status);
CREATE INDEX IF NOT EXISTS idx_comp_cases_severity  ON compl_records (severity);
CREATE INDEX IF NOT EXISTS idx_comp_cases_agent     ON compl_records (agent_id);
CREATE INDEX IF NOT EXISTS idx_comp_cases_created   ON compl_records (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_comp_cases_type      ON compl_records (case_type);

CREATE INDEX IF NOT EXISTS idx_comp_evidence_tenant ON compl_evidence (tenant_id);
CREATE INDEX IF NOT EXISTS idx_comp_evidence_case   ON compl_evidence (case_id);
CREATE INDEX IF NOT EXISTS idx_comp_evidence_agent  ON compl_evidence (agent_id);
CREATE INDEX IF NOT EXISTS idx_comp_evidence_type   ON compl_evidence (evidence_type);
CREATE INDEX IF NOT EXISTS idx_comp_evidence_date   ON compl_evidence (collected_at DESC);

CREATE INDEX IF NOT EXISTS idx_comp_zkp_tenant      ON compl_evidence (tenant_id);
CREATE INDEX IF NOT EXISTS idx_comp_zkp_status      ON compl_evidence (verification_status);
CREATE INDEX IF NOT EXISTS idx_comp_zkp_batch       ON compl_evidence (batch_id);

CREATE INDEX IF NOT EXISTS idx_comp_dlp_tenant      ON compl_dlp_integrations (tenant_id);
CREATE INDEX IF NOT EXISTS idx_comp_dlp_severity    ON compl_dlp_integrations (severity);
CREATE INDEX IF NOT EXISTS idx_comp_dlp_status      ON compl_dlp_integrations (status);

CREATE INDEX IF NOT EXISTS idx_comp_reports_tenant  ON compl_reports (tenant_id);
CREATE INDEX IF NOT EXISTS idx_comp_reports_type    ON compl_reports (report_type);
CREATE INDEX IF NOT EXISTS idx_comp_reports_date    ON compl_reports (period_start DESC);

CREATE INDEX IF NOT EXISTS idx_comp_controls_tenant ON compl_records (tenant_id);
CREATE INDEX IF NOT EXISTS idx_comp_controls_fw     ON compl_records (framework);
CREATE INDEX IF NOT EXISTS idx_comp_controls_status ON compl_records (status);

-- shar_trust indexes removed: table merged into core_trust_events.

SELECT 'compliance indexes created' AS status;

-- ── DBA Audit Fixes (2026-09-02) ──────────────────────────────────────────────
-- Google/Palantir DBA standard: every FK column must have a supporting index.
-- Missing these caused seq scans on cascade deletes and JOIN queries.

-- core_compliance_comments
CREATE INDEX IF NOT EXISTS idx_case_comments_case_id   ON compl_case_comments (case_id);
CREATE INDEX IF NOT EXISTS idx_case_comments_tenant_id ON compl_case_comments (tenant_id);

-- core_dlp_integrations
CREATE INDEX IF NOT EXISTS idx_dlp_findings_tenant_id  ON compl_dlp_integrations (tenant_id);
CREATE INDEX IF NOT EXISTS idx_dlp_findings_case_id    ON compl_dlp_integrations (case_id);

-- core_evidence chain traversal
CREATE INDEX IF NOT EXISTS idx_evidence_control_id     ON compl_evidence (control_id);
CREATE INDEX IF NOT EXISTS idx_evidence_prev_id        ON compl_evidence (prev_evidence_id);

-- shar_trust compound index removed: table merged into core_trust_events.

-- core_evidence (ZKP batch jobs join on all three)
CREATE INDEX IF NOT EXISTS idx_zkp_proofs_tenant     ON compl_evidence (tenant_id);
CREATE INDEX IF NOT EXISTS idx_zkp_proofs_case_id    ON compl_evidence (case_id);
CREATE INDEX IF NOT EXISTS idx_zkp_proofs_evidence   ON compl_evidence (evidence_id);

-- GIN index on agent_ids JSONB (for @> containment queries during collusion detection)
-- jsonb_path_ops operator class is 2-4x faster than default jsonb_ops for path queries.
CREATE INDEX IF NOT EXISTS idx_collusion_agent_ids_gin
    ON compl_anomaly USING GIN (agent_ids jsonb_path_ops);
