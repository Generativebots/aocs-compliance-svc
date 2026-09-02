-- =============================================================================
-- 05_indexes.sql — aocs-compliance-svc
-- compliance schema indexes
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_comp_cases_tenant    ON compliance.aocs_compliance_cases (tenant_id);
CREATE INDEX IF NOT EXISTS idx_comp_cases_status    ON compliance.aocs_compliance_cases (status);
CREATE INDEX IF NOT EXISTS idx_comp_cases_severity  ON compliance.aocs_compliance_cases (severity);
CREATE INDEX IF NOT EXISTS idx_comp_cases_agent     ON compliance.aocs_compliance_cases (agent_id);
CREATE INDEX IF NOT EXISTS idx_comp_cases_created   ON compliance.aocs_compliance_cases (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_comp_cases_type      ON compliance.aocs_compliance_cases (case_type);

CREATE INDEX IF NOT EXISTS idx_comp_evidence_tenant ON compliance.aocs_evidence (tenant_id);
CREATE INDEX IF NOT EXISTS idx_comp_evidence_case   ON compliance.aocs_evidence (case_id);
CREATE INDEX IF NOT EXISTS idx_comp_evidence_agent  ON compliance.aocs_evidence (agent_id);
CREATE INDEX IF NOT EXISTS idx_comp_evidence_type   ON compliance.aocs_evidence (evidence_type);
CREATE INDEX IF NOT EXISTS idx_comp_evidence_date   ON compliance.aocs_evidence (collected_at DESC);

CREATE INDEX IF NOT EXISTS idx_comp_zkp_tenant      ON compliance.aocs_zkp_proofs (tenant_id);
CREATE INDEX IF NOT EXISTS idx_comp_zkp_status      ON compliance.aocs_zkp_proofs (verification_status);
CREATE INDEX IF NOT EXISTS idx_comp_zkp_batch       ON compliance.aocs_zkp_proofs (batch_id);

CREATE INDEX IF NOT EXISTS idx_comp_dlp_tenant      ON compliance.aocs_dlp_findings (tenant_id);
CREATE INDEX IF NOT EXISTS idx_comp_dlp_severity    ON compliance.aocs_dlp_findings (severity);
CREATE INDEX IF NOT EXISTS idx_comp_dlp_status      ON compliance.aocs_dlp_findings (status);

CREATE INDEX IF NOT EXISTS idx_comp_reports_tenant  ON compliance.nexus_compliance_reports (tenant_id);
CREATE INDEX IF NOT EXISTS idx_comp_reports_type    ON compliance.nexus_compliance_reports (report_type);
CREATE INDEX IF NOT EXISTS idx_comp_reports_date    ON compliance.nexus_compliance_reports (period_start DESC);

CREATE INDEX IF NOT EXISTS idx_comp_controls_tenant ON compliance.aocs_compliance_controls (tenant_id);
CREATE INDEX IF NOT EXISTS idx_comp_controls_fw     ON compliance.aocs_compliance_controls (framework);
CREATE INDEX IF NOT EXISTS idx_comp_controls_status ON compliance.aocs_compliance_controls (status);

CREATE INDEX IF NOT EXISTS idx_comp_sybil_tenant    ON compliance.aocs_sybil_risk_assessments (tenant_id);
CREATE INDEX IF NOT EXISTS idx_comp_sybil_date      ON compliance.aocs_sybil_risk_assessments (assessed_at DESC);

SELECT 'compliance indexes created' AS status;

-- ── DBA Audit Fixes (2026-09-02) ──────────────────────────────────────────────
-- Google/Palantir DBA standard: every FK column must have a supporting index.
-- Missing these caused seq scans on cascade deletes and JOIN queries.

-- aocs_case_comments
CREATE INDEX IF NOT EXISTS idx_case_comments_case_id   ON compliance.aocs_case_comments (case_id);
CREATE INDEX IF NOT EXISTS idx_case_comments_tenant_id ON compliance.aocs_case_comments (tenant_id);

-- aocs_dlp_findings
CREATE INDEX IF NOT EXISTS idx_dlp_findings_tenant_id  ON compliance.aocs_dlp_findings (tenant_id);
CREATE INDEX IF NOT EXISTS idx_dlp_findings_case_id    ON compliance.aocs_dlp_findings (case_id);

-- aocs_evidence chain traversal
CREATE INDEX IF NOT EXISTS idx_evidence_control_id     ON compliance.aocs_evidence (control_id);
CREATE INDEX IF NOT EXISTS idx_evidence_prev_id        ON compliance.aocs_evidence (prev_evidence_id);

-- aocs_sybil_risk_assessments (daily worker reads per-tenant, ordered by time)
CREATE INDEX IF NOT EXISTS idx_sybil_assessments_tenant
    ON compliance.aocs_sybil_risk_assessments (tenant_id, assessed_at DESC);

-- aocs_zkp_proofs (ZKP batch jobs join on all three)
CREATE INDEX IF NOT EXISTS idx_zkp_proofs_tenant     ON compliance.aocs_zkp_proofs (tenant_id);
CREATE INDEX IF NOT EXISTS idx_zkp_proofs_case_id    ON compliance.aocs_zkp_proofs (case_id);
CREATE INDEX IF NOT EXISTS idx_zkp_proofs_evidence   ON compliance.aocs_zkp_proofs (evidence_id);

-- GIN index on agent_ids JSONB (for @> containment queries during collusion detection)
-- jsonb_path_ops operator class is 2-4x faster than default jsonb_ops for path queries.
CREATE INDEX IF NOT EXISTS idx_collusion_agent_ids_gin
    ON compliance.aocs_collusion_ip_agents USING GIN (agent_ids jsonb_path_ops);
