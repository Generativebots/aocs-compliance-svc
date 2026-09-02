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
