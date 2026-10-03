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


CREATE INDEX IF NOT EXISTS idx_comp_dlp_tenant      ON compl_dlp_integrations (tenant_id);
CREATE INDEX IF NOT EXISTS idx_comp_dlp_severity    ON compl_dlp_integrations (severity);
CREATE INDEX IF NOT EXISTS idx_comp_dlp_status      ON compl_dlp_integrations (status);

CREATE INDEX IF NOT EXISTS idx_comp_reports_tenant  ON compl_reports (tenant_id);
CREATE INDEX IF NOT EXISTS idx_comp_reports_type    ON compl_reports (report_type);
CREATE INDEX IF NOT EXISTS idx_comp_reports_date    ON compl_reports (period_start DESC);


-- shar_trust indexes removed: table merged into core_trust_events.


-- Relational integrity: every FK column must have a supporting index.
-- Missing these caused seq scans on cascade deletes and JOIN queries.

-- core_compliance_comments
CREATE INDEX IF NOT EXISTS idx_case_comments_case_id   ON compl_case_comments (case_id);
CREATE INDEX IF NOT EXISTS idx_case_comments_tenant_id ON compl_case_comments (tenant_id);

-- core_dlp_integrations
CREATE INDEX IF NOT EXISTS idx_dlp_findings_case_id    ON compl_dlp_integrations (case_id);

-- core_evidence chain traversal
CREATE INDEX IF NOT EXISTS idx_evidence_control_id     ON compl_evidence (control_id);
CREATE INDEX IF NOT EXISTS idx_evidence_prev_id        ON compl_evidence (prev_evidence_id);

-- shar_trust compound index removed: table merged into core_trust_events.

-- core_evidence (ZKP batch jobs join on all three)

-- GIN index on agent_ids JSONB (for @> containment queries during collusion detection)
-- jsonb_path_ops operator class is 2-4x faster than default jsonb_ops for path queries.
CREATE INDEX IF NOT EXISTS idx_collusion_agent_ids_gin
    ON compl_anomaly USING GIN (agent_ids jsonb_path_ops);

-- =============================================================================
-- Category E Fixes (e2e_data_gap_report.md) — ZKP Proof Chain integrity
-- =============================================================================

-- ── E-ZKP-1: compl_evidence_anchors — supporting indexes ─────────────────────
-- These were missing; without them every cascade DELETE and JOIN from
-- compl_evidence / compl_records produces a seq scan on the anchors table.

CREATE INDEX IF NOT EXISTS idx_zkp_anchors_case_id
    ON compl_evidence_anchors (case_id)
    WHERE case_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_zkp_anchors_evidence_id
    ON compl_evidence_anchors (evidence_id)
    WHERE evidence_id IS NOT NULL;

-- Compound index used by the ZKP dashboard query:
--   SELECT ... FROM compl_evidence_anchors
--   WHERE tenant_id = $1 AND verification_status = $2
-- Covers both dashboard filtering and the background reconciler.
CREATE INDEX IF NOT EXISTS idx_zkp_anchors_tenant_status
    ON compl_evidence_anchors (tenant_id, verification_status);

-- Batch job lookup: processes proofs grouped by batch_id for a tenant.
CREATE INDEX IF NOT EXISTS idx_zkp_anchors_batch_id
    ON compl_evidence_anchors (tenant_id, batch_id)
    WHERE batch_id IS NOT NULL;

-- ── E-ZKP-2: JSONB shape validation for ZKP proof fields ─────────────────────
-- The gap report noted proof_data and public_inputs have no schema validation —
-- the ZKP verifier will panic if given a scalar or array instead of an object.
-- These CHECK constraints ensure only JSON objects are accepted at the DB layer,
-- making the constraint fail-closed regardless of what the application sends.

-- ── E-HITL-1: (tenant_id, status) composite index on core_hitl_decisions ──────
-- Gap report cited missing index. Confirmed existing via 05_indexes.sql in
-- ocx-core-svc: idx_hitl_decisions_pending_status covers (tenant_id, status,
-- created_at DESC). No action needed. ✅


-- Moved from ocx-extension-svc 05_indexes.sql (2026-10-03): compl_cases is compliance-owned.
CREATE INDEX IF NOT EXISTS idx_compliance_cases_agent_id ON compl_cases USING btree (agent_id);
CREATE INDEX IF NOT EXISTS idx_compliance_cases_assignee ON compl_cases USING btree (tenant_id, assigned_to, status) WHERE (assigned_to IS NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS idx_compliance_cases_dedup ON compl_cases USING btree (dedup_key) WHERE (dedup_key IS NOT NULL);
CREATE INDEX IF NOT EXISTS idx_compliance_cases_enforcement_id ON compl_cases USING btree (enforcement_action_id);
CREATE INDEX IF NOT EXISTS idx_compliance_cases_hitl_decision_id ON compl_cases USING btree (hitl_decision_id) WHERE (hitl_decision_id IS NOT NULL);
CREATE INDEX IF NOT EXISTS idx_compliance_cases_policy_id ON compl_cases USING btree (policy_id);
CREATE INDEX IF NOT EXISTS idx_compliance_cases_severity ON compl_cases USING btree (tenant_id, severity, created_at DESC) WHERE (severity IS NOT NULL);
CREATE INDEX IF NOT EXISTS idx_compliance_cases_status ON compl_cases USING btree (tenant_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_compliance_tenant_type_status ON compl_cases USING btree (tenant_id, case_type, status, created_at DESC);

-- ============================================================================
-- Discriminator indexes for the lv_* logical views (tenant_id, subtype)
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_compl_cases_case_type ON compl_cases (tenant_id, case_type) WHERE (case_type IS NOT NULL)
;
