-- =============================================================================
-- 00_seed_controls.sql — aocs-compliance-svc
-- Default compliance controls for SOC2 and EU AI Act
-- Idempotent: ON CONFLICT DO NOTHING
-- Run AFTER compliance tables are deployed and platform tenant is seeded.
-- =============================================================================

-- SOC2 Trust Services Criteria (TSC) — base controls
INSERT INTO compliance.core_compliance
  (tenant_id, framework, control_ref, name, description, status)
SELECT
  t.tenant_id,
  'SOC2',
  ctrl.ref,
  ctrl.name,
  ctrl.description,
  'NOT_STARTED'
FROM public.syst_tenants t
CROSS JOIN (VALUES
  ('CC1.1',  'Control Environment — Commitment to Integrity',  'COSO principle: demonstrates commitment to integrity and ethical values'),
  ('CC2.1',  'Communication and Information',                  'Obtains or generates relevant information to support internal control'),
  ('CC6.1',  'Logical Access Controls',                        'Implements controls to prevent unauthorized access to information assets'),
  ('CC6.6',  'Security Event Monitoring',                      'Implements controls to detect and monitor security events'),
  ('CC7.1',  'System Operations',                              'Detects and monitors for new vulnerabilities on an ongoing basis'),
  ('CC7.2',  'Incident Management',                            'Monitors system components and operates them with defined processes'),
  ('CC9.1',  'Risk Mitigation',                                'Identifies, develops, and implements risk mitigation activities'),
  ('A1.2',   'Availability — System Monitoring',              'Monitors infrastructure and software for capacity and availability')
) AS ctrl(ref, name, description)
WHERE t.is_platform_tenant = TRUE
ON CONFLICT (tenant_id, framework, control_ref) DO NOTHING;

-- EU AI Act — Article compliance controls
INSERT INTO compliance.core_compliance
  (tenant_id, framework, control_ref, name, description, status)
SELECT
  t.tenant_id,
  'EU_AI_ACT',
  ctrl.ref,
  ctrl.name,
  ctrl.description,
  'NOT_STARTED'
FROM public.syst_tenants t
CROSS JOIN (VALUES
  ('Art.9',  'Risk Management System',                         'Establish, implement, document and maintain a risk management system'),
  ('Art.10', 'Data and Data Governance',                       'Training, validation, and testing data sets meet quality criteria'),
  ('Art.12', 'Record-Keeping',                                 'High-risk AI systems log events with sufficient capacity for 7 years'),
  ('Art.13', 'Transparency and Provision of Information',      'Designed to be sufficiently transparent for operators to interpret output'),
  ('Art.14', 'Human Oversight',                                'Enable effective oversight by natural persons during use period'),
  ('Art.17', 'Quality Management System',                      'Implement quality management system covering all aspects of compliance')
) AS ctrl(ref, name, description)
WHERE t.is_platform_tenant = TRUE
ON CONFLICT (tenant_id, framework, control_ref) DO NOTHING;

SELECT COUNT(*) AS seeded_controls FROM compliance.core_compliance;
