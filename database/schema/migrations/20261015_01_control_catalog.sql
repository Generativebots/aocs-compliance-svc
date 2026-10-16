-- 20261015_01: global framework control catalog (F-04).
-- compl_obligations is per tenant; there was no shared catalog of framework controls to adopt from.
-- Read-only for tenants; maintained by the platform (migrations / regulatory scraper later).
CREATE TABLE IF NOT EXISTS compl_control_catalog (
    framework    TEXT        NOT NULL,
    control_id   TEXT        NOT NULL,
    title        TEXT        NOT NULL,
    category     TEXT        NOT NULL DEFAULT '',
    description  TEXT        NOT NULL DEFAULT '',
    is_active    BOOLEAN     NOT NULL DEFAULT true,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (framework, control_id)
);

ALTER TABLE compl_control_catalog ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS compl_control_catalog_read ON compl_control_catalog;
CREATE POLICY compl_control_catalog_read ON compl_control_catalog FOR SELECT USING (true);

INSERT INTO compl_control_catalog (framework, control_id, title, category) VALUES
 ('SOC2','CC1','Control environment','Common Criteria'),
 ('SOC2','CC2','Communication and information','Common Criteria'),
 ('SOC2','CC3','Risk assessment','Common Criteria'),
 ('SOC2','CC4','Monitoring activities','Common Criteria'),
 ('SOC2','CC5','Control activities','Common Criteria'),
 ('SOC2','CC6','Logical and physical access controls','Common Criteria'),
 ('SOC2','CC7','System operations','Common Criteria'),
 ('SOC2','CC8','Change management','Common Criteria'),
 ('SOC2','CC9','Risk mitigation','Common Criteria'),
 ('SOC2','A1','Availability','Additional Criteria'),
 ('SOC2','C1','Confidentiality','Additional Criteria'),
 ('SOC2','PI1','Processing integrity','Additional Criteria'),
 ('SOC2','P1','Privacy','Additional Criteria'),
 ('EU_AI_ACT','ART-9','Risk management system','High-risk AI requirements'),
 ('EU_AI_ACT','ART-10','Data and data governance','High-risk AI requirements'),
 ('EU_AI_ACT','ART-11','Technical documentation','High-risk AI requirements'),
 ('EU_AI_ACT','ART-12','Record-keeping','High-risk AI requirements'),
 ('EU_AI_ACT','ART-13','Transparency and information to deployers','High-risk AI requirements'),
 ('EU_AI_ACT','ART-14','Human oversight','High-risk AI requirements'),
 ('EU_AI_ACT','ART-15','Accuracy, robustness and cybersecurity','High-risk AI requirements'),
 ('EU_AI_ACT','ART-17','Quality management system','Provider obligations'),
 ('EU_AI_ACT','ART-26','Obligations of deployers','Deployer obligations'),
 ('EU_AI_ACT','ART-72','Post-market monitoring','Provider obligations'),
 ('ISO_42001','4','Context of the organization','Clauses'),
 ('ISO_42001','5','Leadership','Clauses'),
 ('ISO_42001','6','Planning','Clauses'),
 ('ISO_42001','7','Support','Clauses'),
 ('ISO_42001','8','Operation','Clauses'),
 ('ISO_42001','9','Performance evaluation','Clauses'),
 ('ISO_42001','10','Improvement','Clauses'),
 ('NIST_AI_RMF','GOVERN','Govern: policies, accountability and culture for AI risk','Core functions'),
 ('NIST_AI_RMF','MAP','Map: establish context and identify AI risks','Core functions'),
 ('NIST_AI_RMF','MEASURE','Measure: analyse, assess and track AI risks','Core functions'),
 ('NIST_AI_RMF','MANAGE','Manage: prioritise and act on AI risks','Core functions')
ON CONFLICT (framework, control_id) DO NOTHING;
