
-- Department master-data keys: (tenant_id, department_id) -> syst_departments.
-- Departments are tenant master data owned by aocs-system-svc; rows reference
-- them by key only (no names, codes or slugs). Idempotent.
DO $$
DECLARE fk record;
BEGIN
  FOR fk IN SELECT * FROM (VALUES
    ('compl_cases', 'fk_compl_cases_department', 'FOREIGN KEY (tenant_id, department_id) REFERENCES syst_departments(tenant_id, department_id)'),
    ('compl_policy_exceptions', 'fk_compl_policy_exceptions_department', 'FOREIGN KEY (tenant_id, department_id) REFERENCES syst_departments(tenant_id, department_id)'),
    ('compl_records', 'fk_compl_records_department', 'FOREIGN KEY (tenant_id, department_id) REFERENCES syst_departments(tenant_id, department_id)'),
    ('compl_risk_assessments', 'fk_compl_risk_assessments_department', 'FOREIGN KEY (tenant_id, department_id) REFERENCES syst_departments(tenant_id, department_id)')
  ) AS v(tbl, name, def)
  LOOP
    CONTINUE WHEN to_regclass('public.' || fk.tbl) IS NULL;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid = format('public.%I', fk.tbl)::regclass AND conname = fk.name) THEN
      EXECUTE format('ALTER TABLE public.%I ADD CONSTRAINT %I %s', fk.tbl, fk.name, fk.def);
    END IF;
  END LOOP;
END $$;
