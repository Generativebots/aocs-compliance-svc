-- Privileges, tenant RLS and D7 row filters for every object that exists so far.
-- Runs last in each module; both calls are idempotent (see the framework in
-- aocs-system-svc/database/schema/03_functions.sql).
SELECT public.app_apply_privileges();
SELECT public.app_apply_tenant_rls();
SELECT public.app_apply_d7_policies();
