# aocs-compliance-svc — Folder Structure

Google-recommended Go service layout (P9 structural mandate).
Reference: https://google.github.io/styleguide/go/decisions

## Key Directories

```
aocs-compliance-svc/
├── cmd/              # Binary entry points
├── internal/         # Not importable outside this module
│   ├── handlers/     # HTTP handlers (grouped by domain)
│   ├── domain/       # Pure domain logic (no HTTP, no DB)
│   └── repository/   # DB query layer
├── database/
│   └── schema/       # PostgreSQL DDL (ordered: 01_tables, 02_indexes…)
└── api/
    └── proto/        # .proto files (if applicable)
```

## Rules (enforced)
1. All DB calls through `database.GovernanceRepository` interface — no raw `pgx` in handlers
2. Tenant isolation: every query includes `tenant_id` filter — no cross-tenant access
3. Zero hardcoded table strings — use `database.Tbl*` constants from ocx-shared-go
4. Handlers return typed responses via `respond.*` — no `json.Marshal` in handlers
5. License guard on every route: `LicenseFeatureGuard("feature-name")`
