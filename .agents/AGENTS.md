<!-- BEGIN:aocs-compliance-svc-rules -->
# aocs-compliance-svc

Evidence vault, ZKP proofs, DLP scanning, compliance cases, SOC2/EU AI Act reports.

## Capability & Role

**Capability: Compliance Vault (module: `compliance`) — PAID independently purchasable add-on.**

- Guard: `ring.GuardCompliance()`
- NOT free. NOT always-on.
- Customers must purchase the `compliance` module separately via Stripe.
- Feature flag: `FeatureCompliance` — checked by `LicenseFeatureGuard("compliance")` on every request.
- Can be purchased independently of `FeatureConnectors`.
- Cannot be meaningfully used without Core (`FeatureCore`) — ZKP/DLP/reports all read agent execution data from `ocx-core-svc`.

## Identity

- **Go module**: `github.com/ocx/compliance`
- **Binary**: `cmd/aocs-compliance/`
- **GitHub**: `Generativebots/aocs-compliance-svc`
- **Git remote**: `https://github.com/Generativebots/aocs-compliance-svc.git`
- **Local path**: `/Users/483863/Documents/aocs-compliance-svc`
- **Port**: `8089`

## Service Dependencies (runtime)

| Service | Responsibility | What compliance needs |
|---------|---------------|-----------------------|
| `aocs-system-svc` (:8082) | Foundation | Tenant validation — hard FK in DB |
| `ocx-extension-svc` (:8087) | Commerce Gateway | JWT billing claims — FeatureCompliance must be in license |
| `ocx-core-svc` (:8083/:8085) | Core Enforcement | Agent executions, HITL decisions, enforcement actions |

Compliance **starts without Core** but all report/metrics/ZKP/DLP handlers return 503 until `ocx-core-svc` is available.

Compliance **will 403** every request if the tenant's JWT does not include `"compliance"` in the `features[]` claim (enforced by `LicenseFeatureGuard("compliance")`).

## Database

- **Same Supabase project** as System, Extension, and Core
- **Schema**: `compliance` (NOT `public`)
- **DATABASE_URL** must include `search_path=compliance,public`
- **FK to System**: Hard FK to `public.syst_tenants(tenant_id)` — System must exist first
- **FK to Core**: TEXT-only references (no hard FK) — enforced at application layer

## Startup Order (local dev)

```bash
# Must start AFTER:
# 1. aocs-system-svc (:8082) — foundation
# 2. ocx-extension-svc (:8087) — for billing JWT
# 3. ocx-core-svc (:8083/:8085) — for agent data (start compliance without core = 503 on report endpoints)
docker compose up -d
```

## Key Design Decisions

1. **PAID Module**: `LicenseFeatureGuard("compliance")` is wired on the ENTIRE `svc.API` router — every request to this service requires the `compliance` feature in the JWT.
2. **Fail-open on Core**: If Core is down, compliance STILL RECORDS evidence (inbound audit ingestion is not gated by Core availability). Only READS (reports, dashboards) require Core.
3. **Separate schema**: `compliance.*` tables never pollute foundation `public` schema.
4. **ZKP proofs**: Ed25519 signatures + Merkle chain ensure tamper-evidence.
<!-- END:aocs-compliance-svc-rules -->
