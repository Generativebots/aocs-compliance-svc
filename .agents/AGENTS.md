<!-- BEGIN:aocs-compliance-svc-rules -->
# aocs-compliance-svc

Evidence vault, ZKP proofs, DLP scanning, compliance cases, SOC2/EU AI Act reports.

## Ring Position

**Ring 3 — PAID — independently purchasable compliance add-on.**

- NOT free. NOT always-on.
- Customers must purchase the `compliance` module separately via Stripe.
- Feature flag: `FeatureCompliance` — checked by `LicenseFeatureGuard("compliance")` on every request.
- Can be purchased independently of `FeatureConnectors` (also Ring 3).
- Cannot be meaningfully used without Ring 2 core (`FeatureCore`) — ZKP/DLP/reports all read agent execution data from `ocx-core-svc`.

## Identity

- **Go module**: `github.com/ocx/compliance`
- **Binary**: `cmd/aocs-compliance/`
- **GitHub**: `Generativebots/aocs-compliance-svc`
- **Git remote**: `https://github.com/Generativebots/aocs-compliance-svc.git`
- **Local path**: `/Users/483863/Documents/aocs-compliance-svc`
- **Port**: `8089`

## Ring Dependencies (runtime)

| Ring | Service | What compliance needs |
|------|---------|-----------------------|
| Ring 0 | aocs-system-svc (:8082) | Tenant validation — hard FK in DB |
| Ring 1 | ocx-extension-svc (:8087) | JWT billing claims — FeatureCompliance must be in license |
| Ring 2 | ocx-core-svc (:8083/:8085) | Agent executions, HITL decisions, enforcement actions |

Compliance **starts without Ring 2** but all report/metrics/ZKP/DLP handlers return 503 until Ring 2 (ocx-core-svc) is available.

Compliance **will 403** every request if the tenant's JWT does not include `"compliance"` in the `features[]` claim (enforced by `LicenseFeatureGuard("compliance")`).

## Database

- **Same Supabase project** as Ring 0, Ring 1, and Ring 2
- **Schema**: `compliance` (NOT `public`)
- **DATABASE_URL** must include `search_path=compliance,public`
- **FK to Ring 0**: Hard FK to `public.syst_tenants(tenant_id)` — Ring 0 must exist first
- **FK to Ring 2**: TEXT-only references (no hard FK) — enforced at application layer

## Startup Order (local dev)

```bash
# Must start AFTER:
# 1. Ring 0 (aocs-system-svc :8082)
# 2. Ring 1 (ocx-extension-svc :8087) — for billing JWT
# 3. Ring 2 (ocx-core-svc :8083/:8085) — for agent data (start compliance without Ring 2 = 503 on report endpoints)
docker compose up -d
```

## Key Design Decisions

1. **Ring 3 PAID**: `LicenseFeatureGuard("compliance")` is wired on the ENTIRE `svc.API` router — every request to this service requires the `compliance` feature in the JWT.
2. **Fail-open on Ring 2**: If Ring 2 is down, compliance STILL RECORDS evidence (inbound audit ingestion is not gated by Ring 2 availability). Only READS (reports, dashboards) require Ring 2.
3. **Separate schema**: `compliance.*` tables never pollute Ring 0 `public` schema.
4. **ZKP proofs**: Ed25519 signatures + Merkle chain ensure tamper-evidence.
<!-- END:aocs-compliance-svc-rules -->
