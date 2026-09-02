<!-- BEGIN:aocs-compliance-svc-rules -->
# aocs-compliance-svc

Evidence vault, ZKP proofs, DLP scanning, compliance cases, SOC2/EU AI Act reports.
Ring 0-adjacent — always-on compliance observability layer.

## Identity

- **Go module**: `github.com/ocx/compliance`
- **Binary**: `cmd/aocs-compliance/`
- **GitHub**: `Generativebots/aocs-compliance-svc`
- **Git remote**: `https://github.com/Generativebots/aocs-compliance-svc.git`
- **Local path**: `/Users/483863/Documents/aocs-compliance-svc`
- **Port**: `8089`

## Ring Dependencies

| Ring | Service | What compliance needs |
|------|---------|-----------------------|
| Ring 0 | aocs-system-svc (:8082) | Tenant validation, billing entitlements, feature flags |
| Ring 1 | ocx-core-svc (:8083) | Agent executions, enforcement actions |
| Ring 1 | aocs-hub (:8085) | HITL decisions |

Compliance **starts without Ring 1** but report and metrics handlers return 503 until Ring 1 is available.

## Database

- **Same Supabase project** as Ring 0 and Ring 1
- **Schema**: `compliance` (NOT `public`)
- **DATABASE_URL** must include `search_path=compliance,public`
- **FK to Ring 0**: Hard FK to `public.aocs_tenants(tenant_id)` — Ring 0 must exist first
- **FK to Ring 1**: TEXT-only references (no hard FK) — enforced at application layer

## Key Design Decisions (Palantir-aligned)

1. **Always-on**: Compliance recording never fails-closed — if downstream is down, compliance still records evidence.
2. **Separate schema**: `compliance.*` tables never pollute Ring 0 `public` schema.
3. **ZKP proofs**: Ed25519 signatures + Merkle chain ensure tamper-evidence.
4. **Fail-open on billing**: If billing service is down, compliance recording continues (billing gate only applies to API writes, not audit ingestion).
<!-- END:aocs-compliance-svc-rules -->
