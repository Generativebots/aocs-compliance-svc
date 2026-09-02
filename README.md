# aocs-compliance-svc

**AOCS Compliance Service** — evidence vault, ZKP proofs, DLP scanning, compliance cases, and SOC2/EU AI Act report generation.

## Ring Position

```
Ring 0: aocs-system-svc  ← tenants, users, billing (PAID — requires FeatureCompliance license entitlement)
  │
  ├── Ring 3 (PAID): aocs-compliance-svc  ← THIS SERVICE (PAID — requires FeatureCompliance license entitlement)
  │     └── Reads Ring 1 at runtime (agent/HITL data)
  │
  └── Ring 1: ocx-core-svc + aocs-hub ← agents, governance, HITL
```

## What it owns

| Domain | Tables |
|--------|--------|
| Compliance cases | `compliance.core_compliance` |
| Evidence vault | `compliance.aocs_evidence` |
| ZKP proofs | `compliance.aocs_zkp_proofs` |
| DLP findings | `compliance.aocs_dlp_findings` |
| Controls | `compliance.aocs_compliance_controls` |
| Reports | `compliance.nexus_compliance_reports` |
| Sybil detection | `compliance.shar_trust` |

## Startup

```bash
# 1. Copy .env and fill it in
cp .env.example .env

# 2. Deploy compliance schema to Supabase (run in SQL Editor)
make db-deploy

# 3. Run locally (requires Ring 0 running on :8082)
make run

# 4. Or use Docker
make docker-run
```

## Port

| Service | Port |
|---------|------|
| aocs-compliance-svc | **8089** |
