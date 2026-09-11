# aocs-compliance-svc

**AOCS Compliance Service** — evidence vault, ZKP proofs, DLP scanning, compliance cases, and SOC2/EU AI Act report generation.

## Architecture Position

```
Foundation: aocs-system-svc (:8082)   ← tenants, users, billing
Core:       ocx-core-svc (:8083)      ← agents, governance, HITL
Compliance: aocs-compliance-svc (:8089) ← THIS SERVICE (PAID — FeatureCompliance license)
            └── Reads Core at runtime (agent/HITL data)
```

## What it owns

| Domain | Tables |
|--------|--------|
| Compliance cases | `compliance.core_compliance` |
| Evidence vault | `compliance.core_evidence` |
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

# 3. Run locally (requires Foundation running on :8082)
make run

# 4. Or use Docker
make docker-run
```

## Port

| Service | Port |
|---------|------|
| aocs-compliance-svc | **8089** |

---

## Ring Synchronization & Activation Endpoint

### `POST /compliance/sync/activate` (or `/api/v1/compliance/sync/activate`)
Handles cross-ring activation when a tenant purchases the Compliance Vault add-on.

#### Request Body
```json
{
  "tenant_id": "meridian-insurance",
  "module": "compliance",
  "mode": "forward_only",
  "watermark": "2026-09-11T13:00:00Z",
  "initiator": "ops-activator"
}
```

#### Modes:
* **Mode A: `"forward_only"` (Move Forward Only)**:
  * Baseline initialized at $t = \text{NOW}()$.
  * Starts a fresh Merkle root in `compliance.merkle_ledger`.
  * Zero historical backfill latency.
  * Responds: `HTTP 200 OK`, `status: "ACTIVE"`, `events_processed: 0`.
* **Mode B: `"full_backfill"` (Historical Replay)**:
  * Retroactively scans all historical `core_events` and `core_hitl` since tenant inception.
  * Generates Merkle tree leaves and Ed25519 signatures.
  * Responds: `HTTP 202 Accepted`, `status: "SYNCHRONIZING"`.

