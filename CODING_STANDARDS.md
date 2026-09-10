# Engineering Standards & Code Style Guide — `aocs-compliance-svc`

> **Authoritative Specification** for Evidence Vault, Zero-Knowledge Proofs (ZKP), DLP Scanners, SOC 2 / EU AI Act Reports, and Regulatory Audits.
> **Service Port**: `8089`
> **Database Schema**: `compliance` (`DATABASE_URL` must include `search_path=compliance,public`)
> **Engineering Benchmark**: Palantir Gotham / Apple Privacy Engineering / Amazon Trust & Safety.

---

## 1. Compliance & Regulatory Invariants

1. **Tamper-Evident Merkle Proofs**: Evidence records in the vault must be cryptographically anchored using Ed25519 signatures and immutable Merkle tree chains. Historical records must never be modified or deleted.
2. **7-Year Durability Standard**: Compliance and audit events must guarantee 7-year regulatory retention (EU AI Act Article 72, DORA Article 17, SOC 2 Type II). Best-effort fire-and-forget publishing is strictly forbidden; transactional outbox persistence is mandatory.
3. **Fail-Open on Inbound Evidence Ingestion**: If upstream core analytics or intelligence services are offline, `aocs-compliance-svc` must still accept and record incoming evidence receipts. Read operations (e.g. reports, export dashboards) return 503 until dependencies recover.
4. **License Enforcement**: The entire API subrouter must be gated by `LicenseFeatureGuard("compliance")`. Every request requires `"compliance"` in the JWT `features[]` claim.

---

## 2. Code Organization & Handler Standards

```
aocs-compliance-svc/
├── cmd/aocs-compliance/      # Binary entry point & router initialization
├── internal/
│   ├── vault/                # Cryptographic evidence vault & Merkle tree proofs
│   ├── dlp/                  # Real-time regex & entropy Data Loss Prevention scanners
│   ├── reports/              # SOC 2, ISO 27001, and EU AI Act compliance generators
│   └── handlers/             # REST API handlers for compliance case management
```

1. **Canonical 4-Step Handler Execution**:
   - Verify `"compliance"` feature entitlement and tenant context.
   - Validate report filters, date ranges, and export formats.
   - Execute cryptographically validated evidence aggregation.
   - Stream response using chunked RFC 7807 error-safe encoders.
2. **Section Banners & Documentation**:
   - Godoc compliance on all exported functions and types.
   - Visual dividers: `// ─── Section Title ──────────────────────────────────────────────────────────`.
   - Semantic tags (`// Cryptography: ...`, `// Compliance: ...`, `// Invariant: ...`) instead of bug slang.
