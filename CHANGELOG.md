# Changelog — aocs-compliance-svc

Format follows Keep a Changelog. Hashes refer to `dev`.

## [Unreleased] — 2026-10-04 — Stopgap removal, sanctioned cross-tenant reads, tests

### Fixed
- `abcb879` The Sybil worker reads `core_agent_telemetry` via the system scope and writes to `core_ids_events`. It no longer writes `core_trust_events`, whose trigger overwrote trust scores.
- `53b84cf` Column contracts: dashboard summary, case timeline, DLP finding get (404/500 no longer masked).
- `6f433c4` DLP PID hydration decodes JSONB metadata and logs failures.
- `6ee3b4e` Local compose: container URLs on aocs-system-net. `localhost` from `.env` was unreachable, so the report workers never ran.
### Added
- `44c12af` CI unit-tests workflow; schema contract test. First test packages in this repo.
### Known issues
- Report worker: 16 serviceclient methods call unprefixed paths (404). The worker inserts `report_type='DAILY'`, which the CHECK constraint rejects.

---

