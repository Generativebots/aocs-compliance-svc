package reports

// analytics_summary.go — GET /analytics/summary
//
// Canonical path: GET /api/v1/analytics/summary
// Owner:          aocs-intel  (analytics sub-domain)
// RBAC:           resource=analytics, action=read
//
// Returns a platform-wide analytics digest scoped to the current tenant:
//   - agent counts + active ratio
//   - gate call volume (24h)
//   - violation count (24h)
//   - compliance posture score
//   - policy verdict distribution (24h)
//
// This is NOT an alias — it aggregates from multiple tables into a single
// summary payload optimised for dashboard header cards.
