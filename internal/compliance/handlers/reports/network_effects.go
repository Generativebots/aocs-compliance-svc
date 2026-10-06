package reports

// ─── Nexus Analytics — Domain-Specific Handlers ───────────────────────────────
// Replaces the generic HandleGetAnalyticsQuery (which returned 501) on all
// /nexs/anly/* and /monitor/* routes in aocs-intel.
// Each handler queries the canonical table for its domain.
