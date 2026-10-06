// Package analytics — Escalation chains list handler.
//
// GET /api/v1/escalation-chains
//
// Returns all escalation chain configurations for the calling tenant.
// Escalation chains define the ordered list of recipients + SLA windows
// when a HITL case is not resolved within the primary SLA window.
// Source: aocs_ia_escalation_configs (verified in DB).
package reports
