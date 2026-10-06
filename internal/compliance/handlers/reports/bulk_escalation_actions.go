package reports

// bulk_escalation_actions.go — Bulk assign and acknowledge for escalation chains.
//
// POST /analytics/escalation-chains/bulk/assign      { ids: [...], assignee_id: "user-uuid" }
// POST /analytics/escalation-chains/bulk/acknowledge { ids: [...] }
//
// The frontend /governance/escalations page calls these when the reviewer
// clicks "Assign All" or "Acknowledge All" on selected escalation chains.
// Without these routes the UI bulk actions silently fail (404).

// ── Shared types ──────────────────────────────────────────────────────────────

type bulkEscalationResult struct {
	ID      string `json:"id"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// ── HandleBulkEscalationAssign — POST /analytics/escalation-chains/bulk/assign ──
//
// Body: { ids: ["chain-uuid-1", ...], assignee_id: "user-uuid" }
// Sets assigned_to on each escalation chain config, with tenant isolation.

// ── HandleBulkEscalationAcknowledge — POST /analytics/escalation-chains/bulk/acknowledge ──
//
// Body: { ids: [...] }
// Marks each escalation chain config as acknowledged (acknowledged_at = now).
