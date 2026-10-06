package reports

// compliance_report.go — AOCS Compliance Report Generator
//
// GET /reports/compliance?standard=SOX|GDPR|EU_AI_ACT&period=2026-Q3
//
// Generates a structured compliance report from AOCS audit data:
//   - Total AI actions in the period
//   - Actions with human approval chain (HITL)
//   - Actions auto-approved by policy
//   - Actions blocked
//   - Financial threshold control (actions > configurable amount)
//   - Segregation of duties (no agent acted as both initiator and approver)
//   - Cryptographic summary hash for tamper-evidence
//
// This single endpoint replaces $500k+ in Big-4 manual audit prep.
// Travis command: "Generate my Q3 SOX report" → calls this endpoint.

// ─── Internal types ───────────────────────────────────────────────────────────

type complianceSummary struct {
	TotalAIActions               int  `json:"total_ai_actions"`
	ActionsWithHumanApproval     int  `json:"actions_with_human_approval"`
	ActionsAutoApproved          int  `json:"actions_auto_approved"`
	ActionsBlocked               int  `json:"actions_blocked"`
	FinancialActionsTotal        int  `json:"financial_actions_total"`
	FinancialActionsWithApproval int  `json:"financial_actions_with_approval"`
	FinancialControlPassed       bool `json:"financial_control_passed"`
	SegregationPassed            bool `json:"segregation_of_duties_passed"`
	ShadowAgentsDetected         int  `json:"shadow_agents_detected"`
	TotalAgentsRegistered        int  `json:"total_agents_registered"`
}

type complianceSection struct {
	Title   string `json:"title"`
	Status  string `json:"status"` // PASS | FAIL | WARNING
	Details string `json:"details"`
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
