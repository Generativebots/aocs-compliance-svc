// Package analytics — Ograph operational graph and Sankey flow analytics.
//
// Resolves FA-27 SEV-1 issues:
//
//	Sankey data aggregated without tenant_id filter
//	core_ograph_flows not populated by gate events
//	Ograph stats response key mismatch
//
// All queries derive live from core_events (the canonical gate event log),
// avoiding the need for a separate core_ograph_flows ETL pipeline.
// Tenant isolation is enforced on every query.
//
// NOTE: core_events stores verdict/action data inside the `payload` JSON
// column — not as top-level columns. All analytics handlers extract from payload.
package reports

import (
	"encoding/json"
)

// platformEvent is the minimal projection of core_events we need.
// final_verdict and action_class are extracted from the payload JSON, not top-level columns.
type platformEvent struct {
	EventID   string          `json:"event_id"`
	AgentID   string          `json:"agent_id"`
	ToolName  string          `json:"tool_name"`
	Payload   json.RawMessage `json:"payload"`
	CreatedAt string          `json:"created_at"`
	// top-level verdict column fallback.
	// core_events migrated final_verdict from payload JSON to a top-level column.
	// Include both so extractPayload can fall back gracefully.
	Verdict     string `json:"verdict,omitempty"`
	ActionClass string `json:"action_class,omitempty"`
}

// payloadFields are the analytics-relevant fields stored inside platform event payload.
type payloadFields struct {
	FinalVerdict string `json:"final_verdict"`
	ActionClass  string `json:"action_class"`
}

// OGRAPH STATS — GET /api/v1/analytics/ograph/stats
//   total_requests, allow_count, block_count, esc_count

// OGRAPH TIMELINE — GET /api/v1/analytics/ograph/timeline
// Returns the last N gate classification events for the timeline chart.

// SANKEY FLOW DATA — GET /api/v1/analytics/ograph/sankey
// core_events. No ETL pipeline or core_ograph_flows table required.
//
// Flow model: each gate event is a directed edge from (agent → verdict) via tool.
// The Sankey nodes are: agentID → toolName → verdict.
// The Sankey weight is the count of events on that edge.

type sankeyNode struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Group string `json:"group"` // "agent" | "tool" | "verdict"
}

type sankeyLink struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Value  int    `json:"value"`
}

// OGRAPH FLOW UPSERT — POST /api/v1/analytics/ograph/flows
// Internal endpoint: allows operators to manually insert/update individual
// flow metrics in core_ograph_flows for custom Sankey overlays.
// Tenant-scoped: can only write flows for your own tenant.
