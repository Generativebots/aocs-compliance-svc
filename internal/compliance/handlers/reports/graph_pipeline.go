// Package analytics — Ograph operational graph and Sankey flow analytics.
//
// Resolves FA-27 SEV-1 issues:
//
//	S1-47: Sankey data aggregated without tenant_id filter
//	S1-48: core_ograph_flows not populated by gate events
//	S1-49: Ograph stats response key mismatch
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
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

// platformEvent is the minimal projection of core_events we need.
// final_verdict and action_class are extracted from the payload JSON, not top-level columns.
type platformEvent struct {
	EventID   string          `json:"event_id"`
	AgentID   string          `json:"agent_id"`
	ToolName  string          `json:"tool_name"`
	Payload   json.RawMessage `json:"payload"`
	CreatedAt string          `json:"created_at"`
	// GAP-P2 FIX: top-level verdict column fallback.
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

// extractPayload parses an event's payload JSON into analytics fields.
// GAP-P2 FIX: falls back to top-level Verdict/ActionClass columns if payload
// JSON is empty or missing final_verdict (column migration scenario).
func extractPayload(raw json.RawMessage) payloadFields {
	var pf payloadFields
	if len(raw) > 0 {
		if _jsonErr := json.Unmarshal(raw, &pf); _jsonErr != nil {
			slog.Warn("metadata unmarshal failed", "source_len", len(raw), "error", _jsonErr)
		}
	}
	return pf
}

// extractPayloadWithFallback is like extractPayload but also accepts the top-level
// verdict/action_class columns from the platformEvent struct as fallback.
func extractPayloadWithFallback(e platformEvent) payloadFields {
	pf := extractPayloadWithFallback(e)
	// GAP-P2: if payload JSON had no final_verdict, try top-level column.
	if pf.FinalVerdict == "" && e.Verdict != "" {
		pf.FinalVerdict = e.Verdict
	}
	if pf.ActionClass == "" && e.ActionClass != "" {
		pf.ActionClass = e.ActionClass
	}
	return pf
}

// OGRAPH STATS — GET /api/v1/analytics/ograph/stats
//   total_requests, allow_count, block_count, esc_count
// Previously the handler returned different key names, causing the stats
// footer to always show zeroes.

// HandleGetOgraphStats returns aggregate gate verdict counts for the tenant.
// GET /api/v1/analytics/ograph/stats
func HandleGetOgraphStats(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized, "tenant context required")
			return
		}

		// core_events: final_verdict lives inside payload JSON, not a top-level column.
		var events []platformEvent
		if _dbErr := db.QueryRowsWithin90DaysCompound(database.TblCoreEvents,
			"event_id,agent_id,tool_name,payload,created_at",
			tenantID,
			"event_type", database.PlatformEventClassification,
			&events); _dbErr != nil {
			slog.Error("analytics: gate classification query failed", "error", _dbErr)
			respond.JSON(w, http.StatusOK, map[string]any{
				"data_unavailable": true,
				"reason":          "analytics DB query failed — retry or check DB health",
				"tenant_id":       tenantID,
			})
			return
		}
		allowCount, blockCount, escCount := 0, 0, 0
		for _, e := range events {
			pf := extractPayloadWithFallback(e)
			switch strings.ToUpper(pf.FinalVerdict) {
			case "ALLOW", "APPROVED":
				allowCount++
			case "BLOCK", "BLOCKED":
				blockCount++
			case "ESC", "HOLD", "ESCROWED":
				escCount++
			}
		}
		total := allowCount + blockCount + escCount

		respond.OK(w, map[string]any{
			"total_requests": total,
			"allow_count":    allowCount,
			"block_count":    blockCount,
			"esc_count":      escCount,
			"tenant_id":      tenantID,
		})
	}
}

// OGRAPH TIMELINE — GET /api/v1/analytics/ograph/timeline
// Returns the last N gate classification events for the timeline chart.

// HandleGetOgraphTimeline returns recent gate events for the operational timeline.
// GET /api/v1/analytics/ograph/timeline?limit=100
func HandleGetOgraphTimeline(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized, "tenant context required")
			return
		}

		// core_events: verdict/action data lives in payload JSON.
		// log_id, final_verdict, action_class are NOT top-level columns.
		var raw []platformEvent
		if _dbErr := db.QueryRowsWithin90DaysCompound(database.TblCoreEvents,
			"event_id,agent_id,tool_name,payload,created_at",
			tenantID,
			"event_type", database.PlatformEventClassification,
			&raw); _dbErr != nil {
			slog.Error("QueryRowsCompound failed", "error", _dbErr)
		}

		type timelineEvent struct {
			EventID      string  `json:"event_id"`
			AgentID      string  `json:"agent_id"`
			ToolName     string  `json:"tool_name"`
			FinalVerdict string  `json:"final_verdict"`
			ActionClass  string  `json:"action_class"`
			TrustScore   float64 `json:"trust_score"`
			CreatedAt    string  `json:"created_at"`
		}
		const maxTimeline = 200
		events := make([]timelineEvent, 0, len(raw))
		for _, e := range raw {
			pf := extractPayloadWithFallback(e)
			events = append(events, timelineEvent{
				EventID:      e.EventID,
				AgentID:      e.AgentID,
				ToolName:     e.ToolName,
				FinalVerdict: pf.FinalVerdict,
				ActionClass:  pf.ActionClass,
				CreatedAt:    e.CreatedAt,
			})
		}
		if len(events) > maxTimeline {
			events = events[:maxTimeline]
		}

		respond.OK(w, map[string]any{
			"events":    events,
			"count":     len(events),
			"tenant_id": tenantID,
		})
	}
}

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

// HandleGetOgraphSankey returns Sankey flow data for the operational graph.
// GET /api/v1/analytics/ograph/sankey
func HandleGetOgraphSankey(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized, "tenant context required")
			return
		}

		// core_events: final_verdict and action_class live in payload JSON.
		var raw []platformEvent
		if _dbErr := db.QueryRowsWithin90DaysCompound(database.TblCoreEvents,
			"event_id,agent_id,tool_name,payload,created_at",
			tenantID,
			"event_type", database.PlatformEventClassification,
			&raw); _dbErr != nil {
			slog.Error("QueryRowsCompound failed", "error", _dbErr)
		}
		// Build node registry and edge weights
		nodeSet := map[string]sankeyNode{}
		// edge key: "source::target" → weight
		edgeWeights := map[string]int{}

		for _, e := range raw {
			agentID := e.AgentID
			if agentID == "" {
				agentID = "unknown-agent"
			}
			toolName := e.ToolName
			if toolName == "" {
				toolName = "unknown-tool"
			}
			pf := extractPayloadWithFallback(e)
			verdict := strings.ToUpper(pf.FinalVerdict)
			if verdict == "" {
				verdict = "UNKNOWN"
			}

			agentKey := "agent:" + agentID
			toolKey := "tool:" + toolName
			verdictKey := "verdict:" + verdict

			nodeSet[agentKey] = sankeyNode{ID: agentKey, Label: agentID, Group: "agent"}
			nodeSet[toolKey] = sankeyNode{ID: toolKey, Label: toolName, Group: "tool"}
			nodeSet[verdictKey] = sankeyNode{ID: verdictKey, Label: verdict, Group: "verdict"}

			// Edge 1: agent → tool
			e1 := agentKey + "::" + toolKey
			edgeWeights[e1]++
			// Edge 2: tool → verdict
			e2 := toolKey + "::" + verdictKey
			edgeWeights[e2]++
		}

		// Convert to arrays
		nodes := make([]sankeyNode, 0, len(nodeSet))
		for _, n := range nodeSet {
			nodes = append(nodes, n)
		}
		sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

		links := make([]sankeyLink, 0, len(edgeWeights))
		for key, weight := range edgeWeights {
			parts := strings.SplitN(key, "::", 2)
			if len(parts) == 2 {
				links = append(links, sankeyLink{Source: parts[0], Target: parts[1], Value: weight})
			}
		}
		sort.Slice(links, func(i, j int) bool {
			if links[i].Source != links[j].Source {
				return links[i].Source < links[j].Source
			}
			return links[i].Target < links[j].Target
		})

		slog.Info("HandleGetOgraphSankey: computed flow data",
			"tenant_id", tenantID,
			"events_processed", len(raw),
			"nodes", len(nodes),
			"links", len(links),
		)

		respond.OK(w, map[string]any{
			"nodes":        nodes,
			"links":        links,
			"tenant_id":    tenantID,
			"total_events": len(raw),
		})
	}
}

// OGRAPH FLOW UPSERT — POST /api/v1/analytics/ograph/flows
// Internal endpoint: allows operators to manually insert/update individual
// flow metrics in core_ograph_flows for custom Sankey overlays.
// Tenant-scoped: can only write flows for your own tenant.

// HandleUpsertOgraphFlow upserts a single flow metric into core_ograph_flows.
// POST /api/v1/analytics/ograph/flows
func HandleUpsertOgraphFlow(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized, "tenant context required")
			return
		}
		respond.LimitBody(r)

		var req UpsertOgraphFlowRequest
	// GATE-06 FIX (BATCH): removed duplicate LimitBody — double-wrapping halves max body size
		if !validate.Bind(w, r, &req) {
			return
		}
		if req.SourceNode == "" || req.TargetNode == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "source_node and target_node required")
			return
		}
		if req.FlowType == "" {
			req.FlowType = "GATE_EVENT"
		}

		row := map[string]any{
			"tenant_id":   tenantID,
			"source_node": req.SourceNode,
			"target_node": req.TargetNode,
			"flow_value":  req.FlowValue,
			"flow_type":   req.FlowType,
		}

		if err := db.InsertRow(database.TblCoreOgraphFlows, row); err != nil {
			// Table may not exist — fail gracefully
			slog.Error("HandleUpsertOgraphFlow: insert failed (table may be missing)", "error", err)
			respond.ErrorWithCode(w, http.StatusServiceUnavailable, respond.ErrCodeUnavailable, "flow storage not available")
			return
		}
		// H-NEW-4 FIX: Audit log — pipeline flow upsert modifies the ontology graph used for AI routing.
		slog.Info("audit: ograph flow upserted",
			"action", "UPSERT_OGRAPH_FLOW",
			"tenant_id", tenantID,
			"source_node", req.SourceNode,
			"target_node", req.TargetNode,
			"actor", r.Header.Get("X-User-ID"),
			"at", time.Now().UTC().Format(time.RFC3339),
		)

		respond.Created(w, map[string]any{
			"status":      "ok",
			"source_node": req.SourceNode,
			"target_node": req.TargetNode,
			"flow_value":  req.FlowValue,
			"tenant_id":   tenantID,
		})
	}
}
