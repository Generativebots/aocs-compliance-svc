package reports

// resource_graph_worker.go — Resource relationship graph population worker.
//
// Aocs_resource_graph_nodes and aocs_resource_graph_edges were permanently
// empty — the Sankey/Ograph views had no data to render. This worker scans:
//   - aocs_agents (nodes: agent type)
//   - qcore_policy_bindings (edges: agent→policy)
//   - aocs_ia_intents (edges: agent→intent)
// and materializes the graph into the resource graph tables.
//
// Triggered by: POST /api/v1/resource-graph/scan (on-demand) + 15-min background tick.

import (
	"encoding/json"
	"fmt"
	"context"
	"log/slog"
	"os"

	"net/http"
	"time"

	"github.com/ocx/shared/infra/concurrent"
	"github.com/ocx/shared/consts"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
)

// StartResourceGraphWorker starts the periodic resource graph scan.

// deterministicNodeID produces a stable, URL-safe 14-char ID from a string key.
// Replaces uuid.NewSHA1 — maps key deterministically to platform ID format.
func deterministicNodeID(key string) string {
	h := fmt.Sprintf("%x", key)
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, 8)
	for i := 0; i < 8; i++ {
		if i < len(h) { result[i] = chars[int(h[i])%36] } else { result[i] = 'X' }
	}
	return "202605" + string(result)
}

func StartResourceGraphWorker(ctx context.Context, db database.DB) {
	if db == nil {
		slog.Warn("db is nil — disabled")
		return
	}
	// Guard: RESOURCE_GRAPH_DISABLED stops the worker when the resource graph
	// tables are not provisioned on the target DB (avoids 42P01 spam).
	if os.Getenv("RESOURCE_GRAPH_DISABLED") != "" {
		slog.Warn("resource_graph_worker: RESOURCE_GRAPH_DISABLED is set — scanner will not start")
		return
	}

	// F-RPT-04 FIX: Wrap inner worker in a supervisor that auto-restarts on panic.
	// Previously a single panic stopped the worker permanently — graph showed stale data
	// indefinitely with no staleness indicator and no restart.
	// Supervisor: restarts with exponential backoff (1s → 2s → 4s → ... → 5min max).
	concurrent.Go("resource_graph_worker_supervisor", func() {
		backoff := time.Second
		maxBackoff := 5 * time.Minute
		crashCount := 0

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			startedAt := time.Now()
			func() {
				defer func() {
					if r := recover(); r != nil {
						crashCount++
						slog.Error("F-RPT-04: resource_graph_worker panic — supervisor will restart",
							"panic", r, "crash_count", crashCount, "backoff", backoff)
					}
				}()

				// Inner worker — runs until panic or ctx cancel
				ticker := time.NewTicker(consts.ResourceGraphScanInterval)
				defer ticker.Stop()
				slog.Info("resource_graph_worker: started — 15min scan cycle", "restart_count", crashCount)

				// 30s startup delay: let DB pool TLS handshake complete before first scan.
				select {
				case <-ctx.Done():
					return
				case <-time.After(30 * time.Second):
				}

				runResourceGraphScan(ctx, db)
				for {
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
						// runResourceGraphScan is called directly — any panic propagates
						// to the outer supervisor defer/recover at the top of this func(),
						// which logs the crash and triggers the exponential-backoff restart loop.
						// No inner recover needed — double-recover causes redundant re-panic.
						runResourceGraphScan(ctx, db)
					}
				}
			}()

			// If inner worker exited cleanly (ctx cancelled), stop supervisor
			if ctx.Err() != nil {
				return
			}

			// Crash detected — apply backoff before restart
			if time.Since(startedAt) > 10*time.Minute {
				// Stable run — reset backoff
				backoff = time.Second
				crashCount = 0
			}
			if crashCount > 5 {
				slog.Error("F-RPT-04: resource_graph_worker has crashed 5+ times — resource graph data is stale. Check DB connectivity.",
					"crash_count", crashCount)
			}

			slog.Info("resource_graph_worker: restarting after backoff", "backoff", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = backoff * 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	})
}

// RunResourceGraphScanOnce runs a single scan (exported for HTTP trigger).
func RunResourceGraphScanOnce(ctx context.Context, db database.DB) {
	runResourceGraphScan(ctx, db)
}

func runResourceGraphScan(ctx context.Context, db database.DB) {
	now := time.Now().UTC().Format(time.RFC3339)
	nodes := 0
	edges := 0

	// 1. Agent nodes
	// M40: agent_type moved to aocs_agent_config — must read vw_agent_full (JOIN view).
	// Reading TblAgents directly returns NULL agent_type → broken graph topology.
	var agents []struct {
		AgentID   string `json:"agent_id"`
		TenantID  string `json:"tenant_id"`
		AgentType string `json:"agent_type"`
		AgentName string `json:"agent_name"`
	}
	if err := db.QueryRowsCtx(ctx, database.TblAgentFullView, "agent_id,tenant_id,agent_type,agent_name", "", "", &agents); err != nil {
		slog.Error("agents query failed", "error", err)
		return
	}
	for _, agt := range agents {
		nodeID := deterministicNodeID("agent:" + agt.AgentID)
		propsJSON, _ := json.Marshal(map[string]any{
			"agent_type": agt.AgentType,
			"entity_id":  agt.AgentID, // external entity ref stored in properties — NOT source_id (self-ref FK)
		})
		if _dbErr := db.InsertRowIdempotent(database.TblResourceGraphNodes, map[string]any{
			"object_id":      nodeID,
			"tenant_id":      agt.TenantID,
			"object_type":    "agent",
			"object_subtype": agt.AgentType,
			"name":           agt.AgentName,
			// source_id omitted — it is a self-referential FK to object_id;
			// external agent_id goes into properties.entity_id
			"properties": propsJSON,
			"created_at":  now,
			"updated_at":  now,
		}, "object_id"); _dbErr != nil {
			slog.Error("db.InsertRow failed (best-effort)", "error", _dbErr)
		}
		nodes++
	}

	// 2. Policy nodes from aocs_policies (post-consolidation: no dedicated binding table)
	// Pre-consolidation aocs_policy_agent_bindings was merged into aocs_policies.
	// aocs_policies has no agent_id column — policy-agent associations are inferred
	// from aocs_hitl_decisions (policy_id + agent_id). For graph building, we create
	// policy nodes from aocs_policies and derive edges from hitl_decisions.
	tenantSet := make(map[string]struct{}, len(agents))
	for _, agt := range agents {
		tenantSet[agt.TenantID] = struct{}{}
	}
	for tid := range tenantSet {
		var policies []struct {
			PolicyID string `json:"policy_id"`
			Name     string `json:"name"`
			TenantID string `json:"tenant_id"`
		}
		if err := db.QueryRowsCtx(ctx, database.TblQCorePolicyBindings, "policy_id,name,tenant_id",
			"tenant_id", tid, &policies); err != nil {
			slog.Error("policy nodes query failed", "tenant_id", tid, "error", err)
			continue
		}
		for _, p := range policies {
			// Create policy node
			policyPropsJSON, _ := json.Marshal(map[string]any{
				"entity_id": p.PolicyID,
			})
			if _dbErr := db.InsertRowIdempotent(database.TblResourceGraphNodes, map[string]any{
				"object_id":  deterministicNodeID("policy:" + p.PolicyID),
				"tenant_id":  p.TenantID,
				"object_type": "policy",
				"name":       p.Name,
				// source_id omitted — external policy_id goes into properties.entity_id
				"properties": policyPropsJSON,
				"created_at": now,
				"updated_at": now,
			}, "object_id"); _dbErr != nil {
				slog.Error("db.InsertRowIdempotent failed (policy node, best-effort)", "error", _dbErr)
			}
			nodes++
		}
		// Derive agent→policy edges from aocs_hitl_decisions (has both agent_id and policy_id)
		var decisions []struct {
			AgentID  string `json:"agent_id"`
			PolicyID string `json:"policy_id"`
			TenantID string `json:"tenant_id"`
		}
		if err := db.QueryRowsCtx(ctx, database.TblHITLDecisions, "agent_id,policy_id,tenant_id",
			"tenant_id", tid, &decisions); err != nil {
			slog.Error("policy binding edges (via hitl_decisions) query failed", "tenant_id", tid, "error", err)
			continue
		}
		for _, d := range decisions {
			if d.AgentID == "" || d.PolicyID == "" {
				continue // skip rows without both
			}
			if _dbErr := db.InsertRowIdempotent(database.TblResourceGraphEdges, map[string]any{
				"object_id":      deterministicNodeID("binding:" + d.AgentID + ":" + d.PolicyID),
				"tenant_id":      d.TenantID,
				"object_type":    "agent_policy_binding",
				"object_subtype": "POLICY_BINDING",
				"source_id":      deterministicNodeID("agent:" + d.AgentID),
				"target_id":      deterministicNodeID("policy:" + d.PolicyID),
				"properties":     map[string]any{"relationship": "BOUND_TO", "weight": 1.0},
				"created_at":     now,
				"updated_at":     now,
			}, "object_id"); _dbErr != nil {
				slog.Error("db.InsertRowIdempotent failed (policy edge, best-effort)", "error", _dbErr)
			}
			edges++
		}
	}

	slog.Info("scan complete", "nodes", nodes, "edges", edges)
}

// HandleScanResourceGraph — POST /api/v1/resource-graph/scan
// Triggers an immediate resource graph scan. Used by the co-pilot onboarding flow
// and manually from the admin console to pre-populate the graph.
func HandleScanResourceGraph(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		_, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		go RunResourceGraphScanOnce(r.Context(), db)
		respond.Created(w, map[string]any{"status": "scan_triggered"})
	}
}

// HandleGetResourceGraphSnapshot — GET /api/v1/resource-graph/snapshot
// Returns the pre-computed resource graph snapshot from persisted node/edge tables.
// Use this for cached graph views; for the live assembled graph use HandleGetResourceGraph.
func HandleGetResourceGraphSnapshot(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var nodes []map[string]any
		var edges []map[string]any
		if _dbErr := db.QueryRowsCtx(r.Context(), database.TblResourceGraphNodes, database.ColsResourceGraphNodes, "tenant_id", tenantID, &nodes); _dbErr != nil {
			slog.Error("db.QueryRows failed (best-effort)", "error", _dbErr)
		}
		if _dbErr := db.QueryRowsCtx(r.Context(), database.TblResourceGraphEdges, database.ColsResourceGraphEdges, "tenant_id", tenantID, &edges); _dbErr != nil {
			slog.Error("db.QueryRows failed (best-effort)", "error", _dbErr)
		}
		if nodes == nil {
			nodes = []map[string]any{}
		}
		if edges == nil {
			edges = []map[string]any{}
		}
		respond.OK(w, map[string]any{
			"nodes":      nodes,
			"edges":      edges,
			"node_count": len(nodes),
			"edge_count": len(edges),
		})
	}
}
