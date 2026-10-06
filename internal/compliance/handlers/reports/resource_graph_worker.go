package reports

// resource_graph_worker.go — Resource relationship graph population worker.
//
// Aocs_resource_graph_nodes and core_resource_graph_edges were permanently
// empty — the Sankey/Ograph views had no data to render. This worker scans:
//   - core_agents (nodes: agent type)
//   - core_policies (edges: agent→policy)
//   - core_intents (edges: agent→intent)
// and materializes the graph into the resource graph tables.
//
// Triggered by: POST /api/v1/resource-graph/scan (on-demand) + 15-min background tick.

import (
	"log/slog"

	"net/http"

	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
)

// StartResourceGraphWorker starts the periodic resource graph scan.

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
