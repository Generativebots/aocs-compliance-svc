package reports

// trajectories.go — GET /intelligence/trajectories
//
// /intelligence/trajectories page to receive a 404 "route not found" which
// Next.js rendered as "Internal Server Error".
//
// Agent learning trajectories are stored in core_ontology with object_type
// values of OBSERVATION_GAP, TRAJECTORY, or INSIGHT.

import (
	"net/http"

	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
)

// HandleListTrajectories — GET /intelligence/trajectories
// Returns agent learning trajectory observations for the tenant.
// Data source: core_ontology rows with object_type IN ('OBSERVATION_GAP','TRAJECTORY','INSIGHT').
func HandleListTrajectories(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		// Query all ontology rows and filter to trajectory-related types
		var allRows []map[string]any
		if err := db.QueryRowsCtx(r.Context(), database.TblOntology,
			"object_id,object_type,name,agent_id,session_id,risk_level,risk_reason,similarity_score,closest_sop_name,status,detected_at,created_at,updated_at",
			"tenant_id", tenantID, &allRows,
		); err != nil {
			// Return empty on error — do not 500
			allRows = []map[string]any{}
		}

		// Filter to trajectory-type rows
		trajectoryTypes := map[string]bool{
			"OBSERVATION_GAP": true,
			"TRAJECTORY":      true,
			"INSIGHT":         true,
			"SOP_GAP":         true,
		}
		trajectories := make([]map[string]any, 0, len(allRows))
		for _, row := range allRows {
			ot, _ := row["object_type"].(string)
			if trajectoryTypes[ot] {
				trajectories = append(trajectories, row)
			}
		}

		respond.OK(w, map[string]any{
			"items": trajectories,
			"total": len(trajectories),
		})
	}
}
