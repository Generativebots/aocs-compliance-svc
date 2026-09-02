// Package analytics — Escalation chains list handler.
//
// GET /api/v1/escalation-chains
//
// Returns all escalation chain configurations for the calling tenant.
// Escalation chains define the ordered list of recipients + SLA windows
// when a HITL case is not resolved within the primary SLA window.
// Source: aocs_ia_escalation_configs (verified in DB).
package reports

import (
	"log/slog"
	"net/http"

	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
)

// HandleListEscalationChains handles GET /api/v1/escalation-chains
// Returns paginated escalation chain configs for the calling tenant.
func HandleListEscalationChains(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		cp := database.ParseCursorPage(r)
		var rows []map[string]any
		if err := db.QueryRowsCursor(
			database.TblGovernanceDeliberations,
			"escalation_config_id,tenant_id,name,chain,trigger_after_hours,created_at,updated_at,is_active",
			"tenant_id", tenantID,
			cp,
			&rows,
		); err != nil {
			slog.Error("HandleListEscalationChains: query failed", "tenant_id", tenantID, "error", err)
			rows = []map[string]any{}
		}
		if rows == nil {
			rows = []map[string]any{}
		}

		respond.OK(w, map[string]any{
			"escalation_chains": rows,
			"total":             len(rows),
			"limit": cp.Limit,
		})
	}
}
