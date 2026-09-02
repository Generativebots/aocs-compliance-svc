package reports

import (
	"log/slog"
	"net/http"

	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
)

// HandleListIntelligenceObservations lists platform observation events.
//
// GET /api/v1/intelligence/observations
//
// Returns intelligence observations from aocs_observations (which is seeded by the
// ObservationEngine from aocs_platform_events). Supports optional query params:
//   - status   : OPEN | ACKNOWLEDGED | RESOLVED | DISMISSED (default: all)
//   - severity : INFO | LOW | MEDIUM | HIGH | CRITICAL (default: all)
//   - agent_id : filter to a specific agent (default: all)
//
// Response shape:
//
//	{
//	  "items": [
//	    {
//	      "observation_id": "...",
//	      "agent_id":       "...",
//	      "event_type":     "OBSERVATION",
//	      "severity":       "HIGH",
//	      "source":         "OBSERVATION_ENGINE",
//	      "title":          "Drift detected",
//	      "description":    "...",
//	      "status":         "OPEN",
//	      "tags":           [],
//	      "created_at":     "..."
//	    }
//	  ],
//	  "total": 12
//	}
func HandleListIntelligenceObservations(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized, "missing tenant_id")
			return
		}

		// Query aocs_observations — the canonical table for this endpoint.
		// Falls back gracefully if the table is empty or newly created.
		type obsRow struct {
			ObservationID  string `json:"observation_id"`
			AgentID        string `json:"agent_id,omitempty"`
			EventType      string `json:"event_type"`
			Severity       string `json:"severity"`
			Source         string `json:"source"`
			Title          string `json:"title"`
			Description    string `json:"description,omitempty"`
			Status         string `json:"status"`
			AcknowledgedBy string `json:"acknowledged_by,omitempty"`
			ResolvedBy     string `json:"resolved_by,omitempty"`
			CreatedAt      string `json:"created_at"`
			UpdatedAt      string `json:"updated_at"`
		}

		var rows []obsRow
		cols := "observation_id,agent_id,event_type,severity,source,title,description,status,acknowledged_by,resolved_by,created_at,updated_at"

		if err := db.QueryRowsCtx(r.Context(), database.TblObservations, cols, "tenant_id", tenantID, &rows); err != nil {
			slog.Error("HandleListIntelligenceObservations: query failed",
				"table", database.TblObservations, "err", err)
			// Return empty list — never 500 on a missing/empty table
			respond.JSON(w, http.StatusOK, map[string]any{"items": []obsRow{}, "total": 0})
			return
		}

		// Apply optional query filters
		statusFilter := r.URL.Query().Get("status")
		severityFilter := r.URL.Query().Get("severity")
		agentFilter := r.URL.Query().Get("agent_id")

		filtered := make([]obsRow, 0, len(rows))
		for _, row := range rows {
			if statusFilter != "" && row.Status != statusFilter {
				continue
			}
			if severityFilter != "" && row.Severity != severityFilter {
				continue
			}
			if agentFilter != "" && row.AgentID != agentFilter {
				continue
			}
			filtered = append(filtered, row)
		}

		respond.JSON(w, http.StatusOK, map[string]any{
			"items": filtered,
			"total": len(filtered),
		})
	}
}

// HandleListIntelInsights lists synthesised intel insights.
//
// GET /api/v1/intel/insights
//
// Returns insights from aocs_intel_insights. Supports optional query params:
//   - category : OPERATIONAL | RISK | COMPLIANCE | PERFORMANCE (default: all)
//   - severity : INFO | LOW | MEDIUM | HIGH | CRITICAL (default: all)
//   - status   : ACTIVE | ARCHIVED | DISMISSED (default: ACTIVE)
//
// Response shape:
//
//	{
//	  "items": [
//	    {
//	      "insight_id":      "...",
//	      "category":        "RISK",
//	      "severity":        "HIGH",
//	      "title":           "Elevated drift detected across 3 agents",
//	      "summary":         "...",
//	      "recommendations": [],
//	      "confidence":      0.92,
//	      "status":          "ACTIVE",
//	      "created_at":      "..."
//	    }
//	  ],
//	  "total": 5
//	}
func HandleListIntelInsights(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if tenantID == "" {
			respond.ErrorWithCode(w, http.StatusUnauthorized, respond.ErrCodeUnauthorized, "missing tenant_id")
			return
		}

		type insightRow struct {
			InsightID       string  `json:"insight_id"`
			AgentID         string  `json:"agent_id,omitempty"`
			Category        string  `json:"category"`
			Severity        string  `json:"severity"`
			Title           string  `json:"title"`
			Summary         string  `json:"summary,omitempty"`
			Confidence      float64 `json:"confidence"`
			Status          string  `json:"status"`
			CreatedAt       string  `json:"created_at"`
			UpdatedAt       string  `json:"updated_at"`
		}

		cols := "insight_id,agent_id,category,severity,title,summary,confidence,status,created_at,updated_at"
		var rows []insightRow

		if err := db.QueryRowsCtx(r.Context(), database.TblIntelInsights, cols, "tenant_id", tenantID, &rows); err != nil {
			slog.Error("HandleListIntelInsights: query failed",
				"table", database.TblIntelInsights, "err", err)
			respond.JSON(w, http.StatusOK, map[string]any{"items": []insightRow{}, "total": 0})
			return
		}

		// Apply optional filters
		categoryFilter := r.URL.Query().Get("category")
		severityFilter := r.URL.Query().Get("severity")
		statusFilter := r.URL.Query().Get("status")
		if statusFilter == "" {
			statusFilter = "ACTIVE" // default: only show active insights
		}

		filtered := make([]insightRow, 0, len(rows))
		for _, row := range rows {
			if statusFilter != "" && statusFilter != "all" && row.Status != statusFilter {
				continue
			}
			if categoryFilter != "" && row.Category != categoryFilter {
				continue
			}
			if severityFilter != "" && row.Severity != severityFilter {
				continue
			}
			filtered = append(filtered, row)
		}

		respond.JSON(w, http.StatusOK, map[string]any{
			"items": filtered,
			"total": len(filtered),
		})
	}
}
