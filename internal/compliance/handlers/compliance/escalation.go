// Package compliance — HITL / edge-case resolution handlers.
//
// Gathers: Cases, ZKP (chain, export, batch), Ledger Root, SIEM config, Report Export.
package compliance

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

// HandleRejectJuror — POST /api/v1/hitl/cases/{id}/recuse
// Records a juror recusal on a HITL/jury case.
// Appends to recusal_log JSONB column (bugfix3.sql M1).
func HandleRejectJuror(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		caseID := mux.Vars(r)["id"]
		if caseID == "" {
			caseID = mux.Vars(r)["case_id"]
		}
		if caseID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing case id")
			return
		}
		respond.LimitBody(r)
		var body struct {
			Reason  string `json:"reason"`
			JurorID string `json:"juror_id"`
		}
		// GATE-06 FIX (BATCH): removed duplicate LimitBody — double-wrapping halves max body size
		if !validate.Bind(w, r, &body) {
			return
		}
		jurorID := body.JurorID
		if jurorID == "" {
			jurorID = auth.GetUserID(r.Context())
		}
		now := time.Now().UTC().Format(time.RFC3339)

		entry, _ := json.Marshal(map[string]any{
			"juror_id":   jurorID,
			"reason":     body.Reason,
			"recused_at": now,
		})
		update := map[string]any{
			"recusal_log": string(entry),
			"updated_at":  now,
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		if err := db.UpdateRowCompound(database.TblCoreHitl, "decision_id", caseID, "tenant_id", tenantID, update); err != nil {
			slog.Error("RecuseJuror failed", "case_id", caseID, "juror_id", jurorID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "recuse juror", err)
			return
		}
		slog.Info("Juror recused", "case_id", caseID, "juror_id", jurorID)
		respond.OK(w, map[string]any{
			"status":     "recused",
			"case_id":    caseID,
			"juror_id":   jurorID,
			"recused_at": now,
		})
	}
}

// HandleGetRecusalLog — GET /api/v1/hitl/cases/{id}/recusal-log
// B6 FIX: Returns the recusal_log JSONB array for a HITL case so the case
// detail view (E6) can display the full recusal history panel.
// recusal_log is an append-only JSONB array: [{juror_id, reason, recused_at}, ...]
func HandleGetRecusalLog(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		caseID := mux.Vars(r)["id"]
		if caseID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}
		var rows []map[string]any
		if _dbErr := db.QueryRowsCompound(database.TblCoreHitl, "decision_id,recusal_log", "decision_id", caseID, "tenant_id", tenantID, &rows); _dbErr != nil {
			slog.Error("db operation failed", "method", "QueryRowsCompound", "error", _dbErr)
		}
		if len(rows) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "HITL case not found")
			return
		}
		// recusal_log arrives as raw JSON from Supabase — may be null/string/array
		raw := rows[0]["recusal_log"]
		var entries []map[string]any
		switch v := raw.(type) {
		case string:
			if _jsonErr := json.Unmarshal([]byte(v), &entries); _jsonErr != nil {
				slog.Warn("metadata unmarshal failed", "source_len", len([]byte(v)), "error", _jsonErr)
			}
		case []any:
			for _, item := range v {
				if m, ok := item.(map[string]any); ok {
					entries = append(entries, m)
				}
			}
		}
		if entries == nil {
			entries = []map[string]any{}
		}
		respond.JSON(w, http.StatusOK, map[string]any{
			"case_id":     caseID,
			"recusal_log": entries,
			"count":       len(entries),
		})
	}
}
