package compliance

// adopted_controls.go — the tenant's adopted controls (rows of compl_obligations).
//
//	GET   /compliance/controls/adopted          list the tenant's adopted controls
//	PATCH /compliance/controls/adopted/{id}     set process_id / status / owner
//
// compl_obligations is the table POST /compliance/controls/adopt writes to, but
// GET /compliance/obligations is served by the GRA framework list, so adopted
// controls had no read path and no way to be tied to a business process. process_id
// is a TEXT reference to a process owned by another service (application-layer
// integrity, like other cross-service ids), nullable until the control is assigned.

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
)

var validObligationStatus = map[string]bool{
	"NOT_STARTED": true, "IN_PROGRESS": true, "COMPLIANT": true, "NON_COMPLIANT": true, "WAIVED": true,
}

// adoptedControlPatch is the writable subset. Nil pointers are left unchanged;
// an empty process_id clears the assignment.
type adoptedControlPatch struct {
	ProcessID *string `json:"process_id"`
	Status    *string `json:"status"`
	Owner     *string `json:"owner"`
}

// buildAdoptedControlUpdates validates the patch and returns the columns to set.
// It is pure so it can be tested without a database.
func buildAdoptedControlUpdates(p adoptedControlPatch) (map[string]any, string) {
	u := map[string]any{}
	if p.ProcessID != nil {
		id := strings.TrimSpace(*p.ProcessID)
		if len(id) > 128 {
			return nil, "process_id too long"
		}
		if id == "" {
			u["process_id"] = nil
		} else {
			u["process_id"] = id
		}
	}
	if p.Status != nil {
		st := strings.ToUpper(strings.TrimSpace(*p.Status))
		if !validObligationStatus[st] {
			return nil, "invalid status"
		}
		u["status"] = st
	}
	if p.Owner != nil {
		o := strings.TrimSpace(*p.Owner)
		if len(o) > 256 {
			return nil, "owner too long"
		}
		if o == "" {
			u["owner"] = nil
		} else {
			u["owner"] = o
		}
	}
	if len(u) == 0 {
		return nil, "nothing to update"
	}
	return u, ""
}

const adoptedControlCols = "control_id,framework,control_ref,name,status,owner,process_id,created_at,updated_at"

// HandleListAdoptedControls — GET /compliance/controls/adopted[?framework=X]
func HandleListAdoptedControls(db *database.SupabaseClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var rows []map[string]any
		if err := db.QueryRowsCtx(r.Context(), database.TblComplObligations, adoptedControlCols, "tenant_id", tenantID, &rows); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "read adopted controls", err)
			return
		}
		if fw := strings.TrimSpace(r.URL.Query().Get("framework")); fw != "" {
			kept := rows[:0:0]
			for _, o := range rows {
				if f, _ := o["framework"].(string); strings.EqualFold(f, fw) {
					kept = append(kept, o)
				}
			}
			rows = kept
		}
		if rows == nil {
			rows = []map[string]any{}
		}
		respond.ListSimple(w, rows, len(rows))
	}
}

// HandleUpdateAdoptedControl — PATCH /compliance/controls/adopted/{id}
func HandleUpdateAdoptedControl(db *database.SupabaseClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDBWrite(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		id := strings.TrimSpace(mux.Vars(r)["id"])
		var patch adoptedControlPatch
		r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "invalid JSON body")
			return
		}
		updates, msg := buildAdoptedControlUpdates(patch)
		if msg != "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeValidation, msg)
			return
		}

		// Tenant-scoped existence check: a missing or foreign id is a 404, never a silent no-op.
		var have []map[string]any
		if err := db.QueryRowsCompound(database.TblComplObligations, "control_id", "tenant_id", tenantID, "control_id", id, &have); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "read adopted control", err)
			return
		}
		if len(have) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "adopted control not found")
			return
		}
		if err := db.UpdateRowCompound(database.TblComplObligations, "tenant_id", tenantID, "control_id", id, updates); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "update adopted control", err)
			return
		}
		respond.OK(w, map[string]any{"control_id": id, "updated": updates})
	}
}
