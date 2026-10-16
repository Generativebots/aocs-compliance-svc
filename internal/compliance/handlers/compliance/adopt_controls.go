package compliance

// adopt_controls.go — F-04: framework control catalog and one-call adoption.
//
//	GET  /compliance/controls/catalog?framework=SOC2   list catalog controls
//	POST /compliance/controls/adopt  {framework, control_ids?[]}
//	     copies catalog controls into the tenant's compl_obligations
//	     (all of the framework when control_ids is omitted). Idempotent:
//	     controls the tenant already has are skipped, never overwritten.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/logger"
	"github.com/ocx/shared/respond"
)

const tblComplControlCatalog = "compl_control_catalog"

// CatalogControl is one row of compl_control_catalog.
type CatalogControl struct {
	Framework   string `json:"framework"`
	ControlID   string `json:"control_id"`
	Title       string `json:"title"`
	Category    string `json:"category"`
	Description string `json:"description"`
	IsActive    bool   `json:"is_active"`
}

// obligationName builds the tenant-unique obligation name for a catalog control.
// compl_obligations enforces UNIQUE (tenant_id, name), and titles repeat across
// frameworks, so the framework and control id are part of the name.
func obligationName(c CatalogControl) string {
	return strings.TrimSpace(fmt.Sprintf("%s %s - %s", c.Framework, c.ControlID, c.Title))
}

// planAdoption decides which catalog controls become new obligation rows. It is
// pure so it can be tested without a database. wanted (control ids, case-insensitive)
// narrows the set; nil/empty means every active control. It returns the rows to
// insert, the control ids already adopted, and the requested ids not in the catalog.
func planAdoption(tenantID, owner string, catalog []CatalogControl, existing map[string]bool, wanted []string) (rows []map[string]any, skipped, unknown []string) {
	want := map[string]bool{}
	for _, id := range wanted {
		if id = strings.ToUpper(strings.TrimSpace(id)); id != "" {
			want[id] = true
		}
	}
	seen := map[string]bool{}
	for _, c := range catalog {
		if !c.IsActive {
			continue
		}
		key := strings.ToUpper(c.ControlID)
		seen[key] = true
		if len(want) > 0 && !want[key] {
			continue
		}
		if existing[key] {
			skipped = append(skipped, c.ControlID)
			continue
		}
		row := map[string]any{
			"tenant_id":   tenantID,
			"framework":   c.Framework,
			"control_ref": c.ControlID,
			"name":        obligationName(c),
			"description": c.Description,
			"status":      "NOT_STARTED",
			"metadata":    map[string]any{"adopted_from_catalog": true, "category": c.Category},
		}
		if owner != "" {
			row["owner"] = owner
		}
		rows = append(rows, row)
	}
	for id := range want {
		if !seen[id] {
			unknown = append(unknown, id)
		}
	}
	return rows, skipped, unknown
}

func readCatalog(ctx context.Context, db *database.SupabaseClient, framework string) ([]CatalogControl, error) {
	var out []CatalogControl
	if err := db.QueryRowsCtx(ctx, tblComplControlCatalog, "*", "framework", framework, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// HandleControlCatalog — GET /compliance/controls/catalog?framework=X
func HandleControlCatalog(db *database.SupabaseClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		fw := strings.TrimSpace(r.URL.Query().Get("framework"))
		if fw == "" || len(fw) > 64 {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeValidation, "framework query parameter is required")
			return
		}
		items, err := readCatalog(r.Context(), db, fw)
		if err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "read control catalog", err)
			return
		}
		if items == nil {
			items = []CatalogControl{}
		}
		respond.ListSimple(w, items, len(items))
	}
}

// HandleAdoptControls — POST /compliance/controls/adopt
func HandleAdoptControls(db *database.SupabaseClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDBWrite(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var req struct {
			Framework  string   `json:"framework"`
			ControlIDs []string `json:"control_ids"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "invalid JSON body")
			return
		}
		req.Framework = strings.TrimSpace(req.Framework)
		if req.Framework == "" || len(req.Framework) > 64 {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeValidation, "framework is required")
			return
		}
		if len(req.ControlIDs) > 500 {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeValidation, "too many control_ids (max 500)")
			return
		}
		catalog, err := readCatalog(r.Context(), db, req.Framework)
		if err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "read control catalog", err)
			return
		}
		if len(catalog) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "no catalog controls for framework "+req.Framework)
			return
		}
		var have []map[string]any
		if err := db.QueryRowsCtx(r.Context(), database.TblComplObligations, "control_ref,framework", "tenant_id", tenantID, &have); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "read obligations", err)
			return
		}
		existing := map[string]bool{}
		for _, o := range have {
			if f, _ := o["framework"].(string); strings.EqualFold(f, req.Framework) {
				if ref, _ := o["control_ref"].(string); ref != "" {
					existing[strings.ToUpper(ref)] = true
				}
			}
		}
		// Owner is left empty on purpose: it is assigned per control afterwards.
		rows, skipped, unknown := planAdoption(tenantID, "", catalog, existing, req.ControlIDs)

		adopted := 0
		var failed []string
		for _, row := range rows {
			if err := db.InsertRow(database.TblComplObligations, row); err != nil {
				// A concurrent adopt can win the unique constraint; that is a skip, not a failure.
				logger.For("compliance/adopt_controls").Warn("adopt control insert failed",
					"tenant_id", tenantID, "control_ref", row["control_ref"], "error", err)
				failed = append(failed, fmt.Sprint(row["control_ref"]))
				continue
			}
			adopted++
		}
		respond.Created(w, map[string]any{
			"framework": req.Framework,
			"adopted":   adopted,
			"skipped":   skipped,
			"unknown":   unknown,
			"failed":    failed,
		})
	}
}
