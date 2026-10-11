// departments.go — syst_departments lookups keyed by the primary key.
//
// Departments are identified ONLY by syst_departments.department_id (PK).
// Every department_id column in core_hitl / core_hitl_sla / core_agents is a
// reference to that PK. No other department key is read or written here.
// Human-facing output (messages, notes, audit text) shows the department name
// (unique per tenant: uq_departments_tenant_name), never the raw key.
package compliance

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/ocx/shared/infra/database"
)

// deptRef is one syst_departments row.
type deptRef struct {
	ID              string
	Name            string
	EnabledFeatures map[string]any
	OverflowDeptID  string // overflow_routing_config.overflow_dept_id (FK → department_id)
}

// deptIndex holds a tenant's departments keyed by department_id.
type deptIndex map[string]deptRef

const deptSelectCols = "department_id,name,enabled_features,overflow_routing_config"

// loadTenantDepartments loads every department for tenantID keyed by PK.
func loadTenantDepartments(ctx context.Context, db database.DB, tenantID string) (deptIndex, error) {
	var rows []map[string]any
	if err := db.QueryRowsCtx(ctx, database.TblSystDepartments, deptSelectCols, "tenant_id", tenantID, &rows); err != nil {
		return nil, err
	}
	idx := make(deptIndex, len(rows))
	for _, row := range rows {
		d := deptFromRow(row)
		if d.ID != "" {
			idx[d.ID] = d
		}
	}
	return idx, nil
}

// loadDepartment loads a single department by PK within tenantID.
func loadDepartment(db database.DB, tenantID, departmentID string) (deptRef, bool) {
	var rows []map[string]any
	if err := db.QueryRowsCompound(database.TblSystDepartments, deptSelectCols,
		"department_id", departmentID, "tenant_id", tenantID, &rows); err != nil || len(rows) == 0 {
		return deptRef{}, false
	}
	return deptFromRow(rows[0]), true
}

// resolve maps a classifier output onto a department PK. The classifier may
// emit a department_id or a department name (the tenant-unique key); both are
// resolved to the PK. Nothing else is accepted.
func (idx deptIndex) resolve(key string) (deptRef, bool) {
	if d, ok := idx[key]; ok {
		return d, true
	}
	k := strings.TrimSpace(key)
	for _, d := range idx {
		if strings.EqualFold(d.Name, k) {
			return d, true
		}
	}
	return deptRef{}, false
}

// name returns the display name for a department PK (falls back to the PK
// only when the department no longer exists).
func (idx deptIndex) name(id string) string {
	if d, ok := idx[id]; ok && d.Name != "" {
		return d.Name
	}
	return id
}

// names returns display names for a list of department PKs.
func (idx deptIndex) names(ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, idx.name(id))
	}
	return out
}

// hitlEnabled reports whether the department accepts HITL cases. A missing
// enabled_features.hitl key means enabled (default-on).
func (d deptRef) hitlEnabled() bool {
	v, ok := d.EnabledFeatures["hitl"]
	if !ok {
		return true
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t != "false" && t != "0"
	}
	return true
}

func deptFromRow(row map[string]any) deptRef {
	d := deptRef{}
	d.ID, _ = row["department_id"].(string)
	d.Name, _ = row["name"].(string)
	d.EnabledFeatures = jsonObject(row["enabled_features"])
	if cfg := jsonObject(row["overflow_routing_config"]); cfg != nil {
		d.OverflowDeptID, _ = cfg["overflow_dept_id"].(string)
	}
	return d
}

// jsonObject normalises a JSONB value (decoded map, raw string or bytes).
func jsonObject(v any) map[string]any {
	switch t := v.(type) {
	case map[string]any:
		return t
	case string:
		return decodeObject([]byte(t))
	case []byte:
		return decodeObject(t)
	}
	return nil
}

func decodeObject(b []byte) map[string]any {
	if len(b) == 0 {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return m
}
