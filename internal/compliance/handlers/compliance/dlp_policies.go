package compliance

// DLP policies (detection patterns) — distinct from DLP findings.
//
// Findings are immutable audit rows in core_audit (dlp_findings.go).
// Policies are configuration rows in core_dlp_integrations with
// provider='INTERNAL' and config.kind='dlp_policy'; vendor integrations share
// that table but never carry that kind. /dlp/policies used to be wired to the
// findings handlers, so the policy list showed findings and "create policy"
// wrote a finding.

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

const (
	dlpPolicyKind     = "dlp_policy"
	dlpPolicyProvider = "INTERNAL"
	colsDLPPolicy     = "id,tenant_id,provider,policy_name,policy_type,rules,actions,severity,is_active,config,event_count,deactivated_at,created_by,created_at,updated_at"
)

var (
	dlpPolicyCategories = map[string]bool{"PII": true, "FINANCIAL": true, "HEALTH_PHI": true, "CREDENTIAL": true, "CUSTOM": true}
	dlpPolicySeverities = map[string]bool{"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true}
	dlpPolicyActions    = map[string]bool{"BLOCK": true, "REDACT": true, "FLAG": true, "NOTIFY": true}
	errDLPPolicyMissing = errors.New("dlp policy not found")
)

// DLPPolicy is the API shape of one detection pattern.
type DLPPolicy struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Category   string `json:"category"`
	Regex      string `json:"regex"`
	Severity   string `json:"severity"`
	Action     string `json:"action"`
	Enabled    bool   `json:"enabled"`
	MatchCount int    `json:"match_count"`
	CreatedAt  any    `json:"created_at,omitempty"`
	UpdatedAt  any    `json:"updated_at,omitempty"`
}

// DLPPolicyInput is the body of POST and PATCH /dlp/policies. PATCH treats
// nil fields as unchanged.
type DLPPolicyInput struct {
	Name     *string `json:"name"`
	Category *string `json:"category"`
	Regex    *string `json:"regex"`
	Severity *string `json:"severity"`
	Action   *string `json:"action"`
	Enabled  *bool   `json:"enabled"`
}

// NormalizeDLPPolicy merges in over base, validates and upper-cases enums.
func NormalizeDLPPolicy(base DLPPolicy, in DLPPolicyInput) (DLPPolicy, error) {
	p := base
	if in.Name != nil {
		p.Name = strings.TrimSpace(*in.Name)
	}
	if in.Category != nil {
		p.Category = strings.ToUpper(strings.TrimSpace(*in.Category))
	}
	if in.Regex != nil {
		p.Regex = *in.Regex
	}
	if in.Severity != nil {
		p.Severity = strings.ToUpper(strings.TrimSpace(*in.Severity))
	}
	if in.Action != nil {
		p.Action = strings.ToUpper(strings.TrimSpace(*in.Action))
	}
	if in.Enabled != nil {
		p.Enabled = *in.Enabled
	}
	if p.Category == "" {
		p.Category = "CUSTOM"
	}
	if p.Severity == "" {
		p.Severity = "HIGH"
	}
	if p.Action == "" {
		p.Action = "BLOCK"
	}
	switch {
	case p.Name == "":
		return p, errors.New("name is required")
	case p.Regex == "":
		return p, errors.New("regex is required")
	case !dlpPolicyCategories[p.Category]:
		return p, errors.New("category must be one of PII, FINANCIAL, HEALTH_PHI, CREDENTIAL, CUSTOM")
	case !dlpPolicySeverities[p.Severity]:
		return p, errors.New("severity must be one of CRITICAL, HIGH, MEDIUM, LOW")
	case !dlpPolicyActions[p.Action]:
		return p, errors.New("action must be one of BLOCK, REDACT, FLAG, NOTIFY")
	}
	if _, err := regexp.Compile(p.Regex); err != nil {
		return p, errors.New("regex does not compile: " + err.Error())
	}
	return p, nil
}

// DLPPolicyColumns maps a policy onto core_dlp_integrations columns. JSONB
// values are sent as JSON text (the driver cannot encode []map parameters).
func DLPPolicyColumns(p DLPPolicy) map[string]any {
	js := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	return map[string]any{
		"policy_name": p.Name,
		"policy_type": "PATTERN_MATCH",
		"rules":       js([]map[string]any{{"regex": p.Regex, "category": p.Category}}),
		"actions":     js(map[string]any{"on_match": p.Action}),
		"severity":    p.Severity,
		"is_active":   p.Enabled,
		"config":      js(map[string]any{"kind": dlpPolicyKind, "category": p.Category, "regex": p.Regex, "action": p.Action}),
	}
}

func jsonMap(v any) map[string]any {
	switch t := v.(type) {
	case map[string]any:
		return t
	case string:
		var m map[string]any
		_ = json.Unmarshal([]byte(t), &m)
		return m
	case []byte:
		var m map[string]any
		_ = json.Unmarshal(t, &m)
		return m
	}
	return nil
}

func toInt(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case int64:
		return int(t)
	}
	return 0
}

// DLPPolicyFromRow converts a row to a policy. ok is false for rows that are
// not live DLP policies (vendor integrations, deleted policies).
func DLPPolicyFromRow(row map[string]any) (DLPPolicy, bool) {
	cfg := jsonMap(row["config"])
	if cfg == nil || cfg["kind"] != dlpPolicyKind {
		return DLPPolicy{}, false
	}
	if d := row["deactivated_at"]; d != nil && d != "" {
		return DLPPolicy{}, false
	}
	str := func(v any) string { s, _ := v.(string); return s }
	enabled, _ := row["is_active"].(bool)
	return DLPPolicy{
		ID:         str(row["id"]),
		Name:       str(row["policy_name"]),
		Category:   str(cfg["category"]),
		Regex:      str(cfg["regex"]),
		Severity:   str(row["severity"]),
		Action:     str(cfg["action"]),
		Enabled:    enabled,
		MatchCount: toInt(row["event_count"]),
		CreatedAt:  row["created_at"],
		UpdatedAt:  row["updated_at"],
	}, true
}

type compoundDB interface {
	QueryRowsCompound(table, selectCols, col1, val1, col2, val2 string, dest interface{}) error
}

func loadDLPPolicy(db compoundDB, tenantID, id string) (DLPPolicy, map[string]any, error) {
	var rows []map[string]any
	if err := db.QueryRowsCompound(database.TblDLPPolicies, colsDLPPolicy, "id", id, "tenant_id", tenantID, &rows); err != nil {
		return DLPPolicy{}, nil, err
	}
	for _, row := range rows {
		if p, ok := DLPPolicyFromRow(row); ok {
			return p, row, nil
		}
	}
	return DLPPolicy{}, nil, errDLPPolicyMissing
}

// HandleListDLPPolicies — GET /dlp/policies
func HandleListDLPPolicies(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var rows []map[string]any
		if err := db.QueryRowsCompound(database.TblDLPPolicies, colsDLPPolicy,
			"tenant_id", tenantID, "provider", dlpPolicyProvider, &rows); err != nil {
			slog.Error("dlp/policies: list failed", "err", err)
			respond.InternalError(w, http.StatusInternalServerError, "list DLP policies", err)
			return
		}
		out := make([]DLPPolicy, 0, len(rows))
		for _, row := range rows {
			if p, ok := DLPPolicyFromRow(row); ok {
				out = append(out, p)
			}
		}
		respond.OK(w, map[string]any{"data": out, "total": len(out)})
	}
}

// HandleCreateDLPPolicy — POST /dlp/policies
func HandleCreateDLPPolicy(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDBWrite(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		respond.LimitBody(r)
		var in DLPPolicyInput
		if !validate.Bind(w, r, &in) {
			return
		}
		p, err := NormalizeDLPPolicy(DLPPolicy{Enabled: true}, in)
		if err != nil {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, err.Error())
			return
		}
		row := DLPPolicyColumns(p)
		row["tenant_id"] = tenantID
		row["provider"] = dlpPolicyProvider
		if actor := auth.GetUserID(r.Context()); actor != "" {
			row["created_by"] = actor
		}
		id, err := db.InsertRowReturning(database.TblDLPPolicies, row, "id")
		if err != nil {
			slog.Error("dlp/policies: create failed", "err", err)
			respond.InternalError(w, http.StatusInternalServerError, "create DLP policy", err)
			return
		}
		p.ID = id
		respond.Created(w, p)
	}
}

// HandleUpdateDLPPolicy — PATCH /dlp/policies/{id}
func HandleUpdateDLPPolicy(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDBWrite(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		id := mux.Vars(r)["id"]
		current, _, err := loadDLPPolicy(db, tenantID, id)
		if errors.Is(err, errDLPPolicyMissing) {
			respond.NotFound(w, "DLP policy not found")
			return
		} else if err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "load DLP policy", err)
			return
		}
		respond.LimitBody(r)
		var in DLPPolicyInput
		if !validate.Bind(w, r, &in) {
			return
		}
		p, err := NormalizeDLPPolicy(current, in)
		if err != nil {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, err.Error())
			return
		}
		update := DLPPolicyColumns(p)
		update["updated_at"] = time.Now().UTC().Format(time.RFC3339)
		if err := db.UpdateRowCompound(database.TblDLPPolicies, "id", id, "tenant_id", tenantID, update); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "update DLP policy", err)
			return
		}
		respond.OK(w, p)
	}
}

// HandleDeleteDLPPolicy — DELETE /dlp/policies/{id}
// Soft delete: the row keeps its history; deactivated_at hides it from the list.
func HandleDeleteDLPPolicy(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDBWrite(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		id := mux.Vars(r)["id"]
		if _, _, err := loadDLPPolicy(db, tenantID, id); errors.Is(err, errDLPPolicyMissing) {
			respond.NotFound(w, "DLP policy not found")
			return
		} else if err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "load DLP policy", err)
			return
		}
		now := time.Now().UTC().Format(time.RFC3339)
		if err := db.UpdateRowCompound(database.TblDLPPolicies, "id", id, "tenant_id", tenantID,
			map[string]any{"is_active": false, "deactivated_at": now, "updated_at": now}); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "delete DLP policy", err)
			return
		}
		respond.OK(w, map[string]any{"id": id, "status": "DELETED"})
	}
}
