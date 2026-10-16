package compliance

// violation_routing.go — F-07: route an escalated violation to the person who owns the control.
//
// Resolution order (first non-empty wins):
//  1. the violation's own assignee (assigned_to)
//  2. the owner of the compliance obligation the violation references (metadata.control_ref)
//  3. nobody: the alert becomes a tenant-wide alert so it is never silently dropped
//
// The alert is written to core_notifications (record_type ALERT), which the inbox already reads.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ocx/shared/infra/database"
)

// Owner sources, returned by ResolveAlertOwner for audit and tests.
const (
	OwnerSourceAssignee   = "violation_assignee"
	OwnerSourceObligation = "obligation_owner"
	OwnerSourceTenantWide = "tenant_wide"
)

// ResolveAlertOwner applies the resolution order above.
func ResolveAlertOwner(assignee, obligationOwner string) (owner, source string) {
	if a := strings.TrimSpace(assignee); a != "" {
		return a, OwnerSourceAssignee
	}
	if o := strings.TrimSpace(obligationOwner); o != "" {
		return o, OwnerSourceObligation
	}
	return "", OwnerSourceTenantWide
}

// routeViolationAlert resolves the owner of an escalated violation and writes the
// alert. The escalation itself is already committed, so a failure here is returned
// for the caller to report, not to undo the escalation.
func routeViolationAlert(ctx context.Context, db database.DB, tenantID, violationID, reason string) (owner, source string, err error) {
	body := "A compliance violation was escalated to CRITICAL."
	if strings.TrimSpace(reason) != "" {
		body += " Reason: " + reason
	}
	return routeAlert(ctx, db, tenantID, violationID, alertKind{
		typ:   "violation_escalated",
		title: "Violation escalated — your review is required",
		body:  body,
	})
}

// alertKind is the content of a routed violation alert.
type alertKind struct{ typ, title, body string }

// routeAlert resolves the violation's owner and writes one ALERT notification.
func routeAlert(ctx context.Context, db database.DB, tenantID, violationID string, kind alertKind) (owner, source string, err error) {
	var rows []map[string]any
	if qerr := db.QueryRowsCompound(database.TblCoreEnforcementActions,
		"assigned_to,department_id,metadata,reason",
		"enforcement_action_id", violationID, "tenant_id", tenantID, &rows); qerr != nil || len(rows) == 0 {
		return "", "", fmt.Errorf("load violation for routing: %v", qerr)
	}
	v := rows[0]
	assignee, _ := v["assigned_to"].(string)
	deptID, _ := v["department_id"].(string)

	obligationOwner := ""
	if assignee == "" {
		if ref := controlRefOf(v["metadata"]); ref != "" {
			var obs []map[string]any
			if oerr := db.QueryRowsCompound(database.TblComplObligations, "owner",
				"tenant_id", tenantID, "control_ref", ref, &obs); oerr == nil && len(obs) > 0 {
				obligationOwner, _ = obs[0]["owner"].(string)
			}
		}
	}
	owner, source = ResolveAlertOwner(assignee, obligationOwner)

	row := map[string]any{
		"tenant_id":   tenantID,
		"record_type": "ALERT",
		"type":        kind.typ,
		"title":       kind.title,
		"body":        kind.body,
		"entity_type": "violation",
		"entity_id":   violationID,
		"priority":    "CRITICAL",
		"is_read":     false,
		"payload":     map[string]any{"routed_to_source": source, "escalated_at": time.Now().UTC().Format(time.RFC3339)},
	}
	if owner != "" {
		row["user_id"] = owner
	}
	if deptID != "" {
		row["department_id"] = deptID
	}
	if ierr := db.InsertRow(database.TblCoreNotifications, row); ierr != nil {
		slog.Error("violation alert routing failed", "violation", violationID, "error", ierr)
		return owner, source, ierr
	}
	return owner, source, nil
}

// controlRefOf extracts metadata.control_ref from a jsonb value that may arrive as a
// map or as raw JSON text.
func controlRefOf(meta any) string {
	switch m := meta.(type) {
	case map[string]any:
		s, _ := m["control_ref"].(string)
		return strings.TrimSpace(s)
	case string:
		var parsed map[string]any
		if json.Unmarshal([]byte(m), &parsed) == nil {
			s, _ := parsed["control_ref"].(string)
			return strings.TrimSpace(s)
		}
	}
	return ""
}
