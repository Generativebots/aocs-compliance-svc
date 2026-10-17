// Package coredata is compliance's access to rows that ocx-core-svc owns (evidence records,
// enforcement actions, audit, events, ...). Every call goes to core's internal data gateway
// (POST /internal/v1/data/{resource}); compliance never opens these tables itself.
//
// Function names and argument order mirror the database.DB methods they replace (the table
// constant becomes a Resource name), so a call site changes by its receiver and first argument
// only. Semantics are unchanged because core executes the same DB method.
package coredata

import (
	"context"
	"errors"
	"time"

	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/serviceclient"
)

// Resources core exposes through the gateway (names are core's, not table names).
const (
	ResEvents             = "events"
	ResEvidence           = "evidence"
	ResEvidenceRecords    = "evidence_records"
	ResAudit              = "audit"
	ResComplianceActions  = "compliance_actions"
	ResEnforcementActions = "enforcement_actions"
	ResProposals          = "proposals"
	ResGovRounds          = "gov_rounds"
	ResA2AConnections     = "a2a_connections"
	ResLegal              = "legal"
	ResTenantDocs         = "tenant_docs"
	ResJobs               = "jobs"
	ResNotifications      = "notifications"
	ResEscrowTxns         = "escrow_txns"
	ResAgentTelemetry     = "agent_telemetry"
	ResPolicies           = "policies"
)

// ErrNotConfigured is returned when no core client was wired (SetClient).
var ErrNotConfigured = errors.New("coredata: ocx-core-svc client not configured")

var client *serviceclient.Client

// SetClient wires the client that targets core's hub. Called once from main.
func SetClient(c *serviceclient.Client) { client = c }

func call(ctx context.Context, resource string, body map[string]any, dest any) error {
	if client == nil {
		return ErrNotConfigured
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}
	return client.DataCall(ctx, resource, body, dest)
}

// ── reads ──────────────────────────────────────────────────────────────────

// QueryRowsCtx — rows where filterCol = filterVal (filterCol must be tenant_id).
func QueryRowsCtx(ctx context.Context, resource, cols, filterCol, filterVal string, dest any) error {
	return call(ctx, resource, map[string]any{"op": "rows", "tenant_id": filterVal, "select": cols,
		"col1": filterCol, "val1": filterVal}, dest)
}

// QueryRows is QueryRowsCtx without a context.
func QueryRows(resource, cols, filterCol, filterVal string, dest any) error {
	return QueryRowsCtx(context.Background(), resource, cols, filterCol, filterVal, dest)
}

// QueryRowsCompoundCtx — rows matching two column filters, one of which must be the tenant.
func QueryRowsCompoundCtx(ctx context.Context, resource, cols, col1, val1, col2, val2 string, dest any) error {
	return call(ctx, resource, map[string]any{"op": "rows2", "tenant_id": tenantOf(col1, val1, col2, val2),
		"select": cols, "col1": col1, "val1": val1, "col2": col2, "val2": val2}, dest)
}

// QueryRowsCompound is QueryRowsCompoundCtx without a context.
func QueryRowsCompound(resource, cols, col1, val1, col2, val2 string, dest any) error {
	return QueryRowsCompoundCtx(context.Background(), resource, cols, col1, val1, col2, val2, dest)
}

// QueryRowsWithin90DaysCompound — tenant rows with col2 = val2 from the last 90 days.
func QueryRowsWithin90DaysCompound(resource, cols, tenantID, col2, val2 string, dest any) error {
	return call(context.Background(), resource, map[string]any{"op": "window90", "tenant_id": tenantID,
		"select": cols, "col2": col2, "val2": val2}, dest)
}

// QueryRowsWithWindow — tenant rows between from and to (RFC3339, either may be empty).
func QueryRowsWithWindow(resource, cols, tenantID, from, to string, dest any) error {
	return call(context.Background(), resource, map[string]any{"op": "window", "tenant_id": tenantID,
		"select": cols, "from": from, "to": to}, dest)
}

// QueryRowsLimitedWithWindow — one page of the tenant's rows from the last windowDays days.
func QueryRowsLimitedWithWindow(resource, cols, filterCol, filterVal string, windowDays int, p database.PageParams, dest any) error {
	return call(context.Background(), resource, map[string]any{"op": "limited_window", "tenant_id": filterVal,
		"select": cols, "days": windowDays, "limit": p.Limit, "offset": p.Offset}, dest)
}

// QueryRowsCursor — one keyset page of the tenant's rows.
func QueryRowsCursor(resource, cols, filterCol, filterVal string, page database.CursorPage, dest any) error {
	body := map[string]any{"op": "cursor", "tenant_id": filterVal, "select": cols, "limit": page.Limit}
	if page.AfterID != "" {
		body["after"] = page.AfterID
		if !page.AfterTime.IsZero() {
			body["after_time"] = page.AfterTime.UTC().Format(time.RFC3339Nano)
		}
	}
	return call(context.Background(), resource, body, dest)
}

// ── writes ─────────────────────────────────────────────────────────────────

func tenantRow(row any) (string, map[string]any, error) {
	m, ok := row.(map[string]any)
	if !ok {
		return "", nil, errors.New("coredata: row must be map[string]any")
	}
	t, _ := m["tenant_id"].(string)
	return t, m, nil
}

// InsertRowCtx inserts one row; row["tenant_id"] is required.
func InsertRowCtx(ctx context.Context, resource string, row any) error {
	t, m, err := tenantRow(row)
	if err != nil {
		return err
	}
	return call(ctx, resource, map[string]any{"op": "insert", "tenant_id": t, "row": m}, nil)
}

// InsertRow is InsertRowCtx without a context.
func InsertRow(resource string, row any) error {
	return InsertRowCtx(context.Background(), resource, row)
}

// InsertRowIdempotent inserts, ignoring a conflict on conflictCols.
func InsertRowIdempotent(resource string, row any, conflictCols string) error {
	t, m, err := tenantRow(row)
	if err != nil {
		return err
	}
	return call(context.Background(), resource, map[string]any{"op": "insert_idempotent", "tenant_id": t,
		"row": m, "conflict": conflictCols}, nil)
}

// UpdateRowCompound updates the row matching two filters (one must be the tenant).
func UpdateRowCompound(resource, col1, val1, col2, val2 string, updates any) error {
	return UpdateRowCompoundCtx(context.Background(), resource, col1, val1, col2, val2, updates)
}

// UpdateRowCompoundCtx is UpdateRowCompound with a caller context.
func UpdateRowCompoundCtx(ctx context.Context, resource, col1, val1, col2, val2 string, updates any) error {
	m, ok := updates.(map[string]any)
	if !ok {
		return errors.New("coredata: updates must be map[string]any")
	}
	return call(ctx, resource, map[string]any{"op": "update",
		"tenant_id": tenantOf(col1, val1, col2, val2), "col1": col1, "val1": val1, "col2": col2, "val2": val2,
		"updates": m}, nil)
}

// SoftDeleteRowCompound soft-deletes the row matching two filters (one must be the tenant).
func SoftDeleteRowCompound(resource, col1, val1, col2, val2 string) error {
	return call(context.Background(), resource, map[string]any{"op": "soft_delete",
		"tenant_id": tenantOf(col1, val1, col2, val2), "col1": col1, "val1": val1, "col2": col2, "val2": val2}, nil)
}

// tenantOf extracts the tenant id from a column/value pair list.
func tenantOf(col1, val1, col2, val2 string) string {
	if col1 == "tenant_id" {
		return val1
	}
	if col2 == "tenant_id" {
		return val2
	}
	return ""
}

// AgentSeenSince returns each agent's last-seen IP (all tenants, columns tenant_id/agent_id/last_ip)
// for agents seen since the given time. Used only by the sybil scan.
func AgentSeenSince(ctx context.Context, since time.Time, maxRows int, dest any) error {
	return call(ctx, ResAgentTelemetry, map[string]any{"op": "system_agent_seen",
		"from": since.UTC().Format(time.RFC3339), "limit": maxRows}, dest)
}
