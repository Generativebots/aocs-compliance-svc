package compliance

// escalation_sla_worker.go — F-07: escalation SLA timer.
//
// A violation moved to ESCALATED must be handled by its owner within an SLA
// (default 24h, COMPLIANCE_ESCALATION_SLA_HOURS, 0 disables). When the deadline
// passes with the violation still ESCALATED, the owner (same resolution as the
// escalation alert) gets one "violation_sla_breached" alert. metadata.sla_breach_notified
// makes it once-only, so the worker can run on every tick without re-alerting.

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ocx/compliance/internal/compliance/coredata"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ocx/shared/infra/concurrent"
	"github.com/ocx/shared/infra/database"
)

const (
	escalationSLAInterval = 5 * time.Minute
	defaultEscalationSLA  = 24 * time.Hour
	slaNotifiedKey        = "sla_breach_notified"
)

// escalationSLA reads COMPLIANCE_ESCALATION_SLA_HOURS (default 24; 0 disables).
func escalationSLA() time.Duration {
	v := strings.TrimSpace(os.Getenv("COMPLIANCE_ESCALATION_SLA_HOURS"))
	if v == "" {
		return defaultEscalationSLA
	}
	h, err := strconv.ParseFloat(v, 64)
	if err != nil || h < 0 {
		return defaultEscalationSLA
	}
	return time.Duration(h * float64(time.Hour))
}

// parseStatusTime accepts RFC3339 and the Postgres text form.
func parseStatusTime(s string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999-07", "2006-01-02 15:04:05.999999999-07:00"} {
		if t, err := time.Parse(layout, strings.TrimSpace(s)); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// metaMap normalises a jsonb value (map or raw JSON text) to a map.
func metaMap(meta any) map[string]any {
	switch m := meta.(type) {
	case map[string]any:
		return m
	case string:
		var out map[string]any
		if json.Unmarshal([]byte(m), &out) == nil && out != nil {
			return out
		}
	}
	return map[string]any{}
}

// slaBreached reports whether an ESCALATED violation changed state more than sla ago
// and has not been alerted yet. An unparseable timestamp is not a breach (never alert on junk).
func slaBreached(status, statusChangedAt string, meta any, now time.Time, sla time.Duration) bool {
	if sla <= 0 || !strings.EqualFold(status, "ESCALATED") {
		return false
	}
	if done, _ := metaMap(meta)[slaNotifiedKey].(bool); done {
		return false
	}
	at, ok := parseStatusTime(statusChangedAt)
	return ok && now.Sub(at) >= sla
}

// StartEscalationSLAWorker alerts owners of escalated violations that outlive the SLA.
func StartEscalationSLAWorker(ctx context.Context, db database.DB, listTenants func() ([]string, error)) {
	if db == nil || listTenants == nil || escalationSLA() <= 0 {
		slog.Info("EscalationSLAWorker disabled (no db or SLA is 0)")
		return
	}
	concurrent.GoUnbounded("aocs-compliance/escalation_sla_worker", func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("EscalationSLAWorker recovered from panic", "error", r)
			}
		}()
		slog.Info("EscalationSLAWorker started", "sla", escalationSLA(), "interval", escalationSLAInterval)
		ticker := time.NewTicker(escalationSLAInterval)
		defer ticker.Stop()
		for {
			runEscalationSLA(ctx, db, listTenants, time.Now().UTC(), escalationSLA())
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	})
}

// runEscalationSLA performs one pass and returns how many breach alerts were sent.
func runEscalationSLA(ctx context.Context, db database.DB, listTenants func() ([]string, error), now time.Time, sla time.Duration) int {
	tenants, err := listTenants()
	if err != nil {
		slog.Error("EscalationSLAWorker: list tenants failed", "error", err)
		return 0
	}
	sent := 0
	for _, tid := range tenants {
		if ctx.Err() != nil {
			return sent
		}
		var rows []map[string]any
		if err := coredata.QueryRowsCompoundCtx(ctx, coredata.ResEnforcementActions,
			"enforcement_action_id,status,status_changed_at,metadata", "tenant_id", tid, "status", "ESCALATED", &rows); err != nil {
			slog.Warn("EscalationSLAWorker: query failed", "tenant_id", tid, "error", err)
			continue
		}
		for _, v := range rows {
			id, _ := v["enforcement_action_id"].(string)
			status, _ := v["status"].(string)
			changed, _ := v["status_changed_at"].(string)
			if id == "" || !slaBreached(status, changed, v["metadata"], now, sla) {
				continue
			}
			kind := alertKind{
				typ:   "violation_sla_breached",
				title: "Escalated violation overdue — SLA breached",
				body:  fmt.Sprintf("An escalated violation has been open longer than the %s SLA and still needs your review.", sla),
			}
			if _, _, err := routeAlert(ctx, db, tid, id, kind); err != nil {
				continue // retried next tick; not marked, so it is not lost
			}
			meta := metaMap(v["metadata"])
			meta[slaNotifiedKey] = true
			meta["sla_breached_at"] = now.Format(time.RFC3339)
			if uerr := coredata.UpdateRowCompound(coredata.ResEnforcementActions, "enforcement_action_id", id, "tenant_id", tid,
				map[string]any{"metadata": meta}); uerr != nil {
				slog.Warn("EscalationSLAWorker: could not mark notified", "violation", id, "error", uerr)
			}
			sent++
		}
	}
	return sent
}
