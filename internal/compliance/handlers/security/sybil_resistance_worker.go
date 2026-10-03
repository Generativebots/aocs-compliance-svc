// sybil_resistance_worker.go — Part 24 Worker #9: SybilDetectionWorker
// Runs daily at 03:00 UTC. Clusters each tenant's agents by the client IP the
// gate last saw them on (core_agent_telemetry.last_ip, written by the gate's
// AgentTelemetry stage) and records an IDS event (core_ids_events,
// signature SYBIL_IP_CLUSTER) for every agent in a suspicious cluster.
//
// Design:
//   - The read is a sanctioned system-scope read (database.SystemCallerSybilScan):
//     one pass over all tenants, but clustering, correlated-agent lists and
//     findings never cross a tenant boundary.
//   - Findings go to core_ids_events only. They are NOT written to
//     core_trust_events: that table's trigger copies "score" into
//     core_agents.trust_score, so a risk score there would overwrite trust.
//   - The scan never silently truncates: a row-cap overflow fails the run.
package security

import (
	"context"
	"log/slog"
	"sort"
	"time"

	"github.com/ocx/shared/consts"
	"github.com/ocx/shared/infra/concurrent"
	"github.com/ocx/shared/infra/database"
)

const (
	sybilScanInterval = consts.SybilScanInterval
	sybilMaxRisk      = 0.85 // clusters scoring at or above this are flagged
	sybilMinCluster   = 3    // need >= 3 distinct agents on one IP
	sybilRiskPerAgent = 0.15
	sybilWindow       = 7 * 24 * time.Hour // only agents seen in the last 7 days
	sybilMaxRows      = 100_000
	sybilSignatureID  = "SYBIL_IP_CLUSTER"
	sybilMethod       = "IP_CLUSTER_DAILY_SCAN"
)

// sybilStore is the DB capability the scan needs.
type sybilStore interface {
	QuerySystemScopeCtx(ctx context.Context, q database.SystemScopeQuery, dest interface{}) error
	InsertRow(table string, row interface{}) error
}

// agentSeenRow is one core_agent_telemetry row.
type agentSeenRow struct {
	TenantID string `json:"tenant_id"`
	AgentID  string `json:"agent_id"`
	LastIP   string `json:"last_ip"`
}

// sybilFinding is one flagged agent within a same-tenant IP cluster.
type sybilFinding struct {
	TenantID         string
	AgentID          string
	IP               string
	RiskScore        float64
	CorrelatedAgents []string // other agents of the same tenant on IP
}

// StartSybilDetectionWorker starts the daily background sybil risk scan.
// Registration in svcboot: go security.StartSybilDetectionWorker(ctx, db)
func StartSybilDetectionWorker(ctx context.Context, db database.DB) {
	if db == nil {
		slog.Warn("db is nil — sybil scan disabled")
		return
	}
	concurrent.GoUnbounded("aocs-compliance/sybil_resistance_worker", func() {
		// Align to next 03:00 UTC
		now := time.Now().UTC()
		nextRun := time.Date(now.Year(), now.Month(), now.Day(), 3, 0, 0, 0, time.UTC)
		if now.After(nextRun) {
			nextRun = nextRun.Add(24 * time.Hour)
		}
		slog.Info("started — first run scheduled",
			"next_run_utc", nextRun.Format(time.RFC3339))

		timer := time.NewTimer(time.Until(nextRun))
		defer timer.Stop()

		for {
			select {
			case <-ctx.Done():
				slog.Info("stopped")
				return
			case <-timer.C:
				if err := runSybilScan(ctx, db, time.Now().UTC()); err != nil {
					slog.Error("sybil scan failed", "error", err)
				}
				timer.Reset(sybilScanInterval)
			}
		}
	})
}

// runSybilScan reads recent agent IPs, clusters them per tenant and records
// one IDS event per flagged agent.
func runSybilScan(ctx context.Context, db sybilStore, now time.Time) error {
	scoped, err := database.WithSystemScope(ctx, database.SystemCallerSybilScan,
		"daily same-tenant IP cluster scan (sybil resistance)")
	if err != nil {
		return err
	}
	var rows []agentSeenRow
	if err := db.QuerySystemScopeCtx(scoped, database.SystemScopeQuery{
		Table:       database.TblCoreAgentTelemetry,
		Columns:     []string{"tenant_id", "agent_id", "last_ip"},
		NotNull:     []string{"last_ip"},
		SinceColumn: "last_seen_at",
		Since:       now.Add(-sybilWindow),
		MaxRows:     sybilMaxRows,
	}, &rows); err != nil {
		return err
	}

	findings := clusterSybil(rows)
	written := 0
	for _, f := range findings {
		if err := db.InsertRow(database.TblSharIdsEvents, sybilIDSEvent(f, now)); err != nil {
			slog.Error("sybil scan: IDS event write failed",
				"tenant_id", f.TenantID, "agent_id", f.AgentID, "error", err)
			continue
		}
		written++
	}
	slog.Info("sybil scan complete",
		"agents_scanned", len(rows), "flagged_agents", len(findings), "events_written", written)
	return nil
}

// clusterSybil groups agents by (tenant, ip) and returns the flagged agents in
// deterministic order. Agents of different tenants are never correlated.
func clusterSybil(rows []agentSeenRow) []sybilFinding {
	type key struct{ tenant, ip string }
	clusters := map[key]map[string]bool{}
	for _, r := range rows {
		if r.TenantID == "" || r.AgentID == "" || r.LastIP == "" {
			continue
		}
		k := key{r.TenantID, r.LastIP}
		if clusters[k] == nil {
			clusters[k] = map[string]bool{}
		}
		clusters[k][r.AgentID] = true
	}

	var out []sybilFinding
	for k, set := range clusters {
		n := len(set)
		if n < sybilMinCluster {
			continue
		}
		risk := sybilRisk(n)
		if risk < sybilMaxRisk {
			continue
		}
		agents := make([]string, 0, n)
		for a := range set {
			agents = append(agents, a)
		}
		sort.Strings(agents)
		for _, a := range agents {
			others := make([]string, 0, n-1)
			for _, o := range agents {
				if o != a {
					others = append(others, o)
				}
			}
			out = append(out, sybilFinding{
				TenantID: k.tenant, AgentID: a, IP: k.ip,
				RiskScore: risk, CorrelatedAgents: others,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TenantID != out[j].TenantID {
			return out[i].TenantID < out[j].TenantID
		}
		if out[i].IP != out[j].IP {
			return out[i].IP < out[j].IP
		}
		return out[i].AgentID < out[j].AgentID
	})
	return out
}

// sybilRisk maps cluster size to a 0..1 risk score.
func sybilRisk(clusterSize int) float64 {
	r := float64(clusterSize) * sybilRiskPerAgent
	if r > 1 {
		return 1
	}
	return r
}

// sybilIDSEvent builds the core_ids_events row for a finding.
func sybilIDSEvent(f sybilFinding, now time.Time) map[string]any {
	return map[string]any{
		"tenant_id":     f.TenantID,
		"agent_id":      f.AgentID,
		"signature_id":  sybilSignatureID,
		"event_type":    sybilSignatureID,
		"severity":      "HIGH",
		"source_ip":     f.IP,
		"anomaly_score": f.RiskScore,
		"description":   "Agent shares its client IP with 3+ agents of the same tenant — potential Sybil cluster",
		"detected_at":   now.Format(time.RFC3339),
		"raw_payload": map[string]any{
			"detection_method":  sybilMethod,
			"cluster_size":      len(f.CorrelatedAgents) + 1,
			"correlated_agents": f.CorrelatedAgents,
			"window_days":       int(sybilWindow.Hours() / 24),
		},
	}
}
