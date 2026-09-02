// sybil_detection_worker.go — Part 24 Worker #9: SybilDetectionWorker
// Runs daily at 03:00 UTC; scans core_agents for correlated IP clusters
// and writes shar_trust + senti_ids_events for flagged agents.
package security

import (
	"context"
	"log/slog"
	"time"

	"github.com/ocx/shared/consts"
	"github.com/ocx/shared/infra/database"

	"github.com/ocx/shared/infra/concurrent"
)

const (
	sybilScanInterval = consts.SybilScanInterval
	sybilMaxRisk      = 0.85 // agents above this score get flagged in DB
)

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
				runSybilScan(ctx, db)
				// Reset to next 03:00 UTC
				timer.Reset(sybilScanInterval)
			}
		}
	})
}

// runSybilScan queries for agents sharing IPs and writes risk assessments.
func runSybilScan(ctx context.Context, db database.DB) {
	slog.Info("sybil scan started")

	// Query agents grouped by last_known_ip from audit logs
	var ipGroups []struct {
		TenantID  string `json:"tenant_id"`
		AgentID   string `json:"agent_id"`
		IPAddress string `json:"ip_address"`
	}
	if _dbErr := db.QueryRowsCtx(ctx, 
		"core_audit",
		"tenant_id,agent_id,ip_address",
		"action_type", "GATE_REQUEST",
		&ipGroups,
	); _dbErr != nil {
		slog.Error("QueryRows failed", "error", _dbErr)
	}
	// Build IP → agents map to detect collusion
	ipToAgents := make(map[string][]string)
	agentTenants := make(map[string]string)
	for _, row := range ipGroups {
		if row.IPAddress == "" || row.AgentID == "" {
			continue
		}
		ipToAgents[row.IPAddress] = appendUniq(ipToAgents[row.IPAddress], row.AgentID)
		agentTenants[row.AgentID] = row.TenantID
	}

	flagged := 0
	for ip, agents := range ipToAgents {
		if len(agents) < 3 {
			// Need ≥3 distinct agents on same IP to flag
			continue
		}
		riskScore := min(float64(len(agents))*0.15, 1.0)
		if riskScore < sybilMaxRisk {
			continue
		}
		for _, agentID := range agents {
			tenantID := agentTenants[agentID]
			if _dbErr := db.InsertRow(database.TblSybilRiskAssess, map[string]interface{}{
				"tenant_id":         tenantID,
				"agent_id":          agentID,
				"risk_score":        riskScore,
				"detection_method":  "IP_CLUSTER_DAILY_SCAN",
				"correlated_agents": agents,
				"source_ip":         ip,
				"assessed_at": time.Now().UTC(),
			}); _dbErr != nil {
				slog.Error("db.InsertRow failed (best-effort)", "error", _dbErr)
			}
			if _dbErr := db.InsertRow(database.TblSharIdsEvents, map[string]interface{}{
				"tenant_id":    tenantID,
				"signature_id": "SYBIL_IP_CLUSTER",
				"source_ip":    ip,
				"severity":     "HIGH",
				"description":  "Agent shares IP with 3+ agents — potential Sybil cluster",
				"agent_id":     agentID,
				"detected_at":  time.Now().UTC(),
			}); _dbErr != nil {
				slog.Error("db.InsertRow failed (best-effort)", "error", _dbErr)
			}
			flagged++
		}
	}

	slog.Info("scan complete",
		"ip_groups", len(ipToAgents),
		"flagged_agents", flagged,
	)
}

func appendUniq(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
