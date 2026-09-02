// Package compliance — WORKER-06: Daily Compliance Report Generator.
//
// Runs a background goroutine that fires every 24 hours (configurable via
// COMPLIANCE_REPORT_INTERVAL_HOURS env var). For each tenant it aggregates:
//   - HITL case outcomes (total / approved / blocked / overdue)
//   - Enforcement actions (total / by type)
//   - Policy drift events (high-severity SOP violations)
//   - Active probation agents
//
// Each aggregation is persisted as a "DAILY" row in nexus_compliance_reports
// so the Compliance dashboard (/govern/compliance) has real data.
//
// Wire from cmd/aocs-platform/main.go:
//
//	compliance.StartReportGenerator(svc.BgCtx, db, coreClient)
package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/ocx/shared/infra/concurrent"

	"github.com/ocx/shared/consts"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/serviceclient"
)

const defaultReportIntervalHours = 24

// StartReportGenerator launches the daily compliance report generator.
// The goroutine terminates when ctx is cancelled (e.g. SIGTERM).
// coreClient is used for all ocx-core-svc table reads (tenants, HITL decisions, platform events,
// probation periods). If coreClient is nil the worker still starts but ocx-core-svc reads
// are skipped (best-effort aggregation with zero counts).
func StartReportGenerator(ctx context.Context, db database.DB, coreClient *serviceclient.Client) {
	if db == nil {
		slog.Warn("db is nil — worker not started")
		return
	}

	intervalHours := defaultReportIntervalHours
	if v := os.Getenv("COMPLIANCE_REPORT_INTERVAL_HOURS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			intervalHours = n
		}
	}
	interval := time.Duration(intervalHours) * time.Hour

	concurrent.Go("report_worker", func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("panic recovered", "panic", r)
			}
		}()

		slog.Info("started", "interval_hours", intervalHours)

		// Run immediately on startup to populate on first deploy.
		generateDailyReports(ctx, db, coreClient)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				slog.Info("shutting down")
				return
			case <-ticker.C:
				generateDailyReports(ctx, db, coreClient)
			}
		}
	})
}

// generateDailyReports fetches the active tenant list and generates a report row
// for each tenant. Non-fatal: individual tenant failures are logged and skipped.
func generateDailyReports(ctx context.Context, db database.DB, coreClient *serviceclient.Client) {
	if ctx.Err() != nil {
		return
	}

	// Load all active tenants via ocx-core-svc API (boundary enforcement: no direct syst_tenants read).
	var tenantIDs []string
	if coreClient != nil {
		tenants, err := coreClient.ListTenants(ctx)
		if err != nil {
			slog.Error("failed to load tenants via coreClient", "error", err)
			return
		}
		for _, t := range tenants {
			if t.Status == "ACTIVE" {
				tenantIDs = append(tenantIDs, t.TenantID)
			}
		}
	} else {
		// Fallback: direct DB only when coreClient is unavailable (e.g. test/offline mode).
		var tenants []struct {
			TenantID string `json:"tenant_id"`
			Slug     string `json:"slug"`
		}
		if err := db.QueryRowsLimited(database.TblSystTenants, "tenant_id, slug", "status", "ACTIVE",
			database.PageParams{Limit: 200, Offset: 0}, &tenants); err != nil {
			slog.Error("failed to load tenants (fallback)", "error", err)
			return
		}
		for _, t := range tenants {
			tenantIDs = append(tenantIDs, t.TenantID)
		}
	}

	generated := 0
	for _, tenantID := range tenantIDs {
		if ctx.Err() != nil {
			break
		}
		if err := generateTenantReport(ctx, db, coreClient, tenantID); err != nil {
			slog.Error("tenant report failed", "tenant_id", tenantID, "error", err)
			continue
		}
		generated++
	}

	slog.Info("daily reports generated",
		"tenant_count", len(tenantIDs), "succeeded", generated,
		"generated_at", time.Now().UTC().Format(time.RFC3339))
}

// generateTenantReport aggregates compliance data for a single tenant and
// inserts a nexus_compliance_reports row.
func generateTenantReport(ctx context.Context, db database.DB, coreClient *serviceclient.Client, tenantID string) error {
	// Respect cancellation (SIGTERM / shutdown) — stop generating mid-batch.
	if ctx.Err() != nil {
		return ctx.Err()
	}
	now := time.Now().UTC()
	since := now.Add(-consts.DefaultLookbackWindow).Format(time.RFC3339)

	// 1. HITL case outcomes (last 24h) — read via ocx-core-svc API.
	hitlTotal, hitlApproved, hitlBlocked, hitlOverdue := 0, 0, 0, 0
	if coreClient != nil {
		hitlRows, err := coreClient.ListHITLDecisions(ctx, tenantID, 200)
		if err != nil {
			slog.Error("ListHITLDecisions failed (best-effort)", "error", err)
		}
		for _, row := range hitlRows {
			if row.CreatedAt < since {
				continue // client-side 24h filter
			}
			hitlTotal++
			switch row.Verdict {
			case "ALLOW_OVERRIDE", "MODIFY_OUTPUT":
				hitlApproved++
			case "BLOCK_OVERRIDE":
				hitlBlocked++
			}
		}
	} else {
		var hitlRows []map[string]any
		if _dbErr := db.QueryRowsCursor(database.TblCoreHitl, "decision_id,status,decision_type,created_at",
			"tenant_id", tenantID, database.CursorPage{Limit: 200}, &hitlRows); _dbErr != nil {
			slog.Error("db.QueryRows HITL failed (best-effort)", "error", _dbErr)
		}
		for _, row := range hitlRows {
			createdAt, _ := row["created_at"].(string)
			if createdAt < since {
				continue
			}
			hitlTotal++
			switch row["decision_type"] {
			case "ALLOW_OVERRIDE", "MODIFY_OUTPUT":
				hitlApproved++
			case "BLOCK_OVERRIDE":
				hitlBlocked++
			}
			if row["status"] == "SLA_BREACHED" {
				hitlOverdue++
			}
		}
	}
	_ = hitlOverdue // used in report data below

	// 2. Enforcement actions (last 24h) — read from Ring2-owned compliance cases (local).
	var enfRows []map[string]any
	// FIX: Column name aligned with actual core_compliance schema.
	// Previous code referenced phantom column enforcement_action_id (SQLSTATE 42703).
	if _dbErr := db.QueryRowsCursor(database.TblCoreCompliance, "case_id,case_type,created_at",
		"tenant_id", tenantID, database.CursorPage{Limit: 200}, &enfRows); _dbErr != nil {
		slog.Error("db.QueryRows compliance cases failed (best-effort)", "error", _dbErr)
	}

	enfTotal := 0
	enfByType := map[string]int{}
	for _, row := range enfRows {
		createdAt, _ := row["created_at"].(string)
		if createdAt < since {
			continue
		}
		enfTotal++
		t, _ := row["case_type"].(string)
		enfByType[t]++
	}

	// 3. High-severity SOP drift events (last 24h) — read via ocx-core-svc API.
	sopHighSev := 0
	if coreClient != nil {
		evtRows, err := coreClient.ListPlatformEvents(ctx, tenantID, 200)
		if err != nil {
			slog.Error("ListPlatformEvents failed (best-effort)", "error", err)
		}
		for _, row := range evtRows {
			if row.CreatedAt < since {
				continue
			}
			if row.EventType == "SOP_DRIFT" {
				sopHighSev++
			}
		}
	} else {
		var sopRows []map[string]any
		if _dbErr := db.QueryRowsCursor(database.TblCoreEvents, "event_id,event_type,severity,created_at",
			"tenant_id", tenantID, database.CursorPage{Limit: 200}, &sopRows); _dbErr != nil {
			slog.Error("db.QueryRows platform events failed (best-effort)", "error", _dbErr)
		}
		for _, row := range sopRows {
			createdAt, _ := row["created_at"].(string)
			if createdAt < since {
				continue
			}
			if row["event_type"] == "SOP_DRIFT" && row["severity"] == "WARN" {
				sopHighSev++
			}
		}
	}
	_ = sopHighSev // used in report data below

	// 4. Active probation agents — read via ocx-core-svc API.
	probationCount := 0
	if coreClient != nil {
		probRows, err := coreClient.ListProbationPeriods(ctx, tenantID)
		if err != nil {
			slog.Error("ListProbationPeriods failed (best-effort)", "error", err)
		}
		for _, row := range probRows {
			if row.IsActive {
				probationCount++
			}
		}
	} else {
		var probRows []map[string]any
		if _dbErr := db.QueryRowsCursor(database.TblSharProbation, "agent_id,is_active",
			"tenant_id", tenantID, database.CursorPage{Limit: 200}, &probRows); _dbErr != nil {
			slog.Error("db.QueryRows probation failed (best-effort)", "error", _dbErr)
		}
		for _, row := range probRows {
			if row["is_active"] == true {
				probationCount++
			}
		}
	}

	// 5. Assemble and persist report
	reportData, _ := json.Marshal(map[string]any{
		"period":       "24h",
		"generated_at": now.Format(time.RFC3339),
		"hitl": map[string]int{
			"total":    hitlTotal,
			"approved": hitlApproved,
			"blocked":  hitlBlocked,
			"overdue":  hitlOverdue,
		},
		"enforcement": map[string]any{
			"total":   enfTotal,
			"by_type": enfByType,
		},
		"probation_agents": probationCount,
		"sop_high_sev":     sopHighSev,
	})

	// Generate platform-standard ID: YYYYMM + 8 random uppercase alphanumeric chars
	// Matches gen_id() DB function. Supplied explicitly so PostgREST doesn't send null.
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 8)
	for i := range b {
		b[i] = chars[rand.Intn(36)] //nolint:gosec — non-crypto ID generation
	}
	reportID := fmt.Sprintf("%d%02d", now.Year(), int(now.Month())) + string(b)

	return db.InsertRow(database.TblSharComplianceReports, map[string]any{
		"compliance_report_id": reportID,
		"tenant_id":            tenantID,
		"report_type":          "DAILY",
		"status":               "READY", // valid values: PENDING|GENERATING|READY|FAILED
		"metadata":             reportData,
		"period_start":         now.Add(-consts.DefaultLookbackWindow).Format(time.RFC3339),
		"period_end":           now.Format(time.RFC3339),
		"created_by":           "system@ocx.ai", // background worker — no user context
	})
}
