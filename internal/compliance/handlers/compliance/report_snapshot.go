package compliance

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ocx/shared/infra/database"
)

// posture is one tenant's earned obligation posture at a point in time.
type posture struct {
	Total  int
	Passed int
}

// scorePct returns the percentage of obligations that are compliant, or nil
// when the tenant has no obligations (no score has been earned yet).
func (p posture) scorePct() *float64 {
	if p.Total == 0 {
		return nil
	}
	s := float64(p.Passed) / float64(p.Total) * 100.0
	return &s
}

// postureFromObligations counts compliant obligations. Status vocabulary matches
// HandleGetComplianceDashboardSummary: COMPLIANT / PASSED count as passed.
func postureFromObligations(obligations []map[string]any) posture {
	p := posture{Total: len(obligations)}
	for _, ob := range obligations {
		st, _ := ob["status"].(string)
		if st == "COMPLIANT" || st == "PASSED" {
			p.Passed++
		}
	}
	return p
}

// dailySnapshotID is deterministic so a worker restart on the same UTC day
// updates the day's snapshot instead of adding another row.
func dailySnapshotID(tenantID string, day time.Time) string {
	t := strings.ReplaceAll(tenantID, "-", "")
	if len(t) > 8 {
		t = t[:8]
	}
	return fmt.Sprintf("DAILY-%s-%s", day.UTC().Format("20060102"), t)
}

// snapshotDailyPosture persists the day's posture to compl_reports as a DAILY
// row so the dashboard history has one scored point per day. Tenants with no
// obligations get no row: an unearned score is not recorded as 0.
func snapshotDailyPosture(ctx context.Context, db database.DB, tenantID string, now time.Time) (*float64, error) {
	var obligations []map[string]any
	if err := db.QueryRowsCtx(ctx, database.TblComplObligations, "status", "tenant_id", tenantID, &obligations); err != nil {
		return nil, fmt.Errorf("read obligations: %w", err)
	}
	p := postureFromObligations(obligations)
	score := p.scorePct()
	if score == nil {
		return nil, nil
	}

	id := dailySnapshotID(tenantID, now)
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	values := map[string]any{
		"compliance_score": *score,
		"total_controls":   p.Total,
		"passed_controls":  p.Passed,
		"control_count":    p.Total,
		"generated_at":     now.Format(time.RFC3339),
		"generated_by":     database.SystemActor("compliance-report-worker"),
		"framework":        "ALL",
	}

	var existing []map[string]any
	if err := db.QueryRowsCompound(database.TblComplReports, "report_id", "tenant_id", tenantID, "report_id", id, &existing); err != nil {
		return nil, fmt.Errorf("check snapshot: %w", err)
	}
	if len(existing) > 0 {
		if err := db.UpdateRowCompound(database.TblComplReports, "tenant_id", tenantID, "report_id", id, values); err != nil {
			return nil, fmt.Errorf("update snapshot: %w", err)
		}
		return score, nil
	}

	values["report_id"] = id
	values["tenant_id"] = tenantID
	values["report_type"] = "DAILY"
	values["status"] = "GENERATED"
	values["period_start"] = dayStart.Format(time.RFC3339)
	values["period_end"] = now.Format(time.RFC3339)
	if err := db.InsertRow(database.TblComplReports, values); err != nil {
		return nil, fmt.Errorf("insert snapshot: %w", err)
	}
	slog.Info("daily posture snapshot recorded", "tenant_id", tenantID, "score", *score)
	return score, nil
}
