package regulatory

// obligation_status.go — GX-02: posture is earned, never seeded.
//
// Baseline framework obligations used to be inserted as COMPLIANT with a fake
// evidence_count of 1 and last_assessed_at = now, and the ISO-42001 / NIST
// reports ignored the stored status entirely (every control COMPLIANT unless a
// violation existed). A fresh tenant therefore showed ~100% posture without a
// single test having run.
//
// Now:
//   - seeds are NOT_STARTED (the schema's "not assessed" state), evidence 0,
//     never assessed, metadata.seeded = true;
//   - reports read the stored status; a blank status is NOT_STARTED, never
//     COMPLIANT;
//   - the continuous compliance worker derives the status of seeded / derived
//     obligations from linked evidence and open violations
//     (handlers/compliance/continuous_compliance_worker.go).

import (
	"time"

	"github.com/google/uuid"
)

const (
	statusNotStarted = "NOT_STARTED"
	statusCompliant  = "COMPLIANT"
)

// storedStatus returns the obligation's recorded status; blank → NOT_STARTED.
func storedStatus(row map[string]any) string {
	if s, _ := row["status"].(string); s != "" {
		return s
	}
	return statusNotStarted
}

// storedEvidenceCount returns the per-control evidence counter (maintained by
// the compl_evidence trigger); 0 when absent. Never a tenant-wide count.
func storedEvidenceCount(row map[string]any) int {
	switch n := row["evidence_count"].(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int32:
		return int(n)
	case int64:
		return int(n)
	}
	return 0
}

// passScore is passed/total as a percentage; 0 when there are no controls
// (an empty framework is not "100% compliant").
func passScore(passed, total int) float64 {
	if total <= 0 {
		return 0
	}
	return float64(passed) / float64(total) * 100.0
}

// seededObligation builds a baseline obligation row: NOT_STARTED, no
// evidence, never assessed. meta is extended with seeded=true and
// status_source=derived so the continuous compliance worker owns its status.
func seededObligation(idPrefix, tenantID, framework, controlRef, name, description string, meta map[string]any, now time.Time) map[string]any {
	if meta == nil {
		meta = map[string]any{}
	}
	meta["seeded"] = true
	meta["status_source"] = "derived"
	ts := now.UTC().Format(time.RFC3339)
	return map[string]any{
		"control_id":     idPrefix + uuid.NewString()[:8],
		"tenant_id":      tenantID,
		"framework":      framework,
		"control_ref":    controlRef,
		"name":           name,
		"description":    description,
		"status":         statusNotStarted,
		"evidence_count": 0,
		"metadata":       meta,
		"created_at":     ts,
		"updated_at":     ts,
	}
}
