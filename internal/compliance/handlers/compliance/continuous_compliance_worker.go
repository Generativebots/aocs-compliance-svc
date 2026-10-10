package compliance

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"time"

	dcompliance "github.com/ocx/compliance/internal/compliance/domain/compliance"
	"github.com/ocx/shared/infra/concurrent"
	"github.com/ocx/shared/infra/config"
	"github.com/ocx/shared/infra/database"
)

const continuousComplianceInterval = 5 * time.Minute

// autoFlagKey marks an obligation the worker moved to IN_PROGRESS so it can
// restore the prior status once every linked violation is closed. Obligations
// a human moved to IN_PROGRESS carry no marker and are never touched.
const autoFlagKey = "continuous_compliance_flag"

// violationEvidenceRefs links a violation type to the evidence capability whose
// controls it undermines (compl_obligations.metadata.evidence_ref). Generic
// links (GX-16), for any violation type:
//   - a violation names controls in details.control_refs / details.control_ref
//     (gate violations carry the controls their policy declares in
//     core_policies.metadata.control_refs, copied by the harvester);
//   - a control opts in with metadata.violation_types or metadata.policy_ids.
var violationEvidenceRefs = map[string][]string{
	dcompliance.ViolationTypeDLPExfiltration: {"evlt_dlp_scanner"},
}

// continuousComplianceStore is the subset of database.DB the worker needs.
type continuousComplianceStore interface {
	ListAllTenants() ([]config.TenantRow, error)
	QueryRowsCtx(ctx context.Context, table, selectCols, filterCol, filterVal string, dest interface{}) error
	QueryRowsCompoundCtx(ctx context.Context, table, selectCols, col1, val1, col2, val2 string, dest interface{}) error
	UpdateRowCompound(table, col1, val1, col2, val2 string, updates interface{}) error
}

// StartContinuousComplianceWorker periodically reconciles each tenant's
// compliance obligations with its open policy violations so the dashboard
// posture is continuously updated rather than only on demand (GAP-GRC1).
func StartContinuousComplianceWorker(ctx context.Context, db continuousComplianceStore) {
	if db == nil {
		slog.Warn("ContinuousComplianceWorker: db is nil — worker not started")
		return
	}

	concurrent.GoUnbounded("aocs-compliance/continuous_compliance_worker", func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("ContinuousComplianceWorker recovered from panic", "error", r)
			}
		}()

		slog.Info("ContinuousComplianceWorker started", "interval", continuousComplianceInterval)

		evaluateContinuousCompliance(ctx, db)

		ticker := time.NewTicker(continuousComplianceInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				slog.Info("ContinuousComplianceWorker shutting down")
				return
			case <-ticker.C:
				evaluateContinuousCompliance(ctx, db)
			}
		}
	})
}

type openViolation struct {
	ViolationID   string          `json:"violation_id"`
	ViolationType string          `json:"violation_type"`
	PolicyID      *string         `json:"policy_id"`
	Details       json.RawMessage `json:"details"`
	controlRefs   []string
}

type obligationRow struct {
	ControlID  string          `json:"control_id"`
	ControlRef string          `json:"control_ref"`
	Status     string          `json:"status"`
	Metadata   json.RawMessage `json:"metadata"`
}

func evaluateContinuousCompliance(ctx context.Context, db continuousComplianceStore) {
	tenants, err := db.ListAllTenants()
	if err != nil {
		slog.Error("ContinuousComplianceWorker: list tenants failed", "error", err)
		return
	}
	demo := demoTenantSet()
	for _, t := range tenants {
		if ctx.Err() != nil {
			return
		}
		if t.TenantID != "" {
			isDemo := demo[strings.ToLower(t.TenantID)] || (t.TenantName != "" && demo[strings.ToLower(t.TenantName)])
			reconcileTenant(ctx, db, t.TenantID, time.Now().UTC(), !isDemo)
		}
	}
}

// demoTenantSet reads COMPLIANCE_DEMO_TENANTS (comma-separated tenant ids or
// names, case-insensitive). Demo tenants keep their seeded posture (GX-02
// decision 2026-10-09: reset real tenants only).
func demoTenantSet() map[string]bool {
	set := map[string]bool{}
	for _, s := range strings.Split(os.Getenv("COMPLIANCE_DEMO_TENANTS"), ",") {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			set[s] = true
		}
	}
	return set
}

// evidenceRow is a compl_evidence row as needed for status derivation.
type evidenceRow struct {
	ControlID   string   `json:"control_id"`
	ControlRefs []string `json:"control_refs"`
	Status      string   `json:"status"`
	ExpiresAt   string   `json:"expires_at"`
}

// invalidEvidenceStatus are evidence states that do not count as a passing test.
var invalidEvidenceStatus = map[string]bool{
	"REVOKED": true, "REJECTED": true, "INVALID": true, "FAILED": true, "EXPIRED": true, "SUPERSEDED": true,
}

// isDerivedObligation reports whether the worker owns the obligation's status:
// baseline seeds and obligations explicitly marked status_source=derived.
// Obligations a human manages (no marker) and WAIVED ones are never derived.
func isDerivedObligation(ob obligationRow, meta map[string]any) bool {
	if strings.EqualFold(ob.Status, "WAIVED") {
		return false
	}
	if src, _ := meta["status_source"].(string); src != "" {
		return strings.EqualFold(src, "derived")
	}
	seeded, _ := meta["seeded"].(bool)
	return seeded
}

// derivedStatus is COMPLIANT when at least one valid, unexpired evidence row
// is linked to the control (by control_id or control_refs), else NOT_STARTED.
// Open violations are applied afterwards by the flagging logic.
func derivedStatus(ob obligationRow, evidence []evidenceRow, now time.Time) (string, int) {
	n := 0
	for _, ev := range evidence {
		if invalidEvidenceStatus[strings.ToUpper(ev.Status)] {
			continue
		}
		if ev.ExpiresAt != "" {
			if exp, err := time.Parse(time.RFC3339Nano, ev.ExpiresAt); err == nil && !exp.After(now) {
				continue
			}
		}
		if evidenceLinked(ob, ev) {
			n++
		}
	}
	if n > 0 {
		return "COMPLIANT", n
	}
	return "NOT_STARTED", 0
}

func evidenceLinked(ob obligationRow, ev evidenceRow) bool {
	if ev.ControlID != "" && ev.ControlID == ob.ControlID {
		return true
	}
	for _, ref := range ev.ControlRefs {
		if ref != "" && (ref == ob.ControlID || (ob.ControlRef != "" && ref == ob.ControlRef)) {
			return true
		}
	}
	return false
}

// reconcileTenantObligations flags COMPLIANT obligations linked to an open
// violation and restores obligations the worker flagged once no linked
// violation remains open. Seeded / derived obligations get their status from
// linked evidence first (GX-02). It returns the number of obligations changed.
func reconcileTenantObligations(ctx context.Context, db continuousComplianceStore, tenantID string, now time.Time) int {
	return reconcileTenant(ctx, db, tenantID, now, true)
}

func reconcileTenant(ctx context.Context, db continuousComplianceStore, tenantID string, now time.Time, derive bool) int {
	var violations []openViolation
	if err := db.QueryRowsCompoundCtx(ctx, database.TblComplPolicyViolations, "violation_id,violation_type,policy_id,details",
		"tenant_id", tenantID, "status", "OPEN", &violations); err != nil {
		slog.Error("ContinuousComplianceWorker: open violations query failed", "tenant_id", tenantID, "error", err)
		return 0
	}
	for i := range violations {
		violations[i].controlRefs = detailControlRefs(violations[i].Details)
	}

	var obligations []obligationRow
	if err := db.QueryRowsCtx(ctx, database.TblComplObligations, "control_id,control_ref,status,metadata",
		"tenant_id", tenantID, &obligations); err != nil {
		slog.Error("ContinuousComplianceWorker: obligations query failed", "tenant_id", tenantID, "error", err)
		return 0
	}

	nowStr := now.Format(time.RFC3339)
	changed, unlinked := 0, map[string]bool{}
	for _, v := range violations {
		unlinked[v.ViolationID] = true
	}

	// Evidence is read lazily: only when some obligation's status is derived.
	var evidence []evidenceRow
	evidenceLoaded, evidenceOK := false, false
	loadEvidence := func() bool {
		if !evidenceLoaded {
			evidenceLoaded = true
			if err := db.QueryRowsCtx(ctx, database.TblComplEvidence, "control_id,control_refs,status,expires_at",
				"tenant_id", tenantID, &evidence); err != nil {
				// Unknown evidence → leave statuses as they are (never guess COMPLIANT or reset).
				slog.Error("ContinuousComplianceWorker: evidence query failed — derivation skipped", "tenant_id", tenantID, "error", err)
			} else {
				evidenceOK = true
			}
		}
		return evidenceOK
	}

	for _, ob := range obligations {
		meta := map[string]any{}
		if len(ob.Metadata) > 0 && string(ob.Metadata) != "null" {
			_ = json.Unmarshal(ob.Metadata, &meta)
		}
		var linked []string
		for _, v := range violations {
			if obligationLinked(ob, meta, v) {
				linked = append(linked, v.ViolationID)
				delete(unlinked, v.ViolationID)
			}
		}
		flag, flagged := meta[autoFlagKey].(map[string]any)

		derived := derive && isDerivedObligation(ob, meta)
		derivedDirty := false
		if derived && !flagged && loadEvidence() {
			if target, n := derivedStatus(ob, evidence, now); !strings.EqualFold(target, ob.Status) {
				meta["status_reason"] = map[string]any{"linked_evidence": n, "derived_at": nowStr}
				ob.Status = target
				derivedDirty = true
			}
		}

		switch {
		case len(linked) > 0 && strings.EqualFold(ob.Status, "COMPLIANT"):
			meta[autoFlagKey] = map[string]any{
				"prior_status":  ob.Status,
				"violation_ids": linked,
				"flagged_at":    nowStr,
			}
			if updateObligation(db, tenantID, ob.ControlID, "IN_PROGRESS", meta, nowStr) {
				changed++
				slog.Info("ContinuousComplianceWorker: obligation flagged by open violation",
					"tenant_id", tenantID, "control_id", ob.ControlID, "violation_ids", linked)
			}
		case len(linked) > 0 && flagged:
			if sameIDs(flag["violation_ids"], linked) {
				continue
			}
			ids := make([]any, len(linked))
			for i, id := range linked {
				ids[i] = id
			}
			flag["violation_ids"] = ids
			meta[autoFlagKey] = flag
			if updateObligation(db, tenantID, ob.ControlID, ob.Status, meta, nowStr) {
				changed++
			}
		case len(linked) == 0 && flagged:
			prior, _ := flag["prior_status"].(string)
			if prior == "" {
				prior = "COMPLIANT"
			}
			// Derived obligations return to what the evidence says now, not
			// to a status recorded before the violation.
			if derived && loadEvidence() {
				prior, _ = derivedStatus(ob, evidence, now)
			}
			delete(meta, autoFlagKey)
			if updateObligation(db, tenantID, ob.ControlID, prior, meta, nowStr) {
				changed++
				slog.Info("ContinuousComplianceWorker: obligation restored — linked violations closed",
					"tenant_id", tenantID, "control_id", ob.ControlID, "status", prior)
			}
		case derivedDirty:
			if updateObligation(db, tenantID, ob.ControlID, ob.Status, meta, nowStr) {
				changed++
				slog.Info("ContinuousComplianceWorker: obligation status derived from evidence",
					"tenant_id", tenantID, "control_id", ob.ControlID, "status", ob.Status)
			}
		}
	}
	if len(unlinked) > 0 {
		slog.Warn("ContinuousComplianceWorker: open violations not linked to any control",
			"tenant_id", tenantID, "count", len(unlinked))
	}
	return changed
}

func obligationLinked(ob obligationRow, meta map[string]any, v openViolation) bool {
	for _, ref := range v.controlRefs {
		if ref != "" && (ref == ob.ControlRef || ref == ob.ControlID) {
			return true
		}
	}
	if v.PolicyID != nil && *v.PolicyID != "" {
		if ids, ok := meta["policy_ids"].([]any); ok {
			for _, id := range ids {
				if s, _ := id.(string); s == *v.PolicyID {
					return true
				}
			}
		}
	}
	if v.ViolationType == "" {
		return false
	}
	if types, ok := meta["violation_types"].([]any); ok {
		for _, t := range types {
			if s, _ := t.(string); strings.EqualFold(s, v.ViolationType) {
				return true
			}
		}
	}
	if ref, _ := meta["evidence_ref"].(string); ref != "" {
		for _, want := range violationEvidenceRefs[strings.ToUpper(v.ViolationType)] {
			if ref == want {
				return true
			}
		}
	}
	return false
}

func detailControlRefs(details json.RawMessage) []string {
	if len(details) == 0 {
		return nil
	}
	var d struct {
		ControlRefs []string `json:"control_refs"`
		ControlRef  string   `json:"control_ref"`
	}
	if err := json.Unmarshal(details, &d); err != nil {
		return nil
	}
	if d.ControlRef != "" {
		return append(d.ControlRefs, d.ControlRef)
	}
	return d.ControlRefs
}

func updateObligation(db continuousComplianceStore, tenantID, controlID, status string, meta map[string]any, nowStr string) bool {
	if err := db.UpdateRowCompound(database.TblComplObligations, "control_id", controlID, "tenant_id", tenantID, map[string]any{
		"status":           status,
		"metadata":         meta,
		"last_assessed_at": nowStr,
		"updated_at":       nowStr,
	}); err != nil {
		slog.Warn("ContinuousComplianceWorker: obligation update failed",
			"tenant_id", tenantID, "control_id", controlID, "error", err)
		return false
	}
	return true
}

func sameIDs(stored any, linked []string) bool {
	list, _ := stored.([]any)
	if len(list) != len(linked) {
		return false
	}
	want := make(map[string]bool, len(linked))
	for _, id := range linked {
		want[id] = true
	}
	for _, v := range list {
		if s, _ := v.(string); !want[s] {
			return false
		}
	}
	return true
}
