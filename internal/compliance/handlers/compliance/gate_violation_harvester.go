package compliance

// gate_violation_harvester.go — gate decisions → compliance violations → cases (GX-15).
//
// The gate (ocx-core-svc) records every verdict in its decision log
// (lv_core_gate_decisions). Until now nothing turned a refusal into compliance
// evidence: compl_policy_violations, and the cases built on it, stayed empty
// however many actions the gate blocked.
//
// This worker reads the log per tenant (D3) and:
//   - records each BLOCK / ESC decision as one compl_policy_violations row
//     (source_tx_id = the gate tx_id; unique per tenant, so runs are
//     idempotent and any number of replicas may run it);
//   - groups the new HIGH/CRITICAL violations by agent + policy (or tool when
//     no policy matched) and opens one compliance case per group, or adds them
//     to the group's case that is still OPEN/INVESTIGATING. ESC decisions are
//     MEDIUM: the gate already opened a HITL review for each, a second
//     (compliance) case would duplicate it;
//   - honours operator overrides: BLOCK→ALLOW waives the open violation,
//     ALLOW→BLOCK records one.
//
// Not violations: operator holds (kill switch, retries during an open HITL
// lock — the decision that opened the hold was recorded), internal pipeline
// errors (a gate fault, already a HITL case) and ERROR / ORPHANED decisions
// (no decision was made; nothing executed).
//
// Compliance is a paid module: the worker records for every tenant (evidence
// must exist from day one), reads are licence-gated by the API as before.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	dcompliance "github.com/ocx/compliance/internal/compliance/domain/compliance"
	"github.com/ocx/shared/infra/concurrent"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/serviceclient"
)

const (
	gateHarvestWorker   = "compliance-gate-violation-harvester"
	gateHarvestInterval = time.Minute
	// gateHarvestOverlap re-reads decisions this far behind the newest
	// harvested one: a decision row is created PENDING and settled seconds
	// later (the pending reconciler orphans it after 60s).
	gateHarvestOverlap = 15 * time.Minute
	// gateHarvestCatchUp bounds how far back a tenant with no harvested
	// violation yet (first run, or only excluded decisions) is read.
	gateHarvestCatchUp = 7 * 24 * time.Hour
	// gateHarvestBatch caps the violations recorded per tenant transaction;
	// the watermark advances, so a backlog drains over successive batches.
	// Kept small: each new HIGH/CRITICAL group costs ~3 round trips (find /
	// open-or-extend / link). With 1000 the first live run (93 decisions,
	// remote DB) overran the 15 s default tx timeout, rolled back, and
	// retried the same batch every minute without ever committing.
	gateHarvestBatch = 50
	// gateHarvestTxBudget is each tenant transaction's own deadline (the
	// shared default is PGX_TX_TIMEOUT_MS = 15 s).
	gateHarvestTxBudget = 40 * time.Second
	// gateHarvestRunBudget bounds one run (all tenants, all batches) so it
	// ends before the next tick.
	gateHarvestRunBudget = 50 * time.Second
)

// gateHarvestStore is the subset of *database.SupabaseClient the worker uses.
type gateHarvestStore interface {
	database.TenantLister
	RunTenantTx(ctx context.Context, tenantID string, fn database.TxFn) error
}

// StartGateViolationHarvester runs the harvester every gateHarvestInterval
// until ctx is cancelled.
func StartGateViolationHarvester(ctx context.Context, db gateHarvestStore) {
	if db == nil {
		slog.Warn("GateViolationHarvester: db is nil — worker not started; gate refusals will not become compliance violations")
		return
	}
	concurrent.GoSupervised(ctx, "aocs-compliance/gate_violation_harvester", func(ctx context.Context) {
		slog.Info("GateViolationHarvester started", "interval", gateHarvestInterval)
		runGateHarvest(ctx, db, time.Now().UTC())
		ticker := time.NewTicker(gateHarvestInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case t := <-ticker.C:
				runGateHarvest(ctx, db, t.UTC())
			}
		}
	})
}

// gateFeedClient is the gate decision feed served by ocx-core-svc (the decision log is core's).
type gateFeedClient interface {
	GateHarvestTenants(ctx context.Context, since time.Time) ([]string, error)
	GateHarvest(ctx context.Context, tenantID string, since time.Time, limit int) ([]serviceclient.GateHarvestRow, error)
	GateOverrides(ctx context.Context, tenantID string, txIDs []string) (map[string]json.RawMessage, error)
}

var gateFeed gateFeedClient

// SetGateFeedClient wires the core client the harvester reads gate decisions from. Without it the
// harvester has no source and records nothing (logged each run).
func SetGateFeedClient(c *serviceclient.Client) {
	if c == nil {
		gateFeed = nil
		return
	}
	gateFeed = c
}

func runGateHarvest(ctx context.Context, db gateHarvestStore, now time.Time) {
	feed := gateFeed
	if feed == nil {
		slog.Warn("GateViolationHarvester: no core gate feed configured — gate refusals are not being recorded")
		return
	}
	floor := now.Add(-gateHarvestCatchUp)
	// Tenants with recent blocking decisions or overrides, discovered by core.
	tenants := map[string]bool{}
	found, err := feed.GateHarvestTenants(ctx, floor)
	if err != nil {
		if ctx.Err() == nil {
			slog.Error("GateViolationHarvester: tenant discovery failed", "error", err)
		}
		return
	}
	for _, id := range found {
		tenants[id] = true
	}
	ids := make([]string, 0, len(tenants))
	for id := range tenants {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	runCtx, cancelRun := context.WithTimeout(ctx, gateHarvestRunBudget)
	defer cancelRun()
	for _, tenantID := range ids {
		for runCtx.Err() == nil {
			res, err := harvestTenantBatch(runCtx, db, tenantID, now)
			if err != nil {
				if ctx.Err() == nil {
					slog.Error("GateViolationHarvester: tenant run failed — retried next tick",
						"tenant_id", tenantID, "error", err)
				}
				break
			}
			if res.recorded > 0 || res.waived > 0 {
				slog.Info("GateViolationHarvester: gate decisions recorded as violations",
					"tenant_id", tenantID, "recorded", res.recorded, "waived", res.waived,
					"cases_opened", res.casesOpened, "cases_extended", res.casesExtended)
			}
			if res.recorded < gateHarvestBatch {
				break // backlog drained for this tenant
			}
		}
	}
}

// harvestTenantBatch runs one committed batch for a tenant under its own deadline.
func harvestTenantBatch(ctx context.Context, db gateHarvestStore, tenantID string, now time.Time) (gateHarvestResult, error) {
	txCtx, cancel := context.WithTimeout(ctx, gateHarvestTxBudget)
	defer cancel()
	var res gateHarvestResult
	err := db.RunTenantTx(txCtx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var hErr error
		res, hErr = harvestTenant(ctx, pgxHarvestOps{tx: tx, feed: gateFeed}, tenantID, now)
		return hErr
	})
	return res, err
}

// ── Orchestration (DB access behind harvestOps) ────────────────────────────

type harvestedViolation struct {
	ViolationID string
	AgentID     string
	PolicyID    string
	PolicyName  string
	ToolName    string
	Severity    string
	Type        string
	Description string
	DetectedAt  time.Time
}

type openCase struct {
	CaseID   string
	Severity string
}

// violationGroup is the new HIGH/CRITICAL violations of one agent + policy/tool.
type violationGroup struct {
	Key        string
	AgentID    string
	PolicyID   string
	PolicyName string
	ToolName   string
	Severity   string // highest in the group
	Violations []harvestedViolation
}

type harvestOps interface {
	lockTenant(ctx context.Context, tenantID string) error
	insertViolations(ctx context.Context, tenantID string, floor time.Time) ([]harvestedViolation, error)
	waiveOverridden(ctx context.Context, tenantID string) (int, error)
	findOpenCase(ctx context.Context, tenantID, groupKey string) (*openCase, error)
	createCase(ctx context.Context, tenantID string, g violationGroup) (string, error)
	extendCase(ctx context.Context, tenantID string, c openCase, g violationGroup) error
	linkViolations(ctx context.Context, tenantID, caseID string, violationIDs []string) error
	refreshOpenCounts(ctx context.Context, tenantID string) (int, error)
}

type gateHarvestResult struct {
	recorded, waived, casesOpened, casesExtended int
}

// harvestTenant runs one harvest for tenantID inside a tenant transaction.
// Every step returns its error: the transaction rolls back and the next run
// redoes the work (nothing is half-recorded).
func harvestTenant(ctx context.Context, ops harvestOps, tenantID string, now time.Time) (gateHarvestResult, error) {
	var res gateHarvestResult
	// One harvester per tenant at a time across replicas: two concurrent runs
	// would each see "no open case" and open two cases for one group.
	if err := ops.lockTenant(ctx, tenantID); err != nil {
		return res, fmt.Errorf("lock tenant: %w", err)
	}
	waived, err := ops.waiveOverridden(ctx, tenantID)
	if err != nil {
		return res, fmt.Errorf("waive overridden violations: %w", err)
	}
	res.waived = waived
	recorded, err := ops.insertViolations(ctx, tenantID, now.Add(-gateHarvestCatchUp))
	if err != nil {
		return res, fmt.Errorf("record violations: %w", err)
	}
	res.recorded = len(recorded)
	for _, g := range groupForCases(recorded) {
		ids := make([]string, len(g.Violations))
		for i, v := range g.Violations {
			ids[i] = v.ViolationID
		}
		c, err := ops.findOpenCase(ctx, tenantID, g.Key)
		if err != nil {
			return res, fmt.Errorf("find open case %s: %w", g.Key, err)
		}
		caseID := ""
		if c != nil {
			if err := ops.extendCase(ctx, tenantID, *c, g); err != nil {
				return res, fmt.Errorf("extend case %s: %w", c.CaseID, err)
			}
			caseID = c.CaseID
			res.casesExtended++
		} else {
			if caseID, err = ops.createCase(ctx, tenantID, g); err != nil {
				return res, fmt.Errorf("open case for %s: %w", g.Key, err)
			}
			if caseID == "" {
				return res, errors.New("open case: no case_id returned")
			}
			res.casesOpened++
		}
		if err := ops.linkViolations(ctx, tenantID, caseID, ids); err != nil {
			return res, fmt.Errorf("link violations to case %s: %w", caseID, err)
		}
	}
	// violation_count is the case's history (never decreases); the open count
	// is recomputed so a waived/resolved violation lowers it. Runs every time
	// so resolutions made elsewhere (UI, API) are picked up too; it only
	// writes rows whose count changed.
	if _, err := ops.refreshOpenCounts(ctx, tenantID); err != nil {
		return res, fmt.Errorf("refresh open violation counts: %w", err)
	}
	return res, nil
}

// severityRank orders compl_* severities.
var severityRank = map[string]int{"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

func maxSeverity(a, b string) string {
	if severityRank[strings.ToUpper(b)] > severityRank[strings.ToUpper(a)] {
		return strings.ToUpper(b)
	}
	return strings.ToUpper(a)
}

// caseGroupKey identifies a violation group: one agent refused by one policy,
// or — when no policy matched — on one tool.
func caseGroupKey(v harvestedViolation) string {
	subject := "policy:" + v.PolicyID
	if v.PolicyID == "" {
		subject = "tool:" + v.ToolName
	}
	return "gate|" + v.AgentID + "|" + subject
}

// groupForCases groups HIGH/CRITICAL violations; order is deterministic.
func groupForCases(vs []harvestedViolation) []violationGroup {
	byKey := map[string]*violationGroup{}
	var keys []string
	for _, v := range vs {
		if severityRank[strings.ToUpper(v.Severity)] < severityRank["HIGH"] {
			continue
		}
		k := caseGroupKey(v)
		g, ok := byKey[k]
		if !ok {
			g = &violationGroup{Key: k, AgentID: v.AgentID, PolicyID: v.PolicyID, PolicyName: v.PolicyName,
				ToolName: v.ToolName, Severity: strings.ToUpper(v.Severity)}
			byKey[k] = g
			keys = append(keys, k)
		}
		g.Severity = maxSeverity(g.Severity, v.Severity)
		g.Violations = append(g.Violations, v)
	}
	sort.Strings(keys)
	out := make([]violationGroup, 0, len(keys))
	for _, k := range keys {
		g := byKey[k]
		sort.Slice(g.Violations, func(i, j int) bool { return g.Violations[i].DetectedAt.Before(g.Violations[j].DetectedAt) })
		out = append(out, *g)
	}
	return out
}

// caseTitle names the case after what was refused.
func caseTitle(g violationGroup) string {
	subject := "tool " + g.ToolName
	if g.PolicyID != "" {
		name := g.PolicyName
		if name == "" {
			name = g.PolicyID
		}
		subject = "policy " + name
	}
	return fmt.Sprintf("Gate refused agent %s (%s)", g.AgentID, subject)
}

// ── SQL (pgx) ──────────────────────────────────────────────────────────────

type pgxHarvestOps struct {
	tx   pgx.Tx
	feed gateFeedClient
}

const gateHarvestLockSQL = `SELECT pg_advisory_xact_lock(hashtext('compl_gate_harvest:' || $1))`

// gateHarvestWatermarkSQL: the tenant's harvest watermark — newest harvested decision minus the
// overlap, never before the floor. $1 tenant_id  $2 catch-up floor  $3 overlap (seconds).
const gateHarvestWatermarkSQL = `
SELECT GREATEST(COALESCE(max(detected_at) - $3::int * interval '1 second', $2::timestamptz),
                $2::timestamptz)
  FROM ` + database.TblComplPolicyViolations + `
 WHERE tenant_id = $1 AND source_tx_id IS NOT NULL`

const gateHarvestRecordedSQL = `
SELECT source_tx_id FROM ` + database.TblComplPolicyViolations + `
 WHERE tenant_id = $1 AND source_tx_id = ANY($2::text[])`

// gateHarvestPolicySQL reads the policy name and declared control_refs from the policy projection
// (compl_core_projection), not from core's policy table.
const gateHarvestPolicySQL = `
SELECT COALESCE(payload->>'name', ''), payload->'metadata'->'control_refs'
  FROM compl_core_projection
 WHERE tenant_id = $1 AND kind = 'policy' AND entity_id = $2`

// gateHarvestInsertRowSQL records one blocking decision. Unique per (tenant, source_tx_id), so
// reruns and concurrent replicas are idempotent.
const gateHarvestInsertRowSQL = `
INSERT INTO ` + database.TblComplPolicyViolations + ` AS v
       (tenant_id, policy_id, policy_name, agent_id, execution_id, violation_type, severity,
        description, evidence, details, status, detected_at, source_tx_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10::jsonb, 'OPEN', $11, $12)
ON CONFLICT (tenant_id, source_tx_id) WHERE source_tx_id IS NOT NULL DO NOTHING
RETURNING v.violation_id, COALESCE(v.agent_id, ''), COALESCE(v.policy_id, ''), COALESCE(v.policy_name, ''),
          COALESCE(v.details->>'tool_name', ''), v.severity, v.violation_type, COALESCE(v.description, ''),
          v.detected_at`

func (o pgxHarvestOps) lockTenant(ctx context.Context, tenantID string) error {
	_, err := o.tx.Exec(ctx, gateHarvestLockSQL, tenantID)
	return err
}

// gateExcluded: operator holds, internal pipeline errors and no-decision verdicts are not
// violations (the decision that opened a hold was recorded; a gate fault is already a HITL case).
func gateExcluded(reason string) bool {
	return reason == "KILL_SWITCH_ACTIVE" ||
		strings.HasPrefix(reason, "hitl_lock_active") ||
		strings.HasPrefix(reason, "internal pipeline error") ||
		strings.HasPrefix(reason, "HITL case not persisted")
}

// gateEffectiveVerdict is the operator override's verdict when present, else the gate's.
func gateEffectiveVerdict(d serviceclient.GateHarvestRow) string {
	if len(d.Override) > 0 && string(d.Override) != "null" {
		var ov struct {
			Verdict string `json:"verdict"`
		}
		if json.Unmarshal(d.Override, &ov) == nil && ov.Verdict != "" {
			return ov.Verdict
		}
	}
	return d.Verdict
}

func gateSeverity(eff string, actionClass *string) string {
	switch {
	case eff == "BLOCK" && actionClass != nil && *actionClass == "CLASS_A":
		return "CRITICAL"
	case eff == "BLOCK":
		return "HIGH"
	}
	return "MEDIUM"
}

// stripNil mirrors jsonb_strip_nulls for the top-level object (typed nil pointers and JSON
// null values are dropped).
func stripNil(m map[string]any) []byte {
	b, _ := json.Marshal(m)
	var kv map[string]json.RawMessage
	if json.Unmarshal(b, &kv) != nil {
		return b
	}
	for k, v := range kv {
		if string(v) == "null" {
			delete(kv, k)
		}
	}
	out, _ := json.Marshal(kv)
	return out
}

func (o pgxHarvestOps) insertViolations(ctx context.Context, tenantID string, floor time.Time) ([]harvestedViolation, error) {
	if o.feed == nil {
		return nil, errors.New("no core gate feed configured")
	}
	var since time.Time
	if err := o.tx.QueryRow(ctx, gateHarvestWatermarkSQL, tenantID, floor, int(gateHarvestOverlap/time.Second)).Scan(&since); err != nil {
		return nil, fmt.Errorf("watermark: %w", err)
	}
	decisions, err := o.feed.GateHarvest(ctx, tenantID, since, 0)
	if err != nil {
		return nil, fmt.Errorf("fetch gate decisions from core: %w", err)
	}
	// Decisions that may become violations; skip what is already recorded BEFORE the batch cap
	// so a window of already-harvested rows cannot stall the watermark.
	var cand []serviceclient.GateHarvestRow
	var txIDs []string
	for _, d := range decisions {
		eff := gateEffectiveVerdict(d)
		if (eff != "BLOCK" && eff != "ESC") || gateExcluded(d.Reason) || d.TxID == "" {
			continue
		}
		cand = append(cand, d)
		txIDs = append(txIDs, d.TxID)
	}
	recorded := map[string]bool{}
	if len(txIDs) > 0 {
		rows, qerr := o.tx.Query(ctx, gateHarvestRecordedSQL, tenantID, txIDs)
		if qerr != nil {
			return nil, fmt.Errorf("recorded lookup: %w", qerr)
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, err
			}
			recorded[id] = true
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	type policyInfo struct {
		name string
		refs json.RawMessage
	}
	policies := map[string]policyInfo{}
	var out []harvestedViolation
	for _, d := range cand {
		if recorded[d.TxID] {
			continue
		}
		if len(out) >= gateHarvestBatch {
			break
		}
		detectedAt, perr := time.Parse(time.RFC3339Nano, d.CreatedAt)
		if perr != nil {
			return nil, fmt.Errorf("decision %s created_at: %w", d.TxID, perr)
		}
		var pol policyInfo
		if d.PolicyID != nil && *d.PolicyID != "" {
			var ok bool
			if pol, ok = policies[*d.PolicyID]; !ok {
				var refs []byte
				switch qerr := o.tx.QueryRow(ctx, gateHarvestPolicySQL, tenantID, *d.PolicyID).Scan(&pol.name, &refs); {
				case qerr == nil:
					pol.refs = refs
				case errors.Is(qerr, pgx.ErrNoRows):
				default:
					return nil, fmt.Errorf("policy lookup: %w", qerr)
				}
				policies[*d.PolicyID] = pol
			}
		}
		eff := gateEffectiveVerdict(d)
		vtype, verb := dcompliance.ViolationTypeGateEscalation, "escalated"
		if eff == "BLOCK" {
			vtype, verb = dcompliance.ViolationTypeGateBlock, "blocked"
		}
		reason := d.Reason
		if reason == "" {
			reason = "no reason recorded"
		}
		desc := fmt.Sprintf("Gate %s: agent %s, tool %s — %s", verb, d.AgentID, d.ToolName, reason)
		evidence := stripNil(map[string]any{
			"source": "core_gate_decisions", "tx_id": d.TxID, "gate_verdict": d.Verdict,
			"override": d.Override, "trust_score": d.TrustScore, "anomaly_score": d.AnomalyScore,
			"hitl_decision_id": d.HitlDecisionID,
		})
		var reasonOrNil any
		if d.Reason != "" {
			reasonOrNil = d.Reason
		}
		details := map[string]any{"tool_name": d.ToolName, "action_class": d.ActionClass, "reason": reasonOrNil}
		// GX-16: controls the policy declares it enforces travel with the violation, snapshotted
		// as they were when the gate refused.
		var refs []json.RawMessage
		if json.Unmarshal(pol.refs, &refs) == nil && len(refs) > 0 {
			details["control_refs"] = pol.refs
		}
		var policyName any
		if pol.name != "" {
			policyName = pol.name
		}
		sev := gateSeverity(eff, d.ActionClass)
		var v harvestedViolation
		err := o.tx.QueryRow(ctx, gateHarvestInsertRowSQL, tenantID, d.PolicyID, policyName, d.AgentID,
			d.ExecutionID, vtype, sev, desc, string(evidence), string(stripNil(details)), detectedAt, d.TxID,
		).Scan(&v.ViolationID, &v.AgentID, &v.PolicyID, &v.PolicyName, &v.ToolName,
			&v.Severity, &v.Type, &v.Description, &v.DetectedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			continue // recorded concurrently
		}
		if err != nil {
			return nil, fmt.Errorf("insert violation for %s: %w", d.TxID, err)
		}
		out = append(out, v)
	}
	return out, nil
}

// gateHarvestOpenTxSQL lists the tenant's open gate violations (by decision tx id) whose decision
// may since have been overridden. $1 tenant_id.
const gateHarvestOpenTxSQL = `
SELECT source_tx_id FROM ` + database.TblComplPolicyViolations + `
 WHERE tenant_id = $1 AND source_tx_id IS NOT NULL AND status IN ('OPEN', 'ACKNOWLEDGED')
 ORDER BY detected_at DESC
 LIMIT 1000`

// gateHarvestWaiveSQL waives one open gate violation whose decision an operator overrode to
// ALLOW. $1 tenant_id  $2 source_tx_id  $3 override record.
const gateHarvestWaiveSQL = `
UPDATE ` + database.TblComplPolicyViolations + ` v
   SET status = 'WAIVED', resolved_at = now(), updated_at = now(),
       details = COALESCE(v.details, '{}'::jsonb) || jsonb_build_object('waived_by_override', $3::jsonb)
 WHERE v.tenant_id = $1 AND v.source_tx_id = $2 AND v.status IN ('OPEN', 'ACKNOWLEDGED')`

func (o pgxHarvestOps) waiveOverridden(ctx context.Context, tenantID string) (int, error) {
	if o.feed == nil {
		return 0, errors.New("no core gate feed configured")
	}
	rows, err := o.tx.Query(ctx, gateHarvestOpenTxSQL, tenantID)
	if err != nil {
		return 0, err
	}
	var txIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		txIDs = append(txIDs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(txIDs) == 0 {
		return 0, nil
	}
	overrides, err := o.feed.GateOverrides(ctx, tenantID, txIDs)
	if err != nil {
		return 0, fmt.Errorf("fetch overrides from core: %w", err)
	}
	waived := 0
	for _, id := range txIDs {
		ov, ok := overrides[id]
		if !ok {
			continue
		}
		if len(ov) == 0 {
			ov = json.RawMessage("null")
		}
		tag, err := o.tx.Exec(ctx, gateHarvestWaiveSQL, tenantID, id, string(ov))
		if err != nil {
			return waived, err
		}
		waived += int(tag.RowsAffected())
	}
	return waived, nil
}

var gateHarvestFindCaseSQL = `
SELECT case_id, severity FROM ` + database.TblComplianceComplianceCases + `
 WHERE tenant_id = $1 AND status IN ('OPEN', 'INVESTIGATING') AND metadata ? 'gate_group'
   AND metadata->>'gate_group' = $2
 ORDER BY created_at DESC
 LIMIT 1
 FOR UPDATE`

func (o pgxHarvestOps) findOpenCase(ctx context.Context, tenantID, groupKey string) (*openCase, error) {
	var c openCase
	err := o.tx.QueryRow(ctx, gateHarvestFindCaseSQL, tenantID, groupKey).Scan(&c.CaseID, &c.Severity)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// gateHarvestCreateCaseSQL opens a case for a violation group. dedup_key is
// globally unique; the first violation id keeps it unique per case while the
// open-case lookup goes by metadata.gate_group.
var gateHarvestCreateCaseSQL = `
INSERT INTO ` + database.TblComplianceComplianceCases + `
       (tenant_id, agent_id, policy_id, violated_policy_id, violation_id, case_type, status, severity,
        title, description, dedup_key, metadata)
VALUES ($1, NULLIF($2, ''), NULLIF($3, ''), NULLIF($3, ''), $4, 'COMPLIANCE', 'OPEN', $5,
        $6, $7, $8,
        jsonb_strip_nulls(jsonb_build_object(
            'gate_group', $9::text, 'source', 'gate_violation_harvester',
            'tool_name', NULLIF($10, ''), 'violation_count', $11::int, 'open_violation_count', $11::int,
            'first_detected_at', $12::timestamptz, 'last_detected_at', $13::timestamptz)))
RETURNING case_id`

func (o pgxHarvestOps) createCase(ctx context.Context, tenantID string, g violationGroup) (string, error) {
	first, last := g.Violations[0], g.Violations[len(g.Violations)-1]
	var caseID string
	err := o.tx.QueryRow(ctx, gateHarvestCreateCaseSQL,
		tenantID, g.AgentID, g.PolicyID, first.ViolationID, g.Severity,
		caseTitle(g), last.Description, "gate:"+first.ViolationID,
		g.Key, g.ToolName, len(g.Violations), first.DetectedAt, last.DetectedAt,
	).Scan(&caseID)
	return caseID, err
}

var gateHarvestExtendCaseSQL = `
UPDATE ` + database.TblComplianceComplianceCases + `
   SET severity = $3,
       description = $4,
       metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
           'violation_count', COALESCE((metadata->>'violation_count')::int, 0) + $5::int,
           'last_detected_at', $6::timestamptz),
       updated_at = now()
 WHERE tenant_id = $1 AND case_id = $2`

func (o pgxHarvestOps) extendCase(ctx context.Context, tenantID string, c openCase, g violationGroup) error {
	last := g.Violations[len(g.Violations)-1]
	tag, err := o.tx.Exec(ctx, gateHarvestExtendCaseSQL,
		tenantID, c.CaseID, maxSeverity(c.Severity, g.Severity), last.Description, len(g.Violations), last.DetectedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("case %s not found", c.CaseID)
	}
	return nil
}

var gateHarvestLinkSQL = `
UPDATE ` + database.TblComplPolicyViolations + `
   SET case_id = $2, updated_at = now()
 WHERE tenant_id = $1 AND violation_id = ANY($3::text[])`

func (o pgxHarvestOps) linkViolations(ctx context.Context, tenantID, caseID string, violationIDs []string) error {
	tag, err := o.tx.Exec(ctx, gateHarvestLinkSQL, tenantID, caseID, violationIDs)
	if err != nil {
		return err
	}
	if int(tag.RowsAffected()) != len(violationIDs) {
		return fmt.Errorf("linked %d of %d violations", tag.RowsAffected(), len(violationIDs))
	}
	return nil
}

// gateHarvestRefreshOpenSQL sets metadata.open_violation_count on the tenant's
// open harvester cases from the violations still OPEN/ACKNOWLEDGED. Only rows
// whose count changed are written. $1 tenant_id.
var gateHarvestRefreshOpenSQL = `
UPDATE ` + database.TblComplianceComplianceCases + ` c
   SET metadata = COALESCE(c.metadata, '{}'::jsonb) || jsonb_build_object('open_violation_count', s.n),
       updated_at = now()
  FROM (SELECT oc.case_id,
               count(v.violation_id) FILTER (WHERE v.status IN ('OPEN', 'ACKNOWLEDGED'))::int AS n
          FROM ` + database.TblComplianceComplianceCases + ` oc
          LEFT JOIN ` + database.TblComplPolicyViolations + ` v
                 ON v.tenant_id = $1 AND v.case_id = oc.case_id
         WHERE oc.tenant_id = $1 AND oc.status IN ('OPEN', 'INVESTIGATING') AND oc.metadata ? 'gate_group'
         GROUP BY oc.case_id) s
 WHERE c.tenant_id = $1 AND c.case_id = s.case_id
   AND (c.metadata->>'open_violation_count')::int IS DISTINCT FROM s.n`

func (o pgxHarvestOps) refreshOpenCounts(ctx context.Context, tenantID string) (int, error) {
	tag, err := o.tx.Exec(ctx, gateHarvestRefreshOpenSQL, tenantID)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}
