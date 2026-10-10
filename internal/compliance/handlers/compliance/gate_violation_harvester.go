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

// gateHarvestDiscoverPred selects tenants with a blocking decision or an
// override inside the catch-up window (superset of what harvestTenant reads).
const gateHarvestDiscoverPred = `w.verdict IN ('BLOCK','ESC') AND w.created_at > $1`

func runGateHarvest(ctx context.Context, db gateHarvestStore, now time.Time) {
	floor := now.Add(-gateHarvestCatchUp)
	// Tenants with recent blocking decisions; overrides (rare) are covered by
	// a second discovery on the event log.
	tenants := map[string]bool{}
	for _, d := range []struct{ table, pred string }{
		{"core_gate_decisions", gateHarvestDiscoverPred},
		{"core_events", `w.event_type = 'gate.verdict_overridden' AND w.created_at > $1`},
	} {
		ids, err := database.ListTenantsWithWork(ctx, db, gateHarvestWorker, d.table, d.pred, floor)
		if err != nil {
			if ctx.Err() == nil {
				slog.Error("GateViolationHarvester: tenant discovery failed", "table", d.table, "error", err)
			}
			continue
		}
		for _, id := range ids {
			tenants[id] = true
		}
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
		res, hErr = harvestTenant(ctx, pgxHarvestOps{tx: tx}, tenantID, now)
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

type pgxHarvestOps struct{ tx pgx.Tx }

const gateHarvestLockSQL = `SELECT pg_advisory_xact_lock(hashtext('compl_gate_harvest:' || $1))`

// gateHarvestInsertSQL records the tenant's new blocking decisions.
//
//	$1 tenant_id  $2 catch-up floor  $3 overlap (seconds)  $4 batch size
//
// Watermark: newest harvested decision − overlap, never before the floor.
// Sources: BLOCK/ESC decisions since the watermark, plus decisions an
// operator overrode since the watermark. The effective verdict is the
// override's when present.
var gateHarvestInsertSQL = `
WITH wm AS (
    SELECT GREATEST(COALESCE(max(detected_at) - $3::int * interval '1 second', $2::timestamptz),
                    $2::timestamptz) AS since
      FROM ` + database.TblComplPolicyViolations + `
     WHERE tenant_id = $1 AND source_tx_id IS NOT NULL
), cand AS (
    SELECT d.decision_id
      FROM ` + database.TblCoreGateDecisions + ` d, wm
     WHERE d.tenant_id = $1 AND d.verdict IN ('BLOCK','ESC') AND d.created_at > wm.since
    UNION
    SELECT e.entity_id
      FROM ` + database.TblCoreEvents + ` e, wm
     WHERE e.tenant_id = $1 AND e.event_type = 'gate.verdict_overridden' AND e.created_at > wm.since
       AND e.entity_id IS NOT NULL
), src AS (
    SELECT d.tx_id, d.agent_id, d.tool_name, NULLIF(d.policy_id, '') AS policy_id, d.action_class,
           d.trust_score, d.anomaly_score, d.execution_id, d.hitl_decision_id, d.created_at,
           d.verdict AS gate_verdict, d.payload->'override' AS override,
           COALESCE(NULLIF(d.payload->'override'->>'verdict', ''), d.verdict) AS eff_verdict,
           COALESCE(d.verdict_reason, '') AS reason
      FROM ` + database.TblCoreGateDecisions + ` d
      JOIN cand c ON c.decision_id = d.decision_id
     WHERE d.tenant_id = $1
)
INSERT INTO ` + database.TblComplPolicyViolations + ` AS v
       (tenant_id, policy_id, policy_name, agent_id, execution_id, violation_type, severity,
        description, evidence, details, status, detected_at, source_tx_id)
SELECT $1, s.policy_id, p.name, s.agent_id, s.execution_id,
       CASE s.eff_verdict WHEN 'BLOCK' THEN '` + dcompliance.ViolationTypeGateBlock + `' ELSE '` + dcompliance.ViolationTypeGateEscalation + `' END,
       CASE WHEN s.eff_verdict = 'BLOCK' AND s.action_class = 'CLASS_A' THEN 'CRITICAL'
            WHEN s.eff_verdict = 'BLOCK' THEN 'HIGH'
            ELSE 'MEDIUM' END,
       format('Gate %s: agent %s, tool %s — %s',
              CASE s.eff_verdict WHEN 'BLOCK' THEN 'blocked' ELSE 'escalated' END,
              s.agent_id, s.tool_name, COALESCE(NULLIF(s.reason, ''), 'no reason recorded')),
       jsonb_strip_nulls(jsonb_build_object(
           'source', 'core_gate_decisions', 'tx_id', s.tx_id, 'gate_verdict', s.gate_verdict,
           'override', s.override, 'trust_score', s.trust_score, 'anomaly_score', s.anomaly_score,
           'hitl_decision_id', s.hitl_decision_id)),
       jsonb_strip_nulls(jsonb_build_object(
           'tool_name', s.tool_name, 'action_class', s.action_class, 'reason', NULLIF(s.reason, ''),
           -- GX-16: controls the policy declares it enforces (policy metadata
           -- control_refs) travel with the violation so continuous compliance
           -- can link it, snapshotted as they were when the gate refused.
           'control_refs', CASE WHEN jsonb_typeof(p.metadata->'control_refs') = 'array'
                                AND jsonb_array_length(p.metadata->'control_refs') > 0
                               THEN p.metadata->'control_refs' END)),
       'OPEN', s.created_at, s.tx_id
  FROM src s
  LEFT JOIN ` + database.TblCorePolicies + ` p ON p.policy_id = s.policy_id AND p.tenant_id = $1
 WHERE s.eff_verdict IN ('BLOCK','ESC')
   AND s.reason <> 'KILL_SWITCH_ACTIVE'
   AND s.reason NOT LIKE 'hitl_lock_active%'
   AND s.reason NOT LIKE 'internal pipeline error%'
   AND s.reason NOT LIKE 'HITL case not persisted%'
   -- Skip what is already recorded BEFORE the LIMIT: otherwise a batch of
   -- already-harvested rows inside the overlap would stall the watermark.
   AND NOT EXISTS (SELECT 1 FROM ` + database.TblComplPolicyViolations + ` x
                    WHERE x.tenant_id = $1 AND x.source_tx_id = s.tx_id)
 ORDER BY s.created_at
 LIMIT $4
ON CONFLICT (tenant_id, source_tx_id) WHERE source_tx_id IS NOT NULL DO NOTHING
RETURNING v.violation_id, COALESCE(v.agent_id, ''), COALESCE(v.policy_id, ''), COALESCE(v.policy_name, ''),
          COALESCE(v.details->>'tool_name', ''), v.severity, v.violation_type, COALESCE(v.description, ''),
          v.detected_at`

func (o pgxHarvestOps) lockTenant(ctx context.Context, tenantID string) error {
	_, err := o.tx.Exec(ctx, gateHarvestLockSQL, tenantID)
	return err
}

func (o pgxHarvestOps) insertViolations(ctx context.Context, tenantID string, floor time.Time) ([]harvestedViolation, error) {
	rows, err := o.tx.Query(ctx, gateHarvestInsertSQL, tenantID, floor, int(gateHarvestOverlap/time.Second), gateHarvestBatch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []harvestedViolation
	for rows.Next() {
		var v harvestedViolation
		if err := rows.Scan(&v.ViolationID, &v.AgentID, &v.PolicyID, &v.PolicyName, &v.ToolName,
			&v.Severity, &v.Type, &v.Description, &v.DetectedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// gateHarvestWaiveSQL waives open gate violations whose decision an operator
// overrode to ALLOW. $1 tenant_id.
var gateHarvestWaiveSQL = `
UPDATE ` + database.TblComplPolicyViolations + ` v
   SET status = 'WAIVED', resolved_at = now(), updated_at = now(),
       details = COALESCE(v.details, '{}'::jsonb) || jsonb_build_object('waived_by_override', d.payload->'override')
  FROM ` + database.TblCoreGateDecisions + ` d
 WHERE v.tenant_id = $1 AND v.source_tx_id IS NOT NULL AND v.status IN ('OPEN', 'ACKNOWLEDGED')
   AND d.tenant_id = $1 AND d.tx_id = v.source_tx_id
   AND d.payload->'override'->>'verdict' = 'ALLOW'`

func (o pgxHarvestOps) waiveOverridden(ctx context.Context, tenantID string) (int, error) {
	tag, err := o.tx.Exec(ctx, gateHarvestWaiveSQL, tenantID)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
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
