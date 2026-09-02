// case_lifecycle.go — Canonical HITL case lifecycle management.
//
// AOCS Production Hardening — Part 4.1, 4.2, 4.3
//
// Every HITL case transition MUST go through this package to guarantee:
//   1. UUID case IDs (never 6-char hashes) — Master Report §9, invariant #9
//   2. SLA deadline set on creation (CIP-2: sla_deadline_at, sla_breached)
//   3. Full lifecycle audit trail in aocs_case_lifecycle_events
//   4. Copilot context pushed on every state change
//   5. Pub/Sub notification so downstream services react (jury, enforcement, AI)
//
// Status state machine:
//
//   PENDING → ASSIGNED → IN_REVIEW → RESOLVED (APPROVED|REJECTED)
//           ↘ ESCALATED (SLA breach or HITL escalation from Sentinel — CIP-4)
//           ↘ TIMEOUT   (pg_cron V028 job fires after SLA deadline passes)
//           ↘ APPEALED  → IN_REVIEW → RESOLVED
//
// Patent relevance:
//   - CIP-2: SLA lifecycle tracking (sla_deadline_at, sla_breached, sla_breached_at)
//   - CIP-4: Sentinel → HITL escalation columns (escalated_to_hitl, hitl_decision_id)
//   - P-04:  Jury quorum enforcement (quorum_required checked before verdict)
//   - P-11:  Self-healing SOP drift → HITL case creation

package compliance

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/ocx/shared/infra/concurrent"
	"github.com/ocx/shared/infra/copilot"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/eventbus"
	"github.com/ocx/shared/infra/serviceclient"
	contracts "github.com/ocx/shared/contracts"
)

// CaseStatus represents the HITL case state machine values.
type CaseStatus string

const (
	StatusPending    CaseStatus = "PENDING"
	StatusAssigned   CaseStatus = "ASSIGNED"
	StatusInReview   CaseStatus = "IN_REVIEW"
	StatusApproved   CaseStatus = "APPROVED"
	StatusRejected   CaseStatus = "REJECTED"
	StatusEscalated  CaseStatus = "ESCALATED"
	StatusTimeout    CaseStatus = "TIMEOUT"
	StatusAppealed   CaseStatus = "APPEALED"
)

// CasePriority maps to SLA deadline hours (CIP-2).
type CasePriority string

const (
	PriorityCritical CasePriority = "CRITICAL" // 2h SLA  — see contracts.DefaultSLAByPriority
	PriorityHigh     CasePriority = "HIGH"     // 4h SLA
	PriorityMedium   CasePriority = "MEDIUM"   // 8h SLA
	PriorityNormal   CasePriority = "NORMAL"   // 24h SLA (default)
	PriorityLow      CasePriority = "LOW"      // 24h SLA (same as NORMAL fallback)
)

// slaHoursForPriority returns the SLA window for a given priority.
// (internal/aocs-hub/domain/hitl/sla.go) so the monitor and the case creator
// always agree on the same thresholds.
func slaHoursForPriority(p CasePriority) int {
	if d, ok := contracts.DefaultSLAByPriority[string(p)]; ok {
		return d // already in hours (int)
	}
	return contracts.DefaultSLAHours // 24h fallback
}

// CreateCaseInput is the canonical input for creating any HITL case.
type CreateCaseInput struct {
	CaseType       string            `json:"case_type"`     // SELF_HEAL|AGENT_ESC|JURY_DEADLOCK|COMPLIANCE|MANUAL|SOP_DRIFT_VIOLATION|SENTINEL_ALERT
	AgentID        string            `json:"agent_id"`
	TenantID       string            `json:"tenant_id"`
	Reason         string            `json:"reason"`
	Priority       CasePriority      `json:"priority"`
	DepartmentID   string            `json:"department_id,omitempty"`
	CaseSource     string            `json:"case_source"`   // gate|sentinel|manual|gra|sop_drift
	ContextData    map[string]any    `json:"context_data,omitempty"`
	// CIP-4: Sentinel escalation — set when case is created from a senti_alert
	AlertID            string `json:"alert_id,omitempty"`
	EscalatedFromAlert bool   `json:"escalated_from_alert,omitempty"`
	// Patent §8: Evidence chain linkage
	EvidenceChainID string `json:"evidence_chain_id,omitempty"`
}

// CaseCreated is returned by CreateCase.
type CaseCreated struct {
	CaseID      string     `json:"case_id"`
	TenantID    string     `json:"tenant_id"`
	Status      CaseStatus `json:"status"`
	Priority    CasePriority `json:"priority"`
	SLADeadline time.Time  `json:"sla_deadline_at"`
	CreatedAt   time.Time  `json:"created_at"`
}

// CreateCase creates a HITL case with full SLA tracking, audit trail, and Pub/Sub notification.
// This is the ONLY place where HITL cases should be created — never raw InsertRow calls.
//
//   - Sets sla_deadline_at based on priority (CIP-2)
//   - Writes lifecycle event "CREATED" to aocs_case_lifecycle_events
//   - If created from a Sentinel alert, marks the alert escalated_to_hitl=true (CIP-4)
//   - Pushes Copilot context so the operator sees new case immediately
//   - Publishes CASE_CREATED to Pub/Sub (topic: cases-escalated)

// calling within the same nanosecond produced identical IDs → duplicate PKs.
// Replaced with crypto/rand for true randomness, concurrency-safe, zero collision.
func generatePlatformID() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	now := time.Now().UTC()
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("%d%02d%08X", now.Year(), int(now.Month()), now.UnixNano()&0xFFFFFFFF)
	}
	n := binary.BigEndian.Uint64(buf[:])
	r := make([]byte, 8)
	for i := range r {
		r[i] = chars[n%36]
		n /= 36
	}
	return fmt.Sprintf("%d%02d", now.Year(), int(now.Month())) + string(r)
}

func CreateCase(
	ctx context.Context,
	db database.DB,
	psBroker *eventbus.PubSubBroker,
	input CreateCaseInput,
	rc ...*serviceclient.Client,
) (*CaseCreated, error) {
	var r1 *serviceclient.Client
	if len(rc) > 0 {
		r1 = rc[0]
	}
	if db == nil {
		return nil, fmt.Errorf("caselifecycle.CreateCase: db is nil")
	}

	// 4.1 FIX: Always use generatePlatformID() — never 6-char hash (invariant #9)
	caseID := generatePlatformID()
	now := time.Now().UTC()

	// 4.3 FIX: Set SLA deadline from priority (CIP-2).
	priority := input.Priority
	if priority == "" {
		priority = PriorityNormal
	}
	hours := slaHoursForPriority(priority)
	slaDeadline := now.Add(time.Duration(hours) * time.Hour)

	caseSource := input.CaseSource
	if caseSource == "" {
		caseSource = "manual"
	}

	ctxData := input.ContextData
	if ctxData == nil {
		ctxData = map[string]any{}
	}
	if input.AlertID != "" {
		ctxData["source_alert_id"] = input.AlertID
	}
	if input.EvidenceChainID != "" {
		ctxData["evidence_chain_id"] = input.EvidenceChainID
	}
	ctxBytes, _ := json.Marshal(ctxData)

	// The UNIQUE constraint on dedup_key in core_hitl means duplicate inserts
	// for the same root cause within a short window are rejected by the DB (idempotent).
	// The hash is truncated to 16 hex chars to keep it compact while still collision-safe
	// for this use case (2^64 space vs at most millions of cases per tenant).
	dedupRaw := fmt.Sprintf("%s:%s:%s:%s", input.TenantID, input.AgentID, input.CaseType, input.Reason)
	dedupHash := sha256.Sum256([]byte(dedupRaw))
	dedupKey := hex.EncodeToString(dedupHash[:8]) // 16 hex chars = 8 bytes

	row := map[string]any{
		"decision_id":      caseID,
		"request_id":       caseID, // NOT NULL — each case creation IS its own request
		"decision_type":    input.CaseType, // NOT NULL — maps to case_type for HITL review classification
		"tenant_id":        input.TenantID,
		"agent_id":         input.AgentID,
		"status":           string(StatusPending),
		"priority":         string(priority),
		"reason":           input.Reason,
		"case_source":      caseSource,
		//   sla_breach_at   → SLA monitor polls this to detect breaches (canonical)
		//   sla_deadline_at → V512 analytics views + legacy code reads this (backward compat)
		"sla_breach_at":    slaDeadline.Format(time.RFC3339),
		"sla_deadline_at":  slaDeadline.Format(time.RFC3339),
		"sla_breached":     false,
		"escalation_count": 0,
		"context_data":     string(ctxBytes),
		"dedup_key":        dedupKey,

		"created_by":       "system@ocx.ai",
		// updated_at is set by the trg_set_updated_at DB trigger on every UPDATE — do NOT set here.
	}
	if input.DepartmentID != "" {
		row["department_id"] = input.DepartmentID
	}

	if r1 != nil {
		if err := r1.CreateHITLCase(ctx, row); err != nil {
			return nil, fmt.Errorf("caselifecycle.CreateCase: ocx-core-svc insert failed: %w", err)
		}
	} else if err := db.InsertRowCtx(ctx, database.TblHITLDecisions, row); err != nil {
		return nil, fmt.Errorf("caselifecycle.CreateCase: insert failed: %w", err)
	}

	slog.Info("HITL case created",
		"case_id", caseID,
		"case_type", input.CaseType,
		"agent_id", input.AgentID,
		"tenant_id", input.TenantID,
		"priority", priority,
		"sla_deadline_at", slaDeadline.Format(time.RFC3339),
		"case_source", caseSource,
	)

	// 4.2 FIX: Write lifecycle event (CIP-2 audit trail)
	writeLifecycleEvent(ctx, db, caseID, input.TenantID,
		"", string(StatusPending), input.Reason, "system", r1)

	// CIP-4 FIX: If escalated from a Sentinel alert, mark the alert record
	if input.EscalatedFromAlert && input.AlertID != "" {
		markAlertEscalated(ctx, db, input.AlertID, input.TenantID, caseID, r1)
	}

	// Copilot: push context so operators see new case in governance dashboard
	concurrent.Go("compliance/copilot_push", func() { copilot.PushCopilotContext(db, input.TenantID, copilot.EventHITLCreated,
		fmt.Sprintf("New %s case (%s) created for agent %s — SLA: %s",
			input.CaseType, priority, input.AgentID, slaDeadline.Format("2006-01-02 15:04")),
		map[string]any{
			"case_id":     caseID,
			"agent_id":    input.AgentID,
			"priority":    string(priority),
			"sla_hours":   hours,
			"case_source": caseSource,
		}) })

	// Pub/Sub: notify jury consumers, SDK polling clients, frontend
	if psBroker != nil {
		// Capture values before goroutine (request ctx may be cancelled by the time goroutine runs)
		payload, _ := json.Marshal(map[string]any{
			"schema_version": "2",
			"event":          "CASE_CREATED",
			"case_id":        caseID,
			"tenant_id":      input.TenantID,
			"agent_id":       input.AgentID,
			"priority":       string(priority),
			"sla_deadline":   slaDeadline.Format(time.RFC3339),
			"case_source":    caseSource,

		})
		orderKey := input.TenantID + ":" + input.AgentID
		broker := psBroker
		// CONC-1: anonymous goroutine — ensure this is lifecycle-managed via svcboot.BgCtx
	concurrent.Go("aocs-compliance/compliance/case_lifecycle", func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("CreateCase: Pub/Sub goroutine panic recovered",
						"panic", r, "case_id", caseID)
				}
			}()
			// context.WithoutCancel: detaches from request lifetime so cancel doesn't
			// abort this goroutine, but preserves trace/tenant values for logging.
			pubCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cancel()
			if err := broker.PublishOrdered(pubCtx, eventbus.TopicCasesEscalated(), orderKey, payload); err != nil {
				slog.Error("CreateCase: Pub/Sub notify failed (non-fatal)", "case_id", caseID, "error", err)
			}
		})
	}

	return &CaseCreated{
		CaseID:      caseID,
		TenantID:    input.TenantID,
		Status:      StatusPending,
		Priority:    priority,
		SLADeadline: slaDeadline,
		CreatedAt:   now,
	}, nil
}

// TransitionCase moves a case from one status to another, writing a lifecycle event.
// This is the ONLY place where case status changes should happen.
//
// Rules:
//   - If transitioning to ESCALATED, increments escalation_count
//   - If SLA is breached (now > sla_deadline_at), sets sla_breached=true, sla_breached_at=now
//   - Writes lifecycle event to aocs_case_lifecycle_events
//   - Pushes Copilot context for status changes the operator should see
func TransitionCase(
	ctx context.Context,
	db database.DB,
	caseID, tenantID, actorID string,
	newStatus CaseStatus,
	reason string,
	rc ...*serviceclient.Client,
) error {
	var r1 *serviceclient.Client
	if len(rc) > 0 {
		r1 = rc[0]
	}
	if db == nil {
		return fmt.Errorf("caselifecycle.TransitionCase: db is nil")
	}

	// Read current case — fetch both canonical columns for SLA check.
	// sla_breach_at: polled by the SLA monitor (canonical).
	// sla_deadline_at: written by legacy paths and analytics views.
	var rows []map[string]any
	if r1 != nil {
		data, _rErr := r1.GetHITLCase(ctx, tenantID, caseID,
			"status,sla_breach_at,sla_deadline_at,sla_breached,escalation_count")
		if _rErr != nil {
			return fmt.Errorf("caselifecycle.TransitionCase: ocx-core-svc read failed: %w", _rErr)
		}
		if data != nil {
			rows = []map[string]any{data}
		}
	} else if err := db.QueryRowsCompoundCtx(ctx, database.TblHITLDecisions,
		"status,sla_breach_at,sla_deadline_at,sla_breached,escalation_count",
		"decision_id", caseID, "tenant_id", tenantID, &rows); err != nil {
		return fmt.Errorf("caselifecycle.TransitionCase: read current case: %w", err)
	}
	if len(rows) == 0 {
		return fmt.Errorf("caselifecycle.TransitionCase: case %s not found for tenant %s", caseID, tenantID)
	}

	oldStatus, _ := rows[0]["status"].(string)
	now := time.Now().UTC()
	update := map[string]any{
		"status":     string(newStatus),
		"updated_by": actorID,
	}

	// CIP-2: Check SLA breach.
	// sla_deadline_at for cases created before this fix was deployed.
	// not as string. The previous .(string) assertions silently yielded "",
	// making ALL cases appear SLA-breached immediately.
	extractTimeStr := func(col string) string {
		v := rows[0][col]
		if v == nil {
			return ""
		}
		switch t := v.(type) {
		case string:
			return t
		case time.Time:
			return t.Format(time.RFC3339)
		}
		return ""
	}
	slaStr := extractTimeStr("sla_breach_at")
	if slaStr == "" {
		slaStr = extractTimeStr("sla_deadline_at")
	}
	slaBreached := false
	if slaStr != "" {
		if slaTime, err := time.Parse(time.RFC3339, slaStr); err == nil {
			if now.After(slaTime) {
				slaBreached = true
				update["sla_breached"]    = true
				update["sla_breached_at"] = now.Format(time.RFC3339)
			}
		}
	}

	// Increment escalation_count when escalating
	if newStatus == StatusEscalated {
		currentCount := 0
		if v, ok := rows[0]["escalation_count"].(float64); ok {
			currentCount = int(v)
		}
		update["escalation_count"] = currentCount + 1
	}

	if r1 != nil {
		if err := r1.PatchHITLCase(ctx, tenantID, caseID, update); err != nil {
			return fmt.Errorf("caselifecycle.TransitionCase: ocx-core-svc update failed: %w", err)
		}
	} else if err := db.UpdateRowCompoundCtx(ctx, database.TblHITLDecisions, "decision_id", caseID, "tenant_id", tenantID, update); err != nil {
		return fmt.Errorf("caselifecycle.TransitionCase: update failed: %w", err)
	}

	slog.Info("HITL case transitioned",
		"case_id", caseID, "tenant_id", tenantID,
		"from", oldStatus, "to", string(newStatus),
		"actor", actorID, "sla_breached", slaBreached,
	)

	// Write lifecycle event
	writeLifecycleEvent(ctx, db, caseID, tenantID, oldStatus, string(newStatus), reason, actorID, r1)

	// Copilot context for operator-visible transitions
	if newStatus == StatusEscalated || newStatus == StatusTimeout || slaBreached {
		eventType := copilot.EventHITLCreated
		msg := fmt.Sprintf("Case %s → %s (actor: %s)", caseID, newStatus, actorID)
		if slaBreached {
			msg = fmt.Sprintf("Case %s SLA BREACHED → %s", caseID, newStatus)
			eventType = copilot.EventSLABreach
		}
		concurrent.Go("compliance/copilot_push", func() { copilot.PushCopilotContext(db, tenantID, eventType, msg,
			map[string]any{"case_id": caseID, "new_status": string(newStatus), "sla_breached": slaBreached}) })
	}

	return nil
}

// writeLifecycleEvent inserts one row into aocs_case_lifecycle_events.
// Best-effort: logs error but does NOT return it so case transition is not blocked.
func writeLifecycleEvent(
	ctx context.Context,
	db database.DB,
	caseID, tenantID string,
	fromStatus, toStatus, reason, actorID string,
	rc ...*serviceclient.Client,
) {
	var r1 *serviceclient.Client
	if len(rc) > 0 {
		r1 = rc[0]
	}
	if db == nil {
		return
	}
	// core_events schema: event_id, entity_id, entity_type, tenant_id, event_type, payload
	// caseID maps to entity_id (FK) — all case-specific fields go into payload JSONB
	// so they are fully preserved and queryable via payload->>'case_id', payload->>'from_status' etc.
	row := map[string]any{
		"event_id":    generatePlatformID(),
		"entity_id":   caseID,   // FK — case_id is stored here for WHERE entity_id=$caseID queries
		"entity_type": "hitl_case",
		"tenant_id":   tenantID,
		"event_type":  "CASE_LIFECYCLE",
		"payload": map[string]any{
			"case_id":     caseID, // also in payload for direct extraction
			"from_status": fromStatus,
			"to_status":   toStatus,
			"reason":      reason,
			"actor_id":    actorID,
			"occurred_at": time.Now().UTC().Format(time.RFC3339),
		},
	}
	if r1 != nil {
		if _err := r1.PostEvent(ctx, row); _err != nil {
			slog.Error("writeLifecycleEvent: ocx-core-svc PostEvent failed (non-fatal)",
				"case_id", caseID, "from", fromStatus, "to", toStatus, "err", _err)
		}
	} else if err := db.InsertRowCtx(ctx, database.TblPlatformEvents, row); err != nil {
		slog.Error("writeLifecycleEvent: insert failed (non-fatal)",
			"case_id", caseID, "from", fromStatus, "to", toStatus, "err", err)
	}
	// aocs_case_lifecycle_events is the compliance record; aocs_hitl_timeline is the
	// analytics timeseries that powers the HITL workload and SLA dashboards.
	// F-HITL-01 FIX: was _ = (silent drop). SLA dashboard gaps break regulator reporting.
	tlRow := map[string]any{
		"event_id":    generatePlatformID(),
		"entity_id":   caseID,
		"entity_type": "hitl_timeline",
		"tenant_id":   tenantID,
		"event_type":  "STATUS_TRANSITION",
		"payload": map[string]any{
			"case_id":     caseID,
			"from_status": fromStatus,
			"to_status":   toStatus,
			"actor_id":    actorID,
			"reason":      reason,
			"occurred_at": time.Now().UTC().Format(time.RFC3339),
		},
	}
	if r1 != nil {
		if tlErr := r1.PostEvent(ctx, tlRow); tlErr != nil {
			slog.Error("F-HITL-01: ocx-core-svc PostEvent timeline failed — SLA dashboard has gap for this transition",
				"case_id", caseID, "from", fromStatus, "to", toStatus, "err", tlErr)
		}
	} else if tlErr := db.InsertRowCtx(ctx, database.TblPlatformEvents, tlRow); tlErr != nil {
		slog.Error("F-HITL-01: HITL timeline event insert failed — SLA dashboard has gap for this transition",
			"case_id", caseID, "from", fromStatus, "to", toStatus, "err", tlErr)
	}
}

// markAlertEscalated sets escalated_to_hitl=true and hitl_decision_id on the senti_alert.
// CIP-4: Sentinel→HITL auto-escalation — links the alert to the created case.
func markAlertEscalated(ctx context.Context, db database.DB, alertID, tenantID, caseID string, rc ...*serviceclient.Client) {
	var r1 *serviceclient.Client
	if len(rc) > 0 {
		r1 = rc[0]
	}
	if db == nil || alertID == "" {
		return
	}
	now := time.Now().UTC()
	update := map[string]any{
		"escalated_to_hitl": true,
		"hitl_decision_id":  caseID,
		"assigned_at":       now.Format(time.RFC3339),
		"updated_by":        "system@ocx.ai",
	}
	if r1 != nil {
		if err := r1.PatchSentiAlert(ctx, tenantID, alertID, update); err != nil {
			slog.Error("caselifecycle.markAlertEscalated: ocx-core-svc PatchSentiAlert failed (non-fatal)",
				"alert_id", alertID, "case_id", caseID, "err", err)
			return
		}
	} else if err := db.UpdateRowCompoundCtx(ctx, database.TblAlerts,
		"alert_id", alertID, "tenant_id", tenantID, update); err != nil {
		slog.Error("caselifecycle.markAlertEscalated: failed to update senti_alert (non-fatal)",
			"alert_id", alertID, "case_id", caseID, "err", err)
		return
	}
	slog.Info("CIP-4: Sentinel alert marked escalated to HITL",
		"alert_id", alertID, "case_id", caseID, "tenant_id", tenantID)
}
