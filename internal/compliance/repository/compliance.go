// Package repository provides the data access layer for aocs-compliance.
// All SQL lives here; handlers operate on typed methods.
package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ComplianceQuerier is the minimal pgx surface used by ComplianceRepository.
// pgxpool.Pool satisfies it; tests can substitute a fake implementation.
type ComplianceQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// ComplianceReport represents a compliance audit report.
type ComplianceReport struct {
	ID          string         `json:"id"`
	TenantID    string         `json:"tenant_id"`
	ReportType  string         `json:"report_type"`
	Status      string         `json:"status"`
	GeneratedAt *time.Time     `json:"generated_at,omitempty"`
	Summary     map[string]any `json:"summary,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// ViolationEvent represents a compliance violation record.
type ViolationEvent struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	AgentID     string    `json:"agent_id"`
	PolicyID    string    `json:"policy_id"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Evidence    any       `json:"evidence,omitempty"`
	Remediated  bool      `json:"remediated"`
	CreatedAt   time.Time `json:"created_at"`
}

// ComplianceRepository encapsulates SQL for compliance-related tables.
type ComplianceRepository struct {
	db ComplianceQuerier
}

// ListReports returns compliance reports for a tenant.
func (r *ComplianceRepository) ListReports(ctx context.Context, tenantID string) ([]ComplianceReport, error) {
	const q = `
		SELECT report_id, tenant_id, report_type, status, generated_at, summary, created_at, updated_at
		FROM compl_reports
		WHERE tenant_id = $1
		ORDER BY created_at DESC`

	rows, err := r.db.Query(ctx, q, tenantID)
	if err != nil {
		return nil, fmt.Errorf("compliance.ListReports: %w", err)
	}
	defer rows.Close()

	var reports []ComplianceReport
	for rows.Next() {
		var cr ComplianceReport
		if err := rows.Scan(
			&cr.ID, &cr.TenantID, &cr.ReportType, &cr.Status, &cr.GeneratedAt,
			&cr.Summary, &cr.CreatedAt, &cr.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("compliance.ListReports scan: %w", err)
		}
		reports = append(reports, cr)
	}
	if reports == nil {
		reports = []ComplianceReport{}
	}
	return reports, rows.Err()
}

// GetReportByID returns a single compliance report.
func (r *ComplianceRepository) GetReportByID(ctx context.Context, tenantID, id string) (*ComplianceReport, error) {
	const q = `
		SELECT report_id, tenant_id, report_type, status, generated_at, summary, created_at, updated_at
		FROM compl_reports
		WHERE tenant_id = $1 AND report_id = $2`

	var cr ComplianceReport
	err := r.db.QueryRow(ctx, q, tenantID, id).Scan(
		&cr.ID, &cr.TenantID, &cr.ReportType, &cr.Status, &cr.GeneratedAt,
		&cr.Summary, &cr.CreatedAt, &cr.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("compliance.GetReportByID: not found")
		}
		return nil, fmt.Errorf("compliance.GetReportByID: %w", err)
	}
	return &cr, nil
}

// CreateReport inserts a new compliance report.
func (r *ComplianceRepository) CreateReport(ctx context.Context, cr ComplianceReport) (*ComplianceReport, error) {
	now := time.Now().UTC()
	// compl_reports: PK report_id (gen_id default when empty), period_start/period_end
	// NOT NULL — default to the trailing 30-day window ending now.
	const q = `
		INSERT INTO compl_reports
		  (report_id, tenant_id, report_type, status, summary, period_start, period_end,
		   created_at, updated_at, generated_by)
		VALUES (COALESCE(NULLIF($1,''), gen_id('')), $2, $3, COALESCE(NULLIF($4,''),'DRAFT'), $5,
		        $6::timestamptz - INTERVAL '30 days', $6::timestamptz, $6, $7, $8)
		RETURNING report_id, tenant_id, report_type, status, generated_at, summary, created_at, updated_at`

	summary := cr.Summary
	if summary == nil {
		summary = map[string]any{} // NOT NULL column — coerce nil to empty object
	}
	var out ComplianceReport
	err := r.db.QueryRow(ctx, q,
		cr.ID, cr.TenantID, cr.ReportType, cr.Status, summary, now, now, "system.compliance",
	).Scan(
		&out.ID, &out.TenantID, &out.ReportType, &out.Status, &out.GeneratedAt,
		&out.Summary, &out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("compliance.CreateReport: %w", err)
	}
	return &out, nil
}

// MarkReportGenerated marks a report as generated with a summary.
// updated_at is trigger-managed; generated_by stamps the actor.
func (r *ComplianceRepository) MarkReportGenerated(ctx context.Context, id string, summary map[string]any) error {
	const q = `
		UPDATE compl_reports
		SET status = 'GENERATED', generated_at=NOW(), summary=$1, generated_by='system.compliance'
		WHERE report_id=$2`
	_, err := r.db.Exec(ctx, q, summary, id)
	if err != nil {
		return fmt.Errorf("compliance.MarkReportGenerated: %w", err)
	}
	return nil
}

// ListViolations returns compliance violation events for a tenant.
func (r *ComplianceRepository) ListViolations(ctx context.Context, tenantID string, limit int) ([]ViolationEvent, error) {
	const q = `
		SELECT case_id, tenant_id, COALESCE(agent_id,''), COALESCE(policy_id,''), severity,
		       COALESCE(description, title), metadata->'evidence',
		       status IN ('RESOLVED','CLOSED'), created_at
		FROM compl_records
		WHERE tenant_id = $1 AND case_type = 'VIOLATION'
		ORDER BY created_at DESC
		LIMIT $2`

	rows, err := r.db.Query(ctx, q, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("compliance.ListViolations: %w", err)
	}
	defer rows.Close()

	var violations []ViolationEvent
	for rows.Next() {
		var v ViolationEvent
		if err := rows.Scan(
			&v.ID, &v.TenantID, &v.AgentID, &v.PolicyID, &v.Severity,
			&v.Description, &v.Evidence, &v.Remediated, &v.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("compliance.ListViolations scan: %w", err)
		}
		violations = append(violations, v)
	}
	if violations == nil {
		violations = []ViolationEvent{}
	}
	return violations, rows.Err()
}

// RecordViolation inserts a new violation event.
func (r *ComplianceRepository) RecordViolation(ctx context.Context, v ViolationEvent) error {
	// compl_records: PK case_id; evidence is kept in metadata.evidence and the
	// creating actor in metadata.created_by (no dedicated columns).
	const q = `
		INSERT INTO compl_records
		  (case_id, tenant_id, agent_id, policy_id, case_type, severity, status, title, description, metadata, created_at)
		VALUES (COALESCE(NULLIF($1,''), gen_id('')), $2, NULLIF($3,''), NULLIF($4,''), 'VIOLATION',
		        COALESCE(NULLIF(UPPER($5),''),'MEDIUM'), 'OPEN', LEFT(COALESCE(NULLIF($6,''),'Policy violation'), 200), $6,
		        jsonb_build_object('evidence', $7::jsonb, 'created_by', $8::text), NOW())`
	_, err := r.db.Exec(ctx, q,
		v.ID, v.TenantID, v.AgentID, v.PolicyID, v.Severity, v.Description, v.Evidence, "system.compliance",
	)
	if err != nil {
		return fmt.Errorf("compliance.RecordViolation: %w", err)
	}
	return nil
}

// MarkRemediated marks a violation as remediated.
func (r *ComplianceRepository) MarkRemediated(ctx context.Context, tenantID, id string) error {
	const q = `UPDATE compl_records
		SET status='RESOLVED', resolved_at=NOW(), resolved_by='system.compliance'
		WHERE tenant_id=$1 AND case_id=$2`
	_, err := r.db.Exec(ctx, q, tenantID, id)
	if err != nil {
		return fmt.Errorf("compliance.MarkRemediated: %w", err)
	}
	return nil
}
