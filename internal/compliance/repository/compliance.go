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
	"github.com/jackc/pgx/v5/pgxpool"
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

// NewComplianceRepository creates a repository backed by the given PGX pool.
func NewComplianceRepository(pool *pgxpool.Pool) *ComplianceRepository {
	return &ComplianceRepository{db: pool}
}

// NewComplianceRepositoryFromQuerier creates a repository from any ComplianceQuerier.
// Intended for unit tests that substitute a fake querier.
func NewComplianceRepositoryFromQuerier(q ComplianceQuerier) *ComplianceRepository {
	return &ComplianceRepository{db: q}
}

// ListReports returns compliance reports for a tenant.
func (r *ComplianceRepository) ListReports(ctx context.Context, tenantID string) ([]ComplianceReport, error) {
	const q = `
		SELECT id, tenant_id, report_type, status, generated_at, summary, created_at, updated_at
		FROM core_compliance_reports
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
		SELECT id, tenant_id, report_type, status, generated_at, summary, created_at, updated_at
		FROM core_compliance_reports
		WHERE tenant_id = $1 AND id = $2`

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
	const q = `
		INSERT INTO core_compliance_reports
		  (id, tenant_id, report_type, status, summary, created_at, updated_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING id, tenant_id, report_type, status, generated_at, summary, created_at, updated_at`

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
// updated_at is trigger-managed; updated_by stamps the actor.
func (r *ComplianceRepository) MarkReportGenerated(ctx context.Context, id string, summary map[string]any) error {
	const q = `
		UPDATE core_compliance_reports
		SET status = 'GENERATED', generated_at=NOW(), summary=$1, updated_by='system.compliance'
		WHERE id=$2`
	_, err := r.db.Exec(ctx, q, summary, id)
	if err != nil {
		return fmt.Errorf("compliance.MarkReportGenerated: %w", err)
	}
	return nil
}

// ListViolations returns compliance violation events for a tenant.
func (r *ComplianceRepository) ListViolations(ctx context.Context, tenantID string, limit int) ([]ViolationEvent, error) {
	const q = `
		SELECT id, tenant_id, agent_id, policy_id, severity, description, evidence, remediated, created_at
		FROM core_compliance
		WHERE tenant_id = $1
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
	const q = `
		INSERT INTO core_compliance
		  (id, tenant_id, agent_id, policy_id, severity, description, evidence, remediated, created_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,false,NOW(),$8)`
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
	const q = `UPDATE core_compliance SET remediated=true WHERE tenant_id=$1 AND id=$2`
	_, err := r.db.Exec(ctx, q, tenantID, id)
	if err != nil {
		return fmt.Errorf("compliance.MarkRemediated: %w", err)
	}
	return nil
}
