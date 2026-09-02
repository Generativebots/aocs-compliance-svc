// Package compliance — named request and row types.
package compliance

import (
	"github.com/ocx/shared/types"
)

// CaseCreateRequest is the body for POST /compliance/cases.
type CaseCreateRequest struct {
	CaseType     string         `json:"case_type"`
	AgentID	string	`json:"agent_id" validate:"required"`
	Reason	string	`json:"reason" validate:"required"`
	DepartmentID string         `json:"department_id,omitempty"`
	Priority     string         `json:"priority,omitempty"` // LOW | MEDIUM | HIGH | CRITICAL
	ContextData  map[string]any `json:"context_data,omitempty"`
}

// EscalationRequest is the body for POST /compliance/cases/:id/escalate.
type EscalationRequest struct {
	CaseID	string	`json:"case_id" validate:"required"`
	AgentID	string	`json:"agent_id" validate:"required"`
	Reason	string	`json:"reason" validate:"required"`
	EvidenceURL string `json:"evidence_url,omitempty"`
}

// CaseCommentRequest is the body for POST /compliance/cases/:id/comments.
type CaseCommentRequest struct {
	Body            string `json:"body"`
	ParentCommentID string `json:"parent_comment_id,omitempty"`
}

// CaseDismissRequest is the body for POST /compliance/cases/:id/dismiss.
type CaseDismissRequest struct {
	Reason	string	`json:"reason" validate:"required"`
	JurorID string `json:"juror_id,omitempty"`
}

// CaseLinkerRequest is the body for POST /compliance/cases/:id/link.
type CaseLinkerRequest struct {
	ParentCaseID      string   `json:"parent_case_id"`
	AdditionalReasons []string `json:"additional_reasons,omitempty"`
}

// ComplianceBatchReportRequest is the body for POST /compliance/reports/batch.
type ComplianceBatchReportRequest struct {
	AgentIDs []string `json:"agent_ids"`
	Period   string   `json:"period"` // YYYY-MM
}

// ComplianceSingleReportRequest is the body for POST /compliance/reports/single.
type ComplianceSingleReportRequest struct {
	AgentID	string	`json:"agent_id" validate:"required"`
	Period  string `json:"period"` // YYYY-MM
}

// DLPFindingRow is the DB projection for DLP finding reads.
type DLPFindingRow struct {
	ID         string `json:"id"`
	TenantID   string `json:"tenant_id"`
	AgentID    string `json:"agent_id"`
	Severity   string `json:"severity"` // LOW | MEDIUM | HIGH | CRITICAL
	PIITypes   string `json:"pii_types"`
	Status     string `json:"status"` // OPEN | MITIGATED | FALSE_POSITIVE
	DetectedAt string `json:"detected_at"`
}

// ComplianceSummaryRow is the DB projection for compliance summary reads.
type ComplianceSummaryRow struct {
	TenantID         string  `json:"tenant_id"`
	ComplianceScore  float64 `json:"compliance_score"`
	OpenCases        int     `json:"open_cases"`
	ResolvedCases    int     `json:"resolved_cases"`
	CriticalFindings int     `json:"critical_findings"`
	PeriodStart      string  `json:"period_start"`
	PeriodEnd        string  `json:"period_end"`
}

// AddCaseCommentRequest is the request body for HandleCreateCaseComment. (3 fields)
type AddCaseCommentRequest struct {
	Body       string `json:"body"`
	AuthorID   string `json:"author_id"`
	IsInternal bool   `json:"is_internal"` // true = internal note only (not visible to agent)
}

// ReassignCaseRequest is the request body for HandleReassignCase. (4 fields)
type ReassignCaseRequest struct {
	FromDeptID      string `json:"from_dept_id"`
	ToDeptID        string `json:"to_dept_id"`
	Reason	string	`json:"reason" validate:"required"`
	EscalationLevel int    `json:"escalation_level"`
}

// CreateCaseRequest is the request body for HandleCreateCase. (6 fields)
type CreateCaseRequest struct {
	CaseType     string         `json:"case_type"`
	AgentID	string	`json:"agent_id" validate:"required"`
	Reason	string	`json:"reason" validate:"required"`
	DepartmentID string         `json:"department_id,omitempty"`
	Priority     string         `json:"priority,omitempty"`
	ContextData  map[string]any `json:"context_data,omitempty"`
}

// CreateComplianceRegionRequest is the request body for HandleCreateComplianceRegion. (7 fields)
type CreateComplianceRegionRequest struct {
	RegionCode           string        `json:"region_code"`
	RegionName           string        `json:"region_name"`
	Countries            []interface{} `json:"countries"`
	RiskWeight           float64       `json:"risk_weight"`
	Description          string        `json:"description"`
	ApplicableFrameworks []interface{} `json:"applicable_frameworks"`
	IsActive             *bool         `json:"is_active"`
}

// DepartmentRouteRequest is the request body for HandleRouteDepartment. (6 fields)
type DepartmentRouteRequest struct {
	CaseType       string `json:"case_type"`
	PolicyCategory string `json:"policy_category"`
	RuleType       string `json:"rule_type"`
	Description    string `json:"description"`
	AgentID	string	`json:"agent_id" validate:"required"`
	CheckCapacity  *bool  `json:"check_capacity"`
}

// CreateDisputeRequest is the request body for HandleCreateDispute. (4 fields)
type CreateDisputeRequest struct {
	CaseID	string	`json:"case_id" validate:"required"`
	AgentID	string	`json:"agent_id" validate:"required"`
	Reason	string	`json:"reason" validate:"required"`
	EvidenceURL string `json:"evidence_url,omitempty"`
}

// CreateDLPFindingRequest is the request body for HandleCreateDLPFinding. (7 fields)
type CreateDLPFindingRequest struct {
	RuleName    string         `json:"rule_name"`
	Severity    string         `json:"severity"`
	DataType    string         `json:"data_type"`
	Description string         `json:"description"`
	Source	string	`json:"source" validate:"required"`	// SCAN | MANUAL | ALERT
	AgentID     string         `json:"agent_id,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// CasesSubmitJuryVoteRequest is the request body for HandleCasesSubmitJuryVote. (8 fields)
type CasesSubmitJuryVoteRequest struct {
	CaseID	string	`json:"case_id" validate:"required"`
	VoterID    string  `json:"voter_id"`
	MemberID   string  `json:"member_id"` // alias
	Decision   string  `json:"decision"`
	Verdict    string  `json:"verdict"` // alias
	Confidence float64 `json:"confidence"`
	Rationale  string  `json:"rationale"`
	PolicyID	string	`json:"policy_id" validate:"required"`	// accepted, not required
}

// UpdateSIEMConfigRequest is the request body for HandleUpdateSIEMConfig. (4 fields)
type UpdateSIEMConfigRequest struct {
	WebhookURL   string `json:"webhook_url"`
	Format       string `json:"format"`
	Enabled      bool   `json:"enabled"`
	SecretHeader string `json:"secret_header,omitempty"`
}

// VerifyProofInclusionRequest is the request body for HandleVerifyProofInclusion. (5 fields)
type VerifyProofInclusionRequest struct {
	ProofHash     string                       `json:"proof_hash"`
	ChainRoot     string                       `json:"chain_root"`
	InclusionPath []types.MerkleProofStep `json:"inclusion_path"`
	AgentID	string	`json:"agent_id" validate:"required"`
	Period        string                       `json:"period"`
}
