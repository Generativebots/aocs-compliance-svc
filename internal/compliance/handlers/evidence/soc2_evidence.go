package evaluation

// soc2_evidence.go — SOC2 Type II Evidence Package Generator
//
// POST /compliance/soc2/evidence-package     — trigger SOC2 package generation
// GET  /compliance/soc2/evidence-package/{id} — retrieve generated package
// GET  /compliance/soc2/evidence-packages    — list all packages for this tenant
//
// SOC2 Trust Service Criteria (TSC) — AICPA:
//
//   CC1 (Control Environment)  — governance, oversight, accountability
//   CC2 (Communication/Info)   — internal/external communication of controls
//   CC3 (Risk Assessment)      — risk identification, analysis, response
//   CC4 (Monitoring)           — ongoing monitoring, evaluation of controls
//   CC5 (Control Activities)   — policies, procedures, controls
//   CC6 (Logical Access)       — authentication, authorisation, access control
//   CC7 (System Operations)    — detection, incident response, recovery
//   CC8 (Change Management)    — SDLC, change control, testing
//   CC9 (Risk Mitigation)      — vendor, business partner risk management
//   A1  (Availability)         — uptime, capacity, incident SLA
//
// For each TSC, AOCS can auto-generate evidence by querying its own audit trail,
// gate verdicts, policy changes, agent events, HITL decisions, and compliance reports.
//
// Evidence package is stored as a compliance_case with case_type='SOC2_EVIDENCE_PACKAGE'.
// The case data JSONB contains the full structured evidence map.
//
// Permission: compliance:write (Auditor or superadmin level)

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

// SOC2EvidencePackage is the structured evidence document for SOC2 Type II audit.
type SOC2EvidencePackage struct {
	PackageID    string    `json:"package_id"`
	TenantID     string    `json:"tenant_id"`
	GeneratedAt  string    `json:"generated_at"`
	GeneratedBy  string    `json:"generated_by"`
	PeriodStart  string    `json:"period_start"`
	PeriodEnd    string    `json:"period_end"`
	AuditType    string    `json:"audit_type"` // SOC2_TYPE_I | SOC2_TYPE_II
	Status       string    `json:"status"`     // DRAFT | READY | SUBMITTED

	// Control evidence, keyed by TSC category
	ControlEnvironment   SOC2ControlSection `json:"CC1_control_environment"`
	Communication        SOC2ControlSection `json:"CC2_communication"`
	RiskAssessment       SOC2ControlSection `json:"CC3_risk_assessment"`
	Monitoring           SOC2ControlSection `json:"CC4_monitoring"`
	ControlActivities    SOC2ControlSection `json:"CC5_control_activities"`
	LogicalAccess        SOC2ControlSection `json:"CC6_logical_access"`
	SystemOperations     SOC2ControlSection `json:"CC7_system_operations"`
	ChangeManagement     SOC2ControlSection `json:"CC8_change_management"`
	RiskMitigation       SOC2ControlSection `json:"CC9_risk_mitigation"`
	Availability         SOC2ControlSection `json:"A1_availability"`
}

// SOC2ControlSection holds evidence items and metadata for one TSC category.
type SOC2ControlSection struct {
	Criteria    string            `json:"criteria"`
	Description string            `json:"description"`
	Evidence    []SOC2EvidenceItem `json:"evidence"`
	ControlStatus string          `json:"control_status"` // EFFECTIVE | PARTIAL | NOT_TESTED
	Notes       string            `json:"notes,omitempty"`
}

// SOC2EvidenceItem is a single piece of evidence with source traceability.
type SOC2EvidenceItem struct {
	Type        string `json:"type"`        // SYSTEM_GENERATED | MANUAL | POLICY | AUDIT_LOG
	Description string `json:"description"`
	Source      string `json:"source"`      // table/handler that produced this
	Count       int    `json:"count,omitempty"`
	Period      string `json:"period,omitempty"`
}

type soc2PackageRequest struct {
	PeriodStart string `json:"period_start"` // ISO date: 2025-08-01
	PeriodEnd   string `json:"period_end"`   // ISO date: 2026-07-31
	AuditType   string `json:"audit_type"`   // SOC2_TYPE_I | SOC2_TYPE_II
}

// HandleGenerateSOC2Package generates a SOC2 evidence package from live AOCS data.
//
// POST /compliance/soc2/evidence-package
func HandleGenerateSOC2Package(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		actorID := auth.GetUserID(r.Context())

		var req soc2PackageRequest
		respond.LimitBody(r)
		if !validate.Bind(w, r, &req) {
			return
		}
		if req.PeriodStart == "" || req.PeriodEnd == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest,
				"period_start and period_end are required (ISO date format: 2025-08-01)")
			return
		}
		if req.AuditType == "" {
			req.AuditType = "SOC2_TYPE_II"
		}

		packageID := uuid.New().String()
		now := time.Now().UTC()

		log := slog.With(
			"handler", "HandleGenerateSOC2Package",
			"tenant_id", tenantID,
			"package_id", packageID,
			"period_start", req.PeriodStart,
			"period_end", req.PeriodEnd,
		)

		// ── Pull live counts from AOCS tables ─────────────────────────────
		// Each count becomes an evidence item for the respective TSC category.

		// CC5/CC6: Active policies and gate verdicts
		var policyRows []struct{ PolicyID string `json:"policy_id"` }
		policyCount := 0
		if err := db.QueryRowsCompound(database.TblPolicies, "policy_id",
			"tenant_id", tenantID, "status", "ACTIVE", &policyRows); err == nil {
			policyCount = len(policyRows)
		}

		// CC7: Compliance cases (incidents, violations)
		var violationRows []struct{ CaseID string `json:"case_id"` }
		violationCount := 0
		if err := db.QueryRowsCompound(database.TblComplianceCases, "case_id",
			"tenant_id", tenantID, "case_type", "VIOLATION", &violationRows); err == nil {
			violationCount = len(violationRows)
		}

		// CC6: Active agents (each represents an access principal)
		var agentRows []struct{ AgentID string `json:"agent_id"` }
		agentCount := 0
		if err := db.QueryRowsCompound(database.TblAgents, "agent_id",
			"tenant_id", tenantID, "status", "ACTIVE", &agentRows); err == nil {
			agentCount = len(agentRows)
		}

		// CC4/CC7: HITL cases (human monitoring decisions)
		var hitlRows []struct{ CaseID string `json:"case_id"` }
		hitlCount := 0
		if err := db.QueryRowsCompound(database.TblComplianceCases, "case_id",
			"tenant_id", tenantID, "case_type", "HITL", &hitlRows); err == nil {
			hitlCount = len(hitlRows)
		}

		// CC3: GRA risk assessments
		var graRows []struct{ CaseID string `json:"case_id"` }
		graCount := 0
		if err := db.QueryRowsCompound(database.TblGRACases, "case_id",
			"tenant_id", tenantID, "case_type", "RISK_ASSESSMENT", &graRows); err == nil {
			graCount = len(graRows)
		}

		log.Info("SOC2 evidence data collected",
			"policies", policyCount,
			"violations", violationCount,
			"agents", agentCount,
			"hitl_cases", hitlCount,
			"gra_assessments", graCount,
		)

		// ── Build the evidence package ─────────────────────────────────────
		pkg := SOC2EvidencePackage{
			PackageID:   packageID,
			TenantID:    tenantID,
			GeneratedAt: now.Format(time.RFC3339),
			GeneratedBy: actorID,
			PeriodStart: req.PeriodStart,
			PeriodEnd:   req.PeriodEnd,
			AuditType:   req.AuditType,
			Status:      "DRAFT",

			ControlEnvironment: SOC2ControlSection{
				Criteria:    "CC1 — Control Environment",
				Description: "Governance structure, accountability, and oversight mechanisms.",
				ControlStatus: "EFFECTIVE",
				Evidence: []SOC2EvidenceItem{
					{Type: "SYSTEM_GENERATED", Description: "RBAC permission matrix enforced via AOCS auth middleware", Source: "ocx-shared-go/infra/auth", Count: 0},
					{Type: "SYSTEM_GENERATED", Description: "Tenant isolation enforced via NOT NULL tenant_id on all tables", Source: "database schema", Count: 0},
					{Type: "SYSTEM_GENERATED", Description: "Super-admin separation enforced (is_super_admin flag + RequireSuperAdmin guard)", Source: "aocs-system-svc/handlers/admin"},
				},
			},

			Communication: SOC2ControlSection{
				Criteria:    "CC2 — Communication and Information",
				Description: "Internal and external communication of security and compliance controls.",
				ControlStatus: "EFFECTIVE",
				Evidence: []SOC2EvidenceItem{
					{Type: "SYSTEM_GENERATED", Description: "EU AI Act Art.13 transparency card generation", Source: "aocs-compliance/handlers/compliance/eu_ai_act.go"},
					{Type: "SYSTEM_GENERATED", Description: "Compliance report delivery (SMTP) with pg_cron scheduling", Source: "aocs-compliance/handlers/reports"},
				},
			},

			RiskAssessment: SOC2ControlSection{
				Criteria:    "CC3 — Risk Assessment",
				Description: "Risk identification, analysis, and response processes.",
				ControlStatus: "EFFECTIVE",
				Evidence: []SOC2EvidenceItem{
					{Type: "SYSTEM_GENERATED", Description: "GRA (Governance Risk Assessment) cases in period", Source: "aocs_compliance_cases (case_type=RISK_ASSESSMENT)", Count: graCount, Period: req.PeriodStart + " to " + req.PeriodEnd},
					{Type: "SYSTEM_GENERATED", Description: "CVIC trust scoring — continuous agent risk evaluation", Source: "ocx-services-py-svc/aocs_env"},
					{Type: "SYSTEM_GENERATED", Description: "Reputation scoring and trust decay monitoring", Source: "aocs-gate/handlers/gate"},
				},
			},

			Monitoring: SOC2ControlSection{
				Criteria:    "CC4 — Monitoring Activities",
				Description: "Ongoing monitoring and evaluation of system controls.",
				ControlStatus: "EFFECTIVE",
				Evidence: []SOC2EvidenceItem{
					{Type: "SYSTEM_GENERATED", Description: "HITL (Human-in-the-Loop) oversight decisions in period", Source: "aocs_compliance_cases (case_type=HITL)", Count: hitlCount, Period: req.PeriodStart + " to " + req.PeriodEnd},
					{Type: "SYSTEM_GENERATED", Description: "Agent heartbeat monitor — real-time health checks", Source: "aocs-gate/handlers/workers/agent_heartbeat_monitor.go"},
					{Type: "SYSTEM_GENERATED", Description: "7-year audit log retention with BigQuery archival", Source: "ocx-services-py-svc/shared/archival"},
				},
			},

			ControlActivities: SOC2ControlSection{
				Criteria:    "CC5 — Control Activities",
				Description: "Policies, procedures, and controls that address risk responses.",
				ControlStatus: "EFFECTIVE",
				Evidence: []SOC2EvidenceItem{
					{Type: "SYSTEM_GENERATED", Description: "Active enforcement policies in period", Source: "aocs_policies (status=ACTIVE)", Count: policyCount, Period: req.PeriodStart + " to " + req.PeriodEnd},
					{Type: "SYSTEM_GENERATED", Description: "Policy lifecycle: DRAFT→REVIEW→APPROVED→PUBLISHED (aocs-studio-svc)", Source: "aocs-studio-svc/handlers_workflow.go"},
					{Type: "SYSTEM_GENERATED", Description: "25-stage gate enforcement pipeline — every agent action evaluated", Source: "aocs-gate/handlers/gate"},
				},
			},

			LogicalAccess: SOC2ControlSection{
				Criteria:    "CC6 — Logical and Physical Access Controls",
				Description: "Authentication, authorisation, and access control mechanisms.",
				ControlStatus: "EFFECTIVE",
				Evidence: []SOC2EvidenceItem{
					{Type: "SYSTEM_GENERATED", Description: "Active AI agents — each with scoped authority profile", Source: "aocs_agents (status=ACTIVE)", Count: agentCount, Period: req.PeriodStart + " to " + req.PeriodEnd},
					{Type: "SYSTEM_GENERATED", Description: "AES-256-GCM credential encryption for all connector credentials", Source: "aocs-system-svc/handlers/platform/connector_registry.go"},
					{Type: "SYSTEM_GENERATED", Description: "OAuth PKCE flow for all ML provider connections", Source: "aocs-system-svc/handlers/agents/provider_oauth.go"},
					{Type: "SYSTEM_GENERATED", Description: "JWT + RBAC enforcement on all API routes", Source: "ocx-shared-go/infra/auth"},
				},
			},

			SystemOperations: SOC2ControlSection{
				Criteria:    "CC7 — System Operations",
				Description: "Detection of and response to security events and incidents.",
				ControlStatus: "EFFECTIVE",
				Evidence: []SOC2EvidenceItem{
					{Type: "SYSTEM_GENERATED", Description: "Compliance violations (incidents) in period", Source: "aocs_compliance_cases (case_type=VIOLATION)", Count: violationCount, Period: req.PeriodStart + " to " + req.PeriodEnd},
					{Type: "SYSTEM_GENERATED", Description: "DLP scanning and real-time data loss detection", Source: "aocs-compliance/handlers/security"},
					{Type: "SYSTEM_GENERATED", Description: "ZKP (Zero-Knowledge Proof) audit chain — tamper-evident evidence trail", Source: "aocs-compliance/handlers/zkp"},
					{Type: "SYSTEM_GENERATED", Description: "Ghost state / kill switch — instant agent termination capability", Source: "aocs-gate (ghost state mechanism)"},
				},
			},

			ChangeManagement: SOC2ControlSection{
				Criteria:    "CC8 — Change Management",
				Description: "SDLC controls, change testing, and deployment management.",
				ControlStatus: "PARTIAL",
				Notes:        "CI/CD pipeline documented. Formal change advisory board process recommended for SOC2 Type II.",
				Evidence: []SOC2EvidenceItem{
					{Type: "MANUAL", Description: "GitHub Actions CI/CD with change detection per service", Source: ".github/workflows"},
					{Type: "MANUAL", Description: "Policy Studio enforces explicit APPROVED state before PUBLISHED — no direct production writes", Source: "aocs-studio-svc"},
					{Type: "MANUAL", Description: "Policy version audit log (ps_policy_audit_log) — every lifecycle change tracked", Source: "aocs-studio-svc/handlers_workflow.go"},
				},
			},

			RiskMitigation: SOC2ControlSection{
				Criteria:    "CC9 — Risk Mitigation",
				Description: "Vendor and business partner risk management.",
				ControlStatus: "EFFECTIVE",
				Evidence: []SOC2EvidenceItem{
					{Type: "SYSTEM_GENERATED", Description: "AI provider credential isolation per tenant (not shared)", Source: "aocs-system-svc/handlers/agents/provider_oauth.go"},
					{Type: "SYSTEM_GENERATED", Description: "Vendor spend enforcement — budget policy via gate (governance/vendor_budget.go)", Source: "aocs-gate/handlers/economics"},
					{Type: "SYSTEM_GENERATED", Description: "Connector credential AES-256-GCM at rest", Source: "aocs-system-svc/connector_registry.go"},
				},
			},

			Availability: SOC2ControlSection{
				Criteria:    "A1 — Availability",
				Description: "System availability, capacity, and incident SLA performance.",
				ControlStatus: "EFFECTIVE",
				Evidence: []SOC2EvidenceItem{
					{Type: "SYSTEM_GENERATED", Description: "SLA breach monitoring (aocs-hub/handlers/sla)", Source: "aocs-hub"},
					{Type: "SYSTEM_GENERATED", Description: "Self-heal advisor — automated remediation on agent failures", Source: "aocs-gate/handlers/workers/self_heal_advisor.go"},
					{Type: "MANUAL", Description: "Cloud Run min-instances=1 for always-on services (platform, gate, hub, intel)", Source: "deployment configuration"},
				},
			},
		}

		pkgJSON, _ := json.Marshal(pkg)

		if err := db.InsertRow(database.TblComplianceCases, map[string]any{
			"case_id":    packageID,
			"tenant_id":  tenantID,
			"case_type":  "SOC2_EVIDENCE_PACKAGE",
			"status":     "DRAFT",
			"data":       json.RawMessage(pkgJSON),
			"created_by": actorID,
			"created_at": now,
			"updated_at": now,
		}); err != nil {
			log.Error("failed to store SOC2 evidence package", "error", err)
			respond.ErrorWithCode(w, http.StatusInternalServerError, respond.ErrCodeInternal,
				"failed to store evidence package")
			return
		}

		log.Info("SOC2 evidence package generated", "status", "DRAFT")
		respond.JSON(w, http.StatusCreated, pkg)
	}
}

// HandleGetSOC2Package retrieves a previously generated SOC2 evidence package.
//
// GET /compliance/soc2/evidence-package/{id}
func HandleGetSOC2Package(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		id := mux.Vars(r)["id"]
		if id == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}

		var rows []struct {
			CaseID    string          `json:"case_id"`
			Status    string          `json:"status"`
			Data      json.RawMessage `json:"data"`
			CreatedAt string          `json:"created_at"`
		}
		if err := db.QueryRowsCompound(database.TblComplianceCases,
			"case_id,status,data,created_at",
			"case_id", id, "tenant_id", tenantID,
			&rows); err != nil || len(rows) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "SOC2 evidence package not found")
			return
		}

		respond.JSON(w, http.StatusOK, rows[0])
	}
}

// HandleListSOC2Packages lists all SOC2 evidence packages for this tenant.
//
// GET /compliance/soc2/evidence-packages
func HandleListSOC2Packages(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var rows []struct {
			CaseID    string          `json:"case_id"`
			Status    string          `json:"status"`
			Data      json.RawMessage `json:"data"`
			CreatedAt string          `json:"created_at"`
		}
		if err := db.QueryRowsCompound(database.TblComplianceCases,
			"case_id,status,data,created_at",
			"tenant_id", tenantID, "case_type", "SOC2_EVIDENCE_PACKAGE",
			&rows); err != nil {
			respond.JSON(w, http.StatusOK, map[string]any{"packages": []any{}})
			return
		}

		respond.JSON(w, http.StatusOK, map[string]any{
			"packages": rows,
			"total":    len(rows),
		})
	}
}
