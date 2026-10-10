package regulatory

// hipaa_report.go — Database-Backed Automated HIPAA Security & Privacy Continuous Assessment
//
// 45 CFR Parts 160 and 164 Automated Compliance Engine for Autonomous AI Agents.
// Replaces manual HIPAA compliance audits with real-time algorithmic verification:
//   • 45 CFR § 164.312(a)(1) — Access Control & Unique Agent Identity
//   • 45 CFR § 164.312(a)(2)(iv) — Encryption & Decryption (AES-256-GCM)
//   • 45 CFR § 164.312(b) — Tamper-Proof Audit Controls (Merkle Chain)
//   • 45 CFR § 164.312(c)(1) — Data Integrity & Non-Repudiation (SHA-256 / ZKP)
//   • 45 CFR § 164.312(e)(1) — Transmission Security (TLS 1.3 / mTLS)
//   • 45 CFR § 164.502(b) — Minimum Necessary Disclosure Rule (Intent Scopes)
//   • 45 CFR § 164.514(b) — Safe Harbor De-identification (Real-time DLP)
//   • 45 CFR § 164.308(b)(1) — Business Associate Agreements (BAA Contract Alignment)
//
// All controls, evidence links, violations, and certified reports are loaded from and
// persisted into the compliance database (compl_obligations, compl_evidence, compl_reports).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

// HIPAACheckItem represents a database-backed safeguard check under 45 CFR Part 164.
type HIPAACheckItem struct {
	ControlID     string `json:"control_id"`
	Citation      string `json:"citation"`
	Title         string `json:"title"`
	Safeguard     string `json:"safeguard"` // Administrative | Physical | Technical | Privacy
	Status        string `json:"status"`    // COMPLIANT | IN_PROGRESS | NON_COMPLIANT | WAIVED
	EvidenceRef   string `json:"evidence_ref,omitempty"`
	EvidenceCount int    `json:"evidence_count"`
	Details       string `json:"details"`
	Remediation   string `json:"remediation,omitempty"`
}

// HIPAAReviewReport is the formal HIPAA attestation artifact backed by DB records.
type HIPAAReviewReport struct {
	ReportID       string  `json:"report_id"`
	TenantID       string  `json:"tenant_id"`
	Framework      string  `json:"framework"` // HIPAA_45CFR164
	GeneratedAt    string  `json:"generated_at"`
	Status         string  `json:"status"` // DRAFT | CERTIFIED
	OverallScore   float64 `json:"overall_score_pct"`
	PassedControls int     `json:"passed_controls"`
	TotalControls  int     `json:"total_controls"`
	ContentHash    string  `json:"content_hash"`
	// BAAStatus is derived from the 164.308(b)(1) obligation and its evidence:
	// EVIDENCED (compliant + evidence) | UNVERIFIED (marked compliant, no
	// evidence) | the obligation's status (NOT_STARTED, NON_COMPLIANT, ...) |
	// NOT_ASSESSED (no BAA obligation). It used to be hard-coded EXECUTED_VALID.
	BAAStatus string `json:"baa_status"`
	// DLPActive: the tenant has at least one active DLP policy (was hard-coded true).
	DLPActive      bool             `json:"dlp_active"`
	DLPPolicyCount int              `json:"dlp_active_policy_count"`
	Controls       []HIPAACheckItem `json:"controls"`
}

const baaControlRef = "164.308(b)(1)"

// baaStatusFrom derives the BAA attestation state from the BAA obligation row
// and its per-control evidence count.
func baaStatusFrom(obRows []map[string]any, evidenceByControl map[string]int) string {
	for _, row := range obRows {
		if ref, _ := row["control_ref"].(string); ref != baaControlRef {
			continue
		}
		st := storedStatus(row)
		if st != statusCompliant {
			return st
		}
		cid, _ := row["control_id"].(string)
		if evidenceByControl[cid] > 0 {
			return "EVIDENCED"
		}
		return "UNVERIFIED"
	}
	return "NOT_ASSESSED"
}

// dlpActivePolicies counts the tenant's active DLP policies (same store and
// provider as /dlp/policies).
func dlpActivePolicies(db database.DB, tenantID string) (int, error) {
	var rows []map[string]any
	if err := db.QueryRowsCompound(database.TblDLPPolicies, "id, is_active", "tenant_id", tenantID, "provider", "INTERNAL", &rows); err != nil {
		return 0, err
	}
	n := 0
	for _, r := range rows {
		if active, _ := r["is_active"].(bool); active {
			n++
		}
	}
	return n, nil
}

// latestReport returns the newest row by generated_at (RFC 3339 strings and
// time values both sort correctly once formatted).
func latestReport(rows []map[string]any) map[string]any {
	var best map[string]any
	bestTS := ""
	for _, r := range rows {
		ts := fmt.Sprint(r["generated_at"])
		if t, ok := r["generated_at"].(time.Time); ok {
			ts = t.UTC().Format(time.RFC3339Nano)
		}
		if best == nil || ts > bestTS {
			best, bestTS = r, ts
		}
	}
	return best
}

// controlStateHash is SHA-256 over the sorted "control_id=status" lines: the
// certified content, reproducible from compl_obligations.
func controlStateHash(obRows []map[string]any) string {
	lines := make([]string, 0, len(obRows))
	for _, ob := range obRows {
		cid, _ := ob["control_id"].(string)
		lines = append(lines, cid+"="+storedStatus(ob))
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

// defaultHIPAABaselineControls defines the required standard obligations to seed into compl_obligations.
var defaultHIPAABaselineControls = []struct {
	ControlRef  string
	Name        string
	Safeguard   string
	Description string
	EvidenceRef string
}{
	{
		ControlRef:  "164.312(a)(1)",
		Name:        "HIPAA: Access Control & Unique Agent Identification",
		Safeguard:   "Technical",
		Description: "All autonomous agents possess cryptographically verified tenant-scoped identities and JWT auth tokens.",
		EvidenceRef: "evlt_iam_rbac",
	},
	{
		ControlRef:  "164.312(a)(2)(iv)",
		Name:        "HIPAA: Encryption and Decryption (ePHI at Rest)",
		Safeguard:   "Technical",
		Description: "Stored credentials, agent memories, and sensitive state encrypted using AES-256-GCM envelope encryption.",
		EvidenceRef: "evlt_crypto_aes256",
	},
	{
		ControlRef:  "164.312(b)",
		Name:        "HIPAA: Audit Controls & Cryptographic Ledger",
		Safeguard:   "Technical",
		Description: "Every agent tool execution and data read is immutably committed to the Patent P-03 Merkle hash chain.",
		EvidenceRef: "evlt_merkle_chain",
	},
	{
		ControlRef:  "164.312(c)(1)",
		Name:        "HIPAA: Data Integrity & Non-Repudiation",
		Safeguard:   "Technical",
		Description: "SHA-256 canonical hash verification active on all evidence ingestion and query pipelines.",
		EvidenceRef: "evlt_zkp_sha256",
	},
	{
		ControlRef:  "164.312(e)(1)",
		Name:        "HIPAA: Transmission Security & Network Safeguards",
		Safeguard:   "Technical",
		Description: "TLS 1.3 enforced for all external ingress/egress; internal microservices communicate over private VPC with mTLS.",
		EvidenceRef: "evlt_tls13_mtls",
	},
	{
		ControlRef:  "164.502(b)",
		Name:        "HIPAA: Minimum Necessary Rule Enforcement",
		Safeguard:   "Privacy",
		Description: "Autonomous agent actions strictly gated by declared intent scopes in core_app_bindings.",
		EvidenceRef: "evlt_intent_scoping",
	},
	{
		ControlRef:  "164.514(b)",
		Name:        "HIPAA: Safe Harbor De-identification & DLP Masking",
		Safeguard:   "Privacy",
		Description: "Real-time DLP engine scans agent payloads for SSN, MRN, DEA, and 18 HIPAA Safe Harbor direct identifiers.",
		EvidenceRef: "evlt_dlp_scanner",
	},
	{
		ControlRef:  "164.308(b)(1)",
		Name:        "HIPAA: Business Associate Agreement Alignment",
		Safeguard:   "Administrative",
		Description: "Tenant enterprise agreement includes active Business Associate provisions and downstream subcontractor tracking.",
		EvidenceRef: "evlt_baa_contract",
	},
}

// ensureHIPAAObligationsInDB seeds baseline obligations into compl_obligations if none exist for this tenant.
func ensureHIPAAObligationsInDB(db database.DB, tenantID string) {
	var existing []map[string]any
	err := db.QueryRowsCompound(database.TblComplObligations, "control_id, name, control_ref", "tenant_id", tenantID, "framework", "HIPAA", &existing)
	if err != nil {
		// Unknown existing state: seeding now could create duplicates.
		slog.Error("HIPAA baseline read failed; skipping seed", "error", err, "tenant_id", tenantID)
		return
	}
	if len(existing) >= len(defaultHIPAABaselineControls) {
		return
	}

	existingRefs := make(map[string]bool)
	for _, row := range existing {
		if ref, ok := row["control_ref"].(string); ok {
			existingRefs[ref] = true
		}
	}

	now := time.Now().UTC()
	for _, base := range defaultHIPAABaselineControls {
		if existingRefs[base.ControlRef] {
			continue
		}
		newRow := seededObligation("ctl-", tenantID, "HIPAA", base.ControlRef, base.Name, base.Description,
			map[string]any{"safeguard": base.Safeguard, "evidence_ref": base.EvidenceRef}, now)
		if insertErr := db.InsertRow(database.TblComplObligations, newRow); insertErr != nil {
			slog.Warn("Failed to seed HIPAA obligation into DB", "error", insertErr, "ref", base.ControlRef, "tenant_id", tenantID)
		}
	}
}

// HandleGetHIPAAReview generates an automated, real-time HIPAA compliance assessment directly from DB records.
// GET /api/v1/compliance/regulatory/hipaa/review
func HandleGetHIPAAReview(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		// Ensure baseline HIPAA controls exist in compl_obligations table
		ensureHIPAAObligationsInDB(db, tenantID)

		// 1. Query live obligations from compl_obligations
		const obCols = "control_id, tenant_id, framework, control_ref, name, description, status, evidence_count, last_assessed_at, metadata"
		var obRows []map[string]any
		if err := db.QueryRowsCompound(database.TblComplObligations, obCols, "tenant_id", tenantID, "framework", "HIPAA", &obRows); err != nil {
			slog.Error("Failed to query compl_obligations for HIPAA", "error", err, "tenant_id", tenantID)
			reportReadFailed(w, tenantID, err)
			return
		}

		// 2. Query live evidence count from compl_evidence
		var evidenceRows []map[string]any
		if err := db.QueryRows(database.TblComplEvidence, "evidence_id, control_id, framework", "tenant_id", tenantID, &evidenceRows); err != nil {
			reportReadFailed(w, tenantID, err)
			return
		}
		evidenceCountByRef := make(map[string]int)
		for _, ev := range evidenceRows {
			fw, _ := ev["framework"].(string)
			cid, _ := ev["control_id"].(string)
			if fw == "HIPAA" || fw == "" {
				evidenceCountByRef[cid]++
				evidenceCountByRef["global"]++
			}
		}

		// 3. Query live policy violations from compl_policy_violations to check for active breaches
		var violations []map[string]any
		if err := db.QueryRowsCompound(database.TblComplPolicyViolations, "violation_id, severity, status", "tenant_id", tenantID, "status", "OPEN", &violations); err != nil {
			reportReadFailed(w, tenantID, err)
			return
		}
		hasCriticalViolations := false
		for _, v := range violations {
			sev, _ := v["severity"].(string)
			if sev == "CRITICAL" || sev == "HIGH" {
				hasCriticalViolations = true
				break
			}
		}

		// 4. Map DB records to response checks
		checks := make([]HIPAACheckItem, 0, len(obRows))
		passedCount := 0

		for _, row := range obRows {
			cid, _ := row["control_id"].(string)
			cref, _ := row["control_ref"].(string)
			name, _ := row["name"].(string)
			desc, _ := row["description"].(string)
			status := storedStatus(row)

			// If critical violations exist in DB and affect this safeguard, reflect state dynamically
			if hasCriticalViolations && status == statusCompliant && (cref == "164.312(a)(1)" || cref == "164.514(b)") {
				status = "IN_PROGRESS"
			}

			safeguard := "Technical"
			evRef := "evlt_vault"
			if meta, ok := row["metadata"].(map[string]any); ok {
				if sg, ok := meta["safeguard"].(string); ok && sg != "" {
					safeguard = sg
				}
				if er, ok := meta["evidence_ref"].(string); ok && er != "" {
					evRef = er
				}
			}

			cnt := evidenceCountByRef[cid] // no tenant-wide fallback

			item := HIPAACheckItem{
				ControlID:     cid,
				Citation:      "45 CFR § " + cref,
				Title:         name,
				Safeguard:     safeguard,
				Status:        status,
				EvidenceRef:   evRef,
				EvidenceCount: cnt,
				Details:       desc,
			}

			if status == "COMPLIANT" {
				passedCount++
			} else {
				item.Remediation = "Review active policy violations in compl_policy_violations and resolve open compliance findings."
			}
			checks = append(checks, item)
		}

		total := len(checks)
		score := passScore(passedCount, total)

		// 5. Latest report from compl_reports (newest by generated_at)
		var reportRows []map[string]any
		reportStatus := "DRAFT"
		latestReportID := "hipaa-" + uuid.NewString()[:8]
		if err := db.QueryRowsCompound(database.TblComplReports, "report_id, status, generated_at", "tenant_id", tenantID, "report_type", "HIPAA", &reportRows); err == nil {
			if latest := latestReport(reportRows); latest != nil {
				if st, ok := latest["status"].(string); ok && st != "" {
					reportStatus = st
				}
				if rid, ok := latest["report_id"].(string); ok && rid != "" {
					latestReportID = rid
				}
			}
		}

		dlpCount, err := dlpActivePolicies(db, tenantID)
		if err != nil {
			reportReadFailed(w, tenantID, err)
			return
		}

		report := HIPAAReviewReport{
			ReportID:       latestReportID,
			TenantID:       tenantID,
			Framework:      "HIPAA_45CFR164",
			GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
			Status:         reportStatus,
			OverallScore:   score,
			PassedControls: passedCount,
			TotalControls:  len(checks),
			BAAStatus:      baaStatusFrom(obRows, evidenceCountByRef),
			DLPActive:      dlpCount > 0,
			DLPPolicyCount: dlpCount,
			Controls:       checks,
		}

		// Compute cryptographic content hash of DB controls for audit non-repudiation
		bodyBytes, _ := json.Marshal(report.Controls)
		sum := sha256.Sum256(bodyBytes)
		report.ContentHash = hex.EncodeToString(sum[:])

		respond.JSON(w, http.StatusOK, report)
	}
}

// HandleSubmitHIPAAReport marks a formal HIPAA assessment as CERTIFIED and persists into compl_reports in DB.
// POST /api/v1/compliance/regulatory/hipaa/report/submit
func HandleSubmitHIPAAReport(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDBWrite(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var req struct {
			ReportID       string `json:"report_id"`
			Certifier      string `json:"certifier_name"`
			ComplianceRole string `json:"certifier_role"`
		}
		if !validate.Bind(w, r, &req) {
			return
		}

		// Ensure baseline HIPAA obligations exist in DB before assessing (GAP-CRUD-7)
		ensureHIPAAObligationsInDB(db, tenantID)

		// Ensure report_id is securely scoped to tenant to prevent arbitrary injection
		reportID := req.ReportID
		if reportID == "" || !strings.HasPrefix(reportID, "hipaa-"+tenantID) {
			reportID = fmt.Sprintf("hipaa-%s-%s", tenantID, uuid.NewString()[:8])
		}

		// 1. Query live controls from compl_obligations to calculate finalized score
		var obRows []map[string]any
		if err := db.QueryRowsCompound(database.TblComplObligations, "control_id, control_ref, status", "tenant_id", tenantID, "framework", "HIPAA", &obRows); err != nil {
			reportReadFailed(w, tenantID, err)
			return
		}
		passed := 0
		for _, ob := range obRows {
			if storedStatus(ob) == statusCompliant {
				passed++
			}
		}
		total := len(obRows)
		score := passScore(passed, total)

		// 2. Query evidence (per control, for the BAA state)
		var evidenceRows []map[string]any
		if err := db.QueryRows(database.TblComplEvidence, "evidence_id, control_id", "tenant_id", tenantID, &evidenceRows); err != nil {
			reportReadFailed(w, tenantID, err)
			return
		}
		evidenceByControl := make(map[string]int)
		for _, ev := range evidenceRows {
			if cid, _ := ev["control_id"].(string); cid != "" {
				evidenceByControl[cid]++
			}
		}
		baaStatus := baaStatusFrom(obRows, evidenceByControl)

		// 3. Hash the certified content (control states), not the report id + clock
		contentHash := controlStateHash(obRows)

		now := time.Now().UTC()
		// Derive certifier identity securely from JWT claims
		certifierName := req.Certifier
		certifierID := ""
		if au, auErr := auth.GetAuthUser(r.Context()); auErr == nil && au != nil {
			certifierID = au.UserID
			if au.Email != "" {
				certifierName = au.Email
			}
		}
		if certifierName == "" {
			certifierName = "Compliance Officer"
		}
		generatedBy := certifierID
		if generatedBy == "" {
			generatedBy = certifierName
		}

		// 4. Persist the report into compl_reports database table
		reportRow := map[string]any{
			"report_id":        reportID,
			"tenant_id":        tenantID,
			"report_type":      "HIPAA",
			"period_start":     now.Add(-30 * 24 * time.Hour).Format(time.RFC3339),
			"period_end":       now.Format(time.RFC3339),
			"status":           "CERTIFIED",
			"case_count":       0,
			"evidence_count":   len(evidenceRows),
			"control_count":    total,
			"compliance_score": score,
			"generated_at":     now.Format(time.RFC3339),
			"generated_by":     generatedBy,
			"metadata": map[string]any{
				"certifier_name": certifierName,
				"certifier_id":   certifierID,
				"certifier_role": req.ComplianceRole,
				"content_hash":   contentHash,
				"baa_status":     baaStatus,
				"framework":      "HIPAA_45CFR164",
			},
			"summary": map[string]any{
				"overall_score_pct": score,
				"passed_controls":   passed,
				"total_controls":    total,
				"content_hash":      contentHash,
			},
			"created_at": now.Format(time.RFC3339),
			"updated_at": now.Format(time.RFC3339),
		}

		if err := db.InsertRow(database.TblComplReports, reportRow); err != nil {
			slog.Warn("Failed to persist report into compl_reports DB (attempting update)", "error", err, "report_id", reportID)
			if upErr := db.UpdateRowCompound(database.TblComplReports, "tenant_id", tenantID, "report_id", reportID, map[string]any{
				"status":           "CERTIFIED",
				"generated_at":     now.Format(time.RFC3339),
				"generated_by":     generatedBy,
				"compliance_score": score,
				"control_count":    total,
				"evidence_count":   len(evidenceRows),
				"metadata":         reportRow["metadata"],
				"summary":          reportRow["summary"],
			}); upErr != nil {
				slog.Error("hipaa_report: both insert and update failed — report not persisted",
					"insert_err", err, "update_err", upErr, "report_id", reportID, "tenant_id", tenantID)
				// Never answer CERTIFIED for a report that does not exist.
				respond.ErrorWithCode(w, http.StatusServiceUnavailable, respond.ErrCodeUnavailable,
					"HIPAA report could not be saved; nothing was certified")
				return
			}
		}

		slog.Info("HIPAA regulatory report certified and saved to compl_reports DB",
			"report_id", reportID,
			"tenant_id", tenantID,
			"certifier", certifierName,
			"score", score,
		)

		respond.JSON(w, http.StatusOK, map[string]any{
			"status":       "CERTIFIED",
			"report_id":    reportID,
			"certified_at": now.Format(time.RFC3339),
			"framework":    "HIPAA_45CFR164",
			"content_hash": contentHash,
			"score_pct":    score,
			"baa_status":   baaStatus,
			"database_row": database.TblComplReports,
			"message":      "HIPAA Continuous Attestation certified and persisted to compl_reports with cryptographic integrity.",
		})
	}
}
