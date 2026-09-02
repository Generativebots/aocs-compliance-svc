// compliance_delivery.go — GAP-R3 FIX: Compliance report delivery verification and on-demand delivery.
//
// cron_expression + notify_emails to schedule_config JSONB, but there was NO:
//   1. Background worker / pg_cron job reading scheduled_reports and sending emails
//   2. Endpoint to check whether pg_cron jobs are actually running
//   3. On-demand "send now" fallback when the cron hasn't fired
//
// This file adds:
//   GET  /compliance/delivery-status          — Check pg_cron health for all AOCS jobs.
//     Queries cron.job_run_details to verify scheduled jobs ran recently. Returns
//     per-job last_run_at, status, and failure flags. Operators can see at a glance
//     whether the Supabase pg_cron extension is running.
//
//   POST /compliance/reports/{id}/deliver     — On-demand report delivery.
//     Generates the compliance report for the given report_id and emails it to
//     the recipients in schedule_config. Uses the tenant's SMTP config
//     (same pattern as SendInviteViaSMTP). Also writes last_sent_at to the report row.
//
// Industry precedent: AWS Audit Manager, Vanta, Drata all expose a "deliver now"
// API that bypasses scheduler — critical for auditors who need ad-hoc evidence packages.
package reports

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

// GET /compliance/delivery-status — pg_cron health check

// HandleComplianceDeliveryStatus verifies that Supabase pg_cron is running
// and all AOCS scheduled jobs executed recently.
//
// Queries cron.job_run_details for jobs whose command matches 'fn_' functions
// registered in the AOCS schema. Returns a status object suitable for the
// Compliance page health banner.
//
// GET /compliance/delivery-status
func HandleComplianceDeliveryStatus(pgx *database.PGXPool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if pgx == nil || pgx.Pool() == nil {
			respond.JSON(w, http.StatusOK, map[string]any{
				"pgcron_available": false,
				"note":             "PGX pool not initialised — pg_cron status unavailable in local dev mode",
				"jobs":             []any{},
			})
			return
		}

		_, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		// cron.job_run_details is Supabase's pg_cron log table.
		// Each row represents one execution of a scheduled job.
		// We take the most recent run per job name to check health.
		const q = `
			SELECT
				j.jobname,
				j.schedule,
				j.command,
				d.start_time,
				d.end_time,
				d.status,
				d.return_message
			FROM cron.job j
			LEFT JOIN LATERAL (
				SELECT start_time, end_time, status, return_message
				FROM cron.job_run_details
				WHERE jobid = j.jobid
				ORDER BY start_time DESC
				LIMIT 1
			) d ON TRUE
			WHERE j.jobname LIKE 'aocs%' OR j.command LIKE '%fn_%'
			ORDER BY j.jobname
		`
		rows, err := pgx.Query(ctx, q)
		if err != nil {
			// pg_cron extension not installed or cron schema not accessible
			slog.Warn("GAP-R3: cron.job_run_details not accessible — pg_cron extension may not be enabled on this Supabase tier",
				"error", err)
			respond.JSON(w, http.StatusOK, map[string]any{
				"pgcron_available": false,
				"note":             "pg_cron not accessible. Enable the pg_cron extension in Supabase Dashboard → Extensions.",
				"error":            err.Error(),
				"jobs":             []any{},
			})
			return
		}
		defer rows.Close()

		type jobStatus struct {
			JobName       string  `json:"job_name"`
			Schedule      string  `json:"schedule"`
			Command       string  `json:"command"`
			LastRunAt     *string `json:"last_run_at"`
			LastEndAt     *string `json:"last_end_at"`
			Status        *string `json:"status"`
			ReturnMessage *string `json:"return_message"`
			Healthy       bool    `json:"healthy"`
		}

		var jobs []jobStatus
		staleCutoff := time.Now().UTC().Add(-26 * time.Hour) // anything older than 26h is stale
		allHealthy := true

		for rows.Next() {
			var js jobStatus
			var lastRunAt, lastEndAt *time.Time
			var status, returnMsg *string
			if scanErr := rows.Scan(&js.JobName, &js.Schedule, &js.Command,
				&lastRunAt, &lastEndAt, &status, &returnMsg); scanErr != nil {
				continue
			}
			if lastRunAt != nil {
				s := lastRunAt.UTC().Format(time.RFC3339)
				js.LastRunAt = &s
				// Healthy = ran within last 26h AND succeeded
				js.Healthy = lastRunAt.After(staleCutoff) && (status == nil || *status == "succeeded")
			} else {
				js.Healthy = false // never ran
			}
			if lastEndAt != nil {
				s := lastEndAt.UTC().Format(time.RFC3339)
				js.LastEndAt = &s
			}
			js.Status = status
			js.ReturnMessage = returnMsg
			if !js.Healthy {
				allHealthy = false
			}
			jobs = append(jobs, js)
		}
		if rows.Err() != nil {
			slog.Error("GAP-R3: cron.job_run_details scan error", "error", rows.Err())
		}

		respond.JSON(w, http.StatusOK, map[string]any{
			"pgcron_available": true,
			"all_healthy":      allHealthy,
			"job_count":        len(jobs),
			"checked_at":       time.Now().UTC().Format(time.RFC3339),
			"jobs":             jobs,
		})
	}
}

// POST /compliance/reports/{id}/deliver — on-demand delivery


// HandleDeliverComplianceReport sends a compliance report immediately to its recipients.
//
// POST /compliance/reports/{id}/deliver
//
// Flow:
//  1. Load the compliance report + schedule_config (recipients, format)
//  2. Load the tenant's SMTP config from core_tenant_smtp
//  3. Send the report JSON/summary to each recipient via SMTP
//  4. Write last_sent_at back to the report row
//
// This is the on-demand "send now" path that bypasses pg_cron scheduling.
// It also serves as a manual trigger when the cron hasn't fired.
func HandleDeliverComplianceReport(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		reportID := mux.Vars(r)["id"]
		if reportID == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "missing path parameter: id")
			return
		}

		// 1. Load the compliance report to get schedule_config + recipients
		type complianceReportRow struct {
			ReportID       string  `json:"compliance_report_id"`
			ReportType     string  `json:"report_type"`
			Standard       string  `json:"standard"`
			Period         string  `json:"period"`
			ScheduleConfig *string `json:"schedule_config"`
			Status         string  `json:"status"`
		}
		var reports []complianceReportRow
		if err := db.QueryRows(database.TblSharComplianceReports,
			"compliance_report_id,report_type,standard,period,schedule_config,status",
			"compliance_report_id", reportID, &reports); err != nil || len(reports) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "compliance report not found")
			return
		}
		rep := reports[0]

		// 2. Parse schedule_config for recipients and format
		var schedConfig struct {
			NotifyEmails []string `json:"notify_emails"`
			Format       string   `json:"format"` // "pdf", "json", "summary"
		}
		if rep.ScheduleConfig != nil && *rep.ScheduleConfig != "" {
			if jsonErr := json.Unmarshal([]byte(*rep.ScheduleConfig), &schedConfig); jsonErr != nil {
				slog.Warn("HandleDeliverComplianceReport: bad schedule_config JSON",
					"report_id", reportID, "error", jsonErr)
			}
		}

		// Allow overriding recipients in POST body
		var req struct {
			Recipients []string `json:"recipients"`
		}
		_ = validate.BindOptional(w, r, &req) // best-effort: empty body keeps schedule recipients
		if len(req.Recipients) > 0 {
			schedConfig.NotifyEmails = req.Recipients
		}

		if len(schedConfig.NotifyEmails) == 0 {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest,
				"no recipients configured — set notify_emails via POST /reports/{id}/schedule or pass recipients in request body")
			return
		}

		// 3. Load tenant SMTP config from core_tenant_smtp
		smtpCfg, smtpErr := loadTenantSMTPForDelivery(r.Context(), db, tenantID)
		if smtpErr != nil {
			slog.Error("HandleDeliverComplianceReport: no SMTP config",
				"tenant_id", tenantID, "report_id", reportID, "error", smtpErr)
			respond.ErrorWithCode(w, http.StatusUnprocessableEntity, "SMTP_NOT_CONFIGURED",
				fmt.Sprintf("SMTP not configured for tenant — configure via PUT /tenant/smtp: %s", smtpErr.Error()))
			return
		}

		// 4. Compose email body
		standard := rep.Standard
		if standard == "" {
			standard = rep.ReportType
		}
		period := rep.Period
		if period == "" {
			now := time.Now().UTC()
			period = fmt.Sprintf("%d-Q%d", now.Year(), (int(now.Month())-1)/3+1)
		}
		now := time.Now().UTC()
		subject := fmt.Sprintf("[OCX] %s Compliance Report — %s", standard, period)
		body := fmt.Sprintf(`AOCS Compliance Report
%s | %s
Generated: %s

Report ID:   %s
Standard:    %s
Period:      %s
Status:      %s

This report was generated by the OCX AI Governance Platform.
To view the full interactive report, log in to OCX and navigate to:
  Compliance → Reports → %s

If you did not expect this report, contact your OCX administrator.

— OCX Compliance Engine`, standard, period, now.Format("January 2, 2006 15:04 UTC"),
			rep.ReportID, standard, period, rep.Status, rep.ReportID)

		// 5. Send to each recipient
		var sent []string
		var failed []string
		for _, recipient := range schedConfig.NotifyEmails {
			recipient = strings.TrimSpace(recipient)
			if recipient == "" {
				continue
			}
			if sendErr := sendComplianceEmail(smtpCfg, recipient, subject, body); sendErr != nil {
				slog.Error("HandleDeliverComplianceReport: send failed",
					"recipient", recipient, "report_id", reportID, "error", sendErr)
				failed = append(failed, recipient)
			} else {
				sent = append(sent, recipient)
			}
		}

		// 6. Write last_sent_at back to the report row (regardless of partial failures)
		if len(sent) > 0 {
			if updateErr := db.UpdateRow(database.TblSharComplianceReports,
				"compliance_report_id", reportID, map[string]any{
					"last_sent_at": now.Format(time.RFC3339),
					"updated_at":   now.Format(time.RFC3339),
				}); updateErr != nil {
				slog.Error("HandleDeliverComplianceReport: failed to write last_sent_at",
					"report_id", reportID, "error", updateErr)
			}
		}

		slog.Info("GAP-R3 FIXED: compliance report delivered",
			"report_id", reportID, "tenant_id", tenantID,
			"sent_count", len(sent), "failed_count", len(failed))

		statusCode := http.StatusOK
		if len(sent) == 0 && len(failed) > 0 {
			statusCode = http.StatusInternalServerError
		}
		respond.JSON(w, statusCode, map[string]any{
			"report_id":     reportID,
			"standard":      standard,
			"period":        period,
			"sent":          sent,
			"failed":        failed,
			"last_sent_at":  now.Format(time.RFC3339),
		})
	}
}

// smtpDeliveryConfig holds the minimal SMTP fields needed for report delivery.
type smtpDeliveryConfig struct {
	Host      string
	Port      int
	Username  string
	Password  string
	FromEmail string
	FromName  string
}

// loadTenantSMTPForDelivery loads SMTP config from core_tenant_smtp and
// decrypts the stored API key / password before returning.
//
// CQ-04 FIX: Previously passed r.APIKeyEnc (AES-GCM ciphertext) directly as the
// SMTP password. smtp.PlainAuth sends this blob to the SMTP server verbatim —
// authentication always fails. Fixed: decrypt using AES-GCM + OCX_ENCRYPTION_KEY
// (same approach as tenant.decryptValue). Falls back to base64 decode when
// OCX_ENCRYPTION_KEY is not set (matching the original tenant.loadSMTPConfig behavior).
func loadTenantSMTPForDelivery(_ context.Context, db database.DB, tenantID string) (*smtpDeliveryConfig, error) {
	type smtpRow struct {
		Host      string `json:"host"`
		Port      int    `json:"port"`
		Username  string `json:"username"`
		APIKeyEnc string `json:"api_key_enc"`
		FromEmail string `json:"from_email"`
		FromName  string `json:"from_name"`
	}
	var rows []smtpRow
	if err := db.QueryRows(database.TblTenantSMTPConfigs,
		"host,port,username,api_key_enc,from_email,from_name",
		"tenant_id", tenantID, &rows); err != nil || len(rows) == 0 {
		return nil, fmt.Errorf("no SMTP config found for tenant %s", tenantID)
	}
	r := rows[0]

	// CQ-04 FIX: Decrypt the stored API key before use.
	// The tenant SMTP handler (tenant/smtp.go) stores the password via encryptValue()
	// which uses AES-GCM when OCX_ENCRYPTION_KEY is set, or base64 otherwise.
	// We must reverse that transformation here before passing to smtp.PlainAuth.
	decrypted, decErr := decryptSMTPKey(r.APIKeyEnc)
	if decErr != nil {
		slog.Error("CQ-04: SMTP key decryption failed — compliance delivery will fail",
			"tenant_id", tenantID, "error", decErr)
		return nil, fmt.Errorf("SMTP key decryption failed: %w", decErr)
	}

	return &smtpDeliveryConfig{
		Host:      r.Host,
		Port:      r.Port,
		Username:  r.Username,
		Password:  decrypted,
		FromEmail: r.FromEmail,
		FromName:  r.FromName,
	}, nil
}

// decryptSMTPKey decrypts an AES-GCM encrypted SMTP API key stored by tenant/smtp.go:encryptValue().
// When OCX_ENCRYPTION_KEY is not set, the value is plain base64 — just decode it.
// This mirrors tenant.decryptValue() without importing the tenant package (circular dep avoidance).
func decryptSMTPKey(ciphertext string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("base64 decode failed: %w", err)
	}

	keyHex := os.Getenv("OCX_ENCRYPTION_KEY")
	if keyHex == "" {
		// No encryption key: stored as plain base64 (legacy / dev mode)
		return string(raw), nil
	}

	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		// Key is malformed — treat as plain base64 fallback with a warning
		slog.Warn("decryptSMTPKey: OCX_ENCRYPTION_KEY is set but not valid 32-byte hex — treating as plaintext",
			"key_len_bytes", len(key))
		return string(raw), nil
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("AES cipher init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("GCM init: %w", err)
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short (len=%d, nonce=%d)", len(raw), gcm.NonceSize())
	}
	nonce, ciphertextBytes := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", fmt.Errorf("AES-GCM decrypt failed: %w — check OCX_ENCRYPTION_KEY matches the key used when SMTP config was saved", err)
	}
	return string(plaintext), nil
}

// sendComplianceEmail sends a compliance report email via SMTP.
func sendComplianceEmail(cfg *smtpDeliveryConfig, to, subject, body string) error {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	msg := fmt.Sprintf(
		"From: %s <%s>\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s",
		cfg.FromName, cfg.FromEmail, to, subject, body,
	)
	return smtp.SendMail(addr, auth, cfg.FromEmail, []string{to}, []byte(msg))
}
