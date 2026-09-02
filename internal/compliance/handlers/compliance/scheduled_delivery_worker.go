// compliance_scheduled_delivery_worker.go — B-5 FIX: FLOW-07 B2
//
// The compliance report scheduler (HandleScheduleReport) writes
// cron_expression + notify_emails to schedule_config JSONB, but there was
// NO background worker that read those schedules and sent emails.
//
// This worker:
//   1. Every minute checks aocs_nexus_compliance_reports for rows where
//      schedule_config is non-null and next_delivery_at <= NOW()
//   2. Sends email to configured recipients via tenant SMTP
//   3. Updates next_delivery_at and last_sent_at
//
// Wire in cmd/aocs-platform/bootstrap.go:
//   compliance.StartScheduledDeliveryWorker(svc.BgCtx, db, coreClient)
package compliance

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/smtp"
	"os"
	"time"

	"github.com/ocx/shared/infra/concurrent"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/serviceclient"
)

const scheduledDeliveryCheckInterval = 1 * time.Minute

// StartScheduledDeliveryWorker launches the compliance scheduled delivery worker.
// FLOW-07 B2 FIX: Previously schedule_config JSONB was written but never read.
// This worker polls every minute for due scheduled reports and delivers them.
// coreClient is used for ocx-core-svc reads (tenants, SMTP config).
func StartScheduledDeliveryWorker(ctx context.Context, db database.DB, coreClient *serviceclient.Client) {
	if db == nil {
		slog.Warn("StartScheduledDeliveryWorker: db is nil — worker not started")
		return
	}
	concurrent.Go("compliance/scheduled_delivery_worker", func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("scheduled-delivery-worker: panic recovered", "error", r)
			}
		}()
		slog.Info("compliance scheduled-delivery-worker: started",
			"check_interval", scheduledDeliveryCheckInterval)

		ticker := time.NewTicker(scheduledDeliveryCheckInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				slog.Info("compliance scheduled-delivery-worker: stopping")
				return
			case <-ticker.C:
				runScheduledDeliveryCycle(ctx, db, coreClient)
			}
		}
	})
}

// runScheduledDeliveryCycle reads due scheduled reports and delivers them.
// FLOW-07 B2: The core loop that was completely missing before this fix.
func runScheduledDeliveryCycle(ctx context.Context, db database.DB, coreClient *serviceclient.Client) {
	if ctx.Err() != nil {
		return
	}

	type reportRow struct {
		ReportID       string          `json:"compliance_report_id"`
		TenantID       string          `json:"tenant_id"`
		ScheduleConfig json.RawMessage `json:"schedule_config"`
		Status         string          `json:"status"`
		NextDeliveryAt *string         `json:"next_delivery_at"`
	}

	// Load active tenants via ocx-core-svc API (boundary enforcement: no direct syst_tenants read).
	var tenantIDs []string
	if coreClient != nil {
		tenants, err := coreClient.ListTenants(ctx)
		if err != nil {
			slog.Error("scheduled-delivery: failed to fetch active tenants via coreClient", "error", err)
			return
		}
		for _, t := range tenants {
			if t.Status == "ACTIVE" {
				tenantIDs = append(tenantIDs, t.TenantID)
			}
		}
	} else {
		var activeTenants []struct {
			TenantID string `json:"tenant_id"`
		}
		if err := db.QueryRowsCtx(ctx, database.TblTenants, "tenant_id", "is_active", "true", &activeTenants); err != nil {
			slog.Error("scheduled-delivery: failed to fetch active tenants (fallback)", "error", err)
			return
		}
		for _, t := range activeTenants {
			tenantIDs = append(tenantIDs, t.TenantID)
		}
	}

	var dueReports []reportRow
	for _, tenantID := range tenantIDs {
		var tenantReports []reportRow
		if err := db.QueryRowsCompound(database.TblNexusComplianceReports,
			"compliance_report_id,tenant_id,schedule_config,next_delivery_at,status",
			"status", "READY", "tenant_id", tenantID, &tenantReports); err != nil {
			slog.Warn("scheduled-delivery: failed to query reports for tenant", "tenant_id", tenantID, "error", err)
			continue
		}
		dueReports = append(dueReports, tenantReports...)
	}

	now := time.Now().UTC()
	delivered := 0

	for _, rpt := range dueReports {
		if ctx.Err() != nil {
			break
		}
		if len(rpt.ScheduleConfig) == 0 || string(rpt.ScheduleConfig) == "null" || string(rpt.ScheduleConfig) == "{}" {
			continue
		}

		// Check if due
		if rpt.NextDeliveryAt != nil && *rpt.NextDeliveryAt != "" {
			nextRun, err := time.Parse(time.RFC3339, *rpt.NextDeliveryAt)
			if err == nil && now.Before(nextRun) {
				continue
			}
		}

		var schedCfg struct {
			NotifyEmails   []string `json:"notify_emails"`
			FrequencyHours int      `json:"frequency_hours"`
		}
		if err := json.Unmarshal(rpt.ScheduleConfig, &schedCfg); err != nil {
			slog.Warn("scheduled-delivery: bad schedule_config",
				"report_id", rpt.ReportID, "error", err)
			continue
		}
		if len(schedCfg.NotifyEmails) == 0 {
			continue
		}

		if err := deliverScheduledReport(ctx, db, coreClient, rpt.ReportID, rpt.TenantID, schedCfg.NotifyEmails); err != nil {
			slog.Error("scheduled-delivery: delivery failed",
				"report_id", rpt.ReportID, "error", err)
			continue
		}

		freqHours := schedCfg.FrequencyHours
		if freqHours <= 0 {
			freqHours = 24
		}
		nextDelivery := now.Add(time.Duration(freqHours) * time.Hour).Format(time.RFC3339)

		// On failure: DB keeps old last_sent_at → next scheduled run sees this report
		// as overdue → re-delivers → tenant receives DUPLICATE compliance report.
		// Now: log ERROR with report_id so ops can manually correct the DB record.
		if updErr := db.UpdateRowCompound(database.TblNexusComplianceReports,
			"compliance_report_id", rpt.ReportID,
			"tenant_id", rpt.TenantID,
			map[string]any{
				"last_sent_at":     now.Format(time.RFC3339),
				"next_delivery_at": nextDelivery,
			}); updErr != nil {
			slog.Error("scheduled-delivery: CRITICAL — report delivered but DB status update failed; "+
				"next run will re-deliver this report to the same recipients (duplicate delivery risk). "+
				"Manually set last_sent_at and next_delivery_at to prevent re-delivery.",
				"report_id", rpt.ReportID, "tenant_id", rpt.TenantID,
				"next_delivery_at", nextDelivery, "error", updErr)
			// Continue — do not let one DB error stop delivery of other reports.
		}
		delivered++
	}

	if delivered > 0 {
		slog.Info("scheduled-delivery: cycle complete", "delivered", delivered)
	}
}

// deliverScheduledReport sends the compliance report email via tenant SMTP.
// SMTP config is fetched via ocx-core-svc API (boundary enforcement: no direct core_tenant_smtp read).
func deliverScheduledReport(ctx context.Context, db database.DB, coreClient *serviceclient.Client, reportID, tenantID string, recipients []string) error {
	type localSMTP struct {
		Host        string
		Port        int
		User        string
		PassEnc     string
		FromEmail   string
	}
	var cfg localSMTP
	if coreClient != nil {
		smtpCfg, err := coreClient.GetSMTPConfig(ctx, tenantID)
		if err != nil || smtpCfg == nil {
			slog.Warn("scheduled-delivery: no SMTP config via coreClient — skipping", "tenant_id", tenantID)
			return nil // non-fatal
		}
		cfg = localSMTP{
			Host:      smtpCfg.Host,
			Port:      smtpCfg.Port,
			User:      smtpCfg.Username,
			PassEnc:   smtpCfg.APIKeyEnc,
			FromEmail: smtpCfg.FromEmail,
		}
	} else {
		type smtpRow struct {
			SMTPHost    string `json:"smtp_host"`
			SMTPPort    int    `json:"smtp_port"`
			SMTPUser    string `json:"smtp_username"`
			SMTPPassEnc string `json:"smtp_password_enc"`
			FromEmail   string `json:"from_email"`
		}
		var smtpRows []smtpRow
		if err := db.QueryRowsCtx(ctx, database.TblTenantSMTPConfigs,
			"smtp_host,smtp_port,smtp_username,smtp_password_enc,from_email",
			"tenant_id", tenantID, &smtpRows); err != nil || len(smtpRows) == 0 {
			slog.Warn("scheduled-delivery: no SMTP config (fallback) — skipping", "tenant_id", tenantID)
			return nil // non-fatal
		}
		row := smtpRows[0]
		cfg = localSMTP{
			Host:      row.SMTPHost,
			Port:      row.SMTPPort,
			User:      row.SMTPUser,
			PassEnc:   row.SMTPPassEnc,
			FromEmail: row.FromEmail,
		}
	}
	if cfg.Host == "" {
		return nil
	}

	smtpPass := cfg.PassEnc
	if cfg.PassEnc != "" {
		if dec, err := scheduledDeliveryDecryptAES(cfg.PassEnc); err == nil {
			smtpPass = dec
		}
	}

	port := 587
	if cfg.Port > 0 {
		port = cfg.Port
	}
	addr := fmt.Sprintf("%s:%d", cfg.Host, port)

	subject := "AOCS Scheduled Compliance Report — " + reportID
	body := "Your scheduled AOCS compliance report (" + reportID + ") is ready.\r\n" +
		"Log in to your AOCS dashboard to view the full report.\r\n\r\n" +
		"This is an automated delivery from your AOCS compliance schedule."

	for _, to := range recipients {
		msg := []byte("To: " + to + "\r\n" +
			"From: " + cfg.FromEmail + "\r\n" +
			"Subject: " + subject + "\r\n\r\n" +
			body)
		auth := smtp.PlainAuth("", cfg.User, smtpPass, cfg.Host)
		if err := smtp.SendMail(addr, auth, cfg.FromEmail, []string{to}, msg); err != nil {
			slog.Warn("scheduled-delivery: SMTP send failed", "to", to, "error", err)
		}
	}
	return nil
}

// scheduledDeliveryDecryptAES decrypts an AES-GCM base64-encoded SMTP password.
// Key: SMTP_AES_KEY env var (32 bytes hex). Same pattern as compliance_delivery.go.
func scheduledDeliveryDecryptAES(enc string) (string, error) {
	keyHex := os.Getenv("SMTP_AES_KEY")
	if keyHex == "" {
		return "", fmt.Errorf("SMTP_AES_KEY not configured")
	}
	key, err := decodeHex(keyHex)
	if err != nil || len(key) != 32 {
		return "", fmt.Errorf("invalid SMTP_AES_KEY: must be 64 hex chars (32 bytes)")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// decodeHex decodes a hex string to bytes.
func decodeHex(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd length hex string")
	}
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi, lo := hexVal(s[i]), hexVal(s[i+1])
		if hi == 255 || lo == 255 {
			return nil, fmt.Errorf("invalid hex char at position %d", i)
		}
		b[i/2] = hi<<4 | lo
	}
	return b, nil
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 255
	}
}
