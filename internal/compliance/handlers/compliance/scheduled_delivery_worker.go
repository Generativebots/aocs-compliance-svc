// compliance_scheduled_delivery_worker.go — FLOW-07 B2
//
// The compliance report scheduler (HandleScheduleReport) writes
// cron_expression + notify_emails to schedule_config JSONB, but there was
// NO background worker that read those schedules and sent emails.
//
// This worker:
//  1. Every minute checks aocs_nexus_compliance_reports for rows where
//     schedule_config is non-null and next_delivery_at <= NOW()
//  2. Sends email to configured recipients via tenant SMTP
//  3. Updates next_delivery_at and last_sent_at
//
// Wire in cmd/aocs-system/bootstrap.go:
//
//	compliance.StartScheduledDeliveryWorker(svc.BgCtx, db, coreClient)
package compliance

import (
	"time"
)

const scheduledDeliveryCheckInterval = 1 * time.Minute
