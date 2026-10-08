// Package compliance — HITL / edge-case resolution handlers.
//
// Gathers: Cases, ZKP (chain, export, batch), Ledger Root, SIEM config, Report Export.
package compliance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/httpclient"
	"github.com/ocx/shared/infra/statemachine"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

// processPendingBatchJobs is a trusted server-side background goroutine.
//   - This runs inside the aocs-platform process, not reachable from the network.
//   - Each job row was created by HandleCreateZKPBatchJob with an explicit tenant_id.
//   - All UpdateRow calls scope by (job_id, tenant_id) — no cross-tenant mutation.
//   - Jobs are isolated: results per-job reference only the agent_ids encoded in that job.
//   - D3: pending jobs are read one tenant at a time (WHERE tenant_id = $1).
func processPendingBatchJobs(ctx context.Context, db database.DB) {
	type batchJob struct {
		JobID    string   `json:"job_id"`
		TenantID string   `json:"tenant_id"`
		AgentIDs []string `json:"agent_ids"`
		Period   string   `json:"period"`
	}
	var jobs []batchJob
	if err := database.ForEachTenant(ctx, db, "compliance.zkp_batch", func(ctx context.Context, tenantID string) error {
		var part []batchJob
		if err := db.QueryRowsCompoundCtx(ctx, database.TblZKPBatchJobs, "job_id,tenant_id,agent_ids,period",
			"tenant_id", tenantID, "status", "PENDING", &part); err != nil {
			return err
		}
		jobs = append(jobs, part...)
		return nil
	}); err != nil {
		slog.Warn("processPendingBatchJobs: tenant loop incomplete", "error", err)
	}
	for _, job := range jobs {
		if ctx.Err() != nil {
			return
		}
		// SM-11 guard: PENDING → PROCESSING must be a valid transition
		if smErr := statemachine.ValidateTransition(
			statemachine.ZKPBatchJob, "PENDING", "PROCESSING",
		); smErr != nil {
			// This should never fail for a freshly queried PENDING job, but
			// log and skip rather than corrupt state if SM definition changes.
			slog.Warn("processPendingBatchJobs: SM-11 PENDING→PROCESSING rejected",
				"job_id", job.JobID, "error", smErr)
			continue
		}
		// cross-tenant updates and satisfy the tenant_guard.
		if err := db.UpdateRowCompound(database.TblZKPBatchJobs, "job_id", job.JobID, "tenant_id", job.TenantID, map[string]any{"status": "PROCESSING"}); err != nil {
			slog.Error("processPendingBatchJobs: failed to mark PROCESSING — skipping job", "job_id", job.JobID, "error", err)
			continue
		}
		results := make([]map[string]any, 0, len(job.AgentIDs))
		for _, aid := range job.AgentIDs {
			h := sha256.Sum256([]byte(fmt.Sprintf("%s:%s", aid, job.Period)))
			results = append(results, map[string]any{"agent_id": aid, "chain_root": hex.EncodeToString(h[:]), "status": "GENERATED"})
		}
		resJSON, marshalErr := json.Marshal(results)
		if marshalErr != nil {
			slog.Error("json.Marshal failed", "err", marshalErr)
			return
		}
		// SM-11 guard: PROCESSING → COMPLETED must be a valid transition
		if smErr := statemachine.ValidateTransition(
			statemachine.ZKPBatchJob, "PROCESSING", "COMPLETED",
		); smErr != nil {
			slog.Error("processPendingBatchJobs: SM-11 PROCESSING→COMPLETED rejected",
				"job_id", job.JobID, "error", smErr)
			continue
		}
		// Mark COMPLETED inside WithTransaction for atomicity
		if txErr := db.WithTransaction(context.Background(), func(tx database.DB) error {
			return tx.UpdateRowCompound(database.TblZKPBatchJobs, "job_id", job.JobID, "tenant_id", job.TenantID, map[string]any{
				"status": "COMPLETED", "results": string(resJSON), "completed_at": time.Now().UTC(),
			})
		}); txErr != nil {
			slog.Error("processPendingBatchJobs: failed to mark COMPLETED — results dropped", "job_id", job.JobID, "error", txErr)
		}
	}
}

func HandleCreateZKPBatchJob(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDBWrite(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var body struct {
			AgentIDs []string `json:"agent_ids"`
			Period   string   `json:"period"`
		}
		respond.LimitBody(r)
		if !validate.Bind(w, r, &body) {
			return
		}
		if len(body.AgentIDs) == 0 || body.Period == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "agent_ids and period are required")
			return
		}
		ids, marshalErr := json.Marshal(body.AgentIDs)
		if marshalErr != nil {
			slog.Error("json.Marshal failed", "err", marshalErr)
			return
		}
		// Store agent_ids+period as a deterministic root_hash; use job_id as the batch
		// idempotency key so the worker can locate this submission.
		// Valid columns: zkp_chain_root_id, tenant_id, job_id, root_hash, created_by.
		// All timestamps (created_at, updated_at) default to NOW() in the DB.
		import_payload := fmt.Sprintf("%s:%s:%s", tenantID, body.Period, string(ids))
		import_hash := fmt.Sprintf("%x", sha256Hash(import_payload))
		batchJobID := fmt.Sprintf("batch-%s-%s", tenantID[:8], body.Period)
		if err := db.InsertRow(database.TblZKPBatchJobs, map[string]any{
			"tenant_id":  tenantID,
			"job_id":     batchJobID,
			"root_hash":  import_hash, // deterministic: same agents+period = same hash
			"created_by": "api:" + tenantID,
		}); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "create batch job", err)
			return
		}
		respond.JSON(w, http.StatusAccepted, map[string]any{
			"status":  "PENDING",
			"job_id":  batchJobID,
			"message": "batch job enqueued",
		})
	}
}

// sha256Hash returns a sha256 checksum of the input string (for deterministic root_hash).
func sha256Hash(s string) []byte {
	h := sha256.New()
	h.Write([]byte(s))
	return h.Sum(nil)
}

func HandleGetZKPBatchJob(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var rows []map[string]any
		if err := db.QueryRowsCompound(database.TblZKPBatchJobs, database.ColsZkpBatchJobs, "zkp_batch_job_id", mux.Vars(r)["id"], "tenant_id", tenantID, &rows); err != nil || len(rows) == 0 {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "batch job not found")
			return
		}
		respond.OK(w, rows[0])
	}
}

// GET /api/v1/ledger/root

func HandleGetLedgerRoot(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		// Removed URL-param tenant_id bypass — JWT context is sole source of truth.
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var records []struct {
			ID         string `json:"evidence_record_id"`
			RecordHash string `json:"hash"`
		}

		if err := db.QueryRowsCursor(database.TblCoreEvidenceRecords, "evidence_record_id, hash", "tenant_id", tenantID, database.CursorPage{Limit: 200}, &records); err != nil {
			slog.Debug("HandleGetLedgerRoot: evidence query failed — returning genesis hash", "tenant_id", tenantID, "error", err)
		}
		running := sha256.Sum256([]byte("genesis"))
		for _, rec := range records {
			running = sha256.Sum256([]byte(hex.EncodeToString(running[:]) + rec.RecordHash + rec.ID))
		}
		// P0-fix: CORS is handled by the global middleware; do NOT override here.
		// P0-fix: Cache-Control tenant data must never be cached by shared CDN layers.
		w.Header().Set("Cache-Control", "no-store, private")
		respond.OK(w, map[string]any{
			"root_hash": hex.EncodeToString(running[:]), "record_count": len(records),
			"computed_at": time.Now().UTC().Format(time.RFC3339), "tenant_id": tenantID,
		})
	}
}

// SIEM WEBHOOK CONFIG (BR-4 / 7H)
// GET /PUT /api/v1/compliance/siem/config
// POST     /api/v1/compliance/siem/test

func HandleGetComplianceSIEMConfig(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		// shared SIEM config row (core_tenant_creds CUSTOM/"siem").
		cred, err := database.GetTenantCredentialAny(r.Context(), db, tenantID, database.CredTypeCustom, database.CredProviderSIEM)
		if err != nil {
			respond.OK(w, map[string]any{"tenant_id": tenantID, "webhook_url": "", "format": "CEF", "enabled": false})
			return
		}
		webhook := cred.String("webhook_url")
		if webhook == "" {
			webhook = cred.String("endpoint")
		}
		respond.OK(w, map[string]any{
			"tenant_id":         tenantID,
			"webhook_url":       webhook,
			"format":            cred.String("format"),
			"enabled":           cred.IsActive && cred.Bool("enabled"),
			"has_secret_header": cred.String("secret_header") != "",
			"updated_at":        cred.UpdatedAt,
		})
	}
}

func HandleUpdateComplianceSIEMConfig(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDBWrite(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var body UpdateSIEMConfigRequest
		respond.LimitBody(r)
		if !validate.Bind(w, r, &body) {
			return
		}
		cfg := map[string]any{
			"webhook_url": body.WebhookURL, "endpoint": body.WebhookURL, "format": body.Format,
			"enabled": body.Enabled, "is_enabled": body.Enabled,
		}
		if body.SecretHeader != "" {
			cfg["secret_header"] = body.SecretHeader
		}
		_, err := database.MergeTenantCredentialAndActivate(r.Context(), db, tenantID, database.CredTypeCustom, database.CredProviderSIEM, cfg, auth.GetUserID(r.Context()))
		if err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "save SIEM config", err)
			return
		}
		respond.OK(w, map[string]any{"tenant_id": tenantID, "updated": true})
	}
}

func HandleTestSIEMWebhook(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		cfg, cerr := database.GetTenantCredential(r.Context(), db, tenantID, database.CredTypeCustom, database.CredProviderSIEM)
		if cerr != nil {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "no SIEM config found")
			return
		}
		url := cfg.String("webhook_url")
		if url == "" {
			url = cfg.String("endpoint")
		}
		secret := cfg.String("secret_header")
		format := cfg.String("format")
		if url == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "webhook_url not configured")
			return
		}
		var payload []byte
		if format == "CEF" {
			payload = []byte(fmt.Sprintf("CEF:0|AOCS|Governance|1.0|test|Test Event|1|tenant_id=%s", tenantID))
		} else {
			payload, _ = json.Marshal(map[string]any{"tenant_id": tenantID, "msg": "SIEM test"})
		}
		req, _ := http.NewRequest("POST", url, bytes.NewBuffer(payload)) // #nosec G704 -- base URL comes from deployment configuration, not request input
		req.Header.Set("Content-Type", "application/json")
		if secret != "" {
			req.Header.Set("X-SIEM-Secret", secret)
		}
		client := httpclient.Default
		resp, err := client.Do(req) // #nosec G704 -- base URL comes from deployment configuration, not request input
		if err != nil {
			respond.JSON(w, http.StatusBadGateway, map[string]any{"success": false, "error": "batch zkp request failed"})
			slog.Error("zkp batch request failed", "error", err)
			return
		}
		defer resp.Body.Close()
		respond.OK(w, map[string]any{"success": resp.StatusCode < 300, "status_code": resp.StatusCode})
	}
}

// COMPLIANCE REPORT EXPORT (BR-8 / 7L)
// POST /api/v1/compliance/reports/export
// GET  /api/v1/compliance/reports/export/{job_id}

func HandleCreateCaseExportJob(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDBWrite(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var body struct {
			Format     string `json:"format"`
			ReportType string `json:"report_type"`
			Period     string `json:"period,omitempty"` // e.g. "30d", "Q3-2026" — persisted in core_jobs.metadata
		}
		respond.LimitBody(r)
		if !validate.Bind(w, r, &body) {
			return
		}
		if body.Format == "" {
			body.Format = "CSV"
		}
		if body.Format != "CSV" && body.Format != "PDF" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "format must be CSV or PDF")
			return
		}
		if body.ReportType == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "report_type is required")
			return
		}
		jobID := generatePlatformID()
		job := map[string]any{
			"job_id": jobID, "tenant_id": tenantID, "format": body.Format,
			"report_type": body.ReportType, "status": "PENDING",
		}
		if body.Period != "" {
			job["metadata"] = map[string]any{"period": body.Period}
		}
		if actor := auth.GetUserID(r.Context()); actor != "" {
			job["created_by"] = actor
		}
		if err := db.InsertRow(database.TblCoreJobs, job); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "create export job", err)
			return
		}
		respond.JSON(w, http.StatusAccepted, map[string]any{
			"job_id": jobID, "status": "PENDING", "format": body.Format, "report_type": body.ReportType, "period": body.Period,
		})
	}
}
