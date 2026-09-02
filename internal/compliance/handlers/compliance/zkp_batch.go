// Package compliance — HITL / edge-case resolution handlers.
//
// Gathers: Cases, ZKP (chain, export, batch), Ledger Root, SIEM config, Report Export.
package compliance

import (
	"context"
	"github.com/ocx/shared/infra/httpclient"
	"bytes"
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
	"github.com/ocx/shared/infra/statemachine"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

// processPendingBatchJobs is a trusted server-side background goroutine.
//   - This runs inside the aocs-platform process, not reachable from the network.
//   - Each job row was created by HandleCreateZKPBatchJob with an explicit tenant_id.
//   - All UpdateRow calls scope by job_id (UUID) — no cross-tenant mutation.
//   - Jobs are isolated: results per-job reference only the agent_ids encoded in that job.
//
// If multi-tenant job isolation is needed in future, add a tenant iteration loop.
func processPendingBatchJobs(ctx context.Context, db database.DB) {
	var jobs []struct {
		JobID    string   `json:"job_id"`
		TenantID string   `json:"tenant_id"`
		AgentIDs []string `json:"agent_ids"`
		Period   string   `json:"period"`
	}
	if err := db.QueryRowsCursor(database.TblZKPBatchJobs, "job_id, tenant_id, agent_ids, period", "status", "PENDING", database.CursorPage{Limit: 200}, &jobs); err != nil {
		return
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
		// Mark COMPLETED — if this fails, the job stays PROCESSING and won't be retried
		// (PROCESSING is not picked up by the PENDING query). Log as error: results are dropped.
		if err := db.UpdateRowCompound(database.TblZKPBatchJobs, "job_id", job.JobID, "tenant_id", job.TenantID, map[string]any{
			"status": "COMPLETED", "results": string(resJSON), "completed_at": time.Now().UTC(),
		}); err != nil {
			slog.Error("processPendingBatchJobs: failed to mark COMPLETED — results dropped", "job_id", job.JobID, "error", err)
		}
	}
}

func HandleCreateZKPBatchJob(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
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
			"tenant_id": tenantID,
			"job_id":    batchJobID,
			"root_hash": import_hash, // deterministic: same agents+period = same hash
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
		// SEC-5 FIX: Removed URL-param tenant_id bypass — JWT context is sole source of truth.
		// Previously a caller could read any tenant's ledger root by supplying ?tenant_id=<other>.
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var records []struct {
			ID         string `json:"evidence_record_id"`
			RecordHash string `json:"hash"`
		}

		if err := db.QueryRowsCursor(database.TblQCoreEvidenceRecords, "evidence_record_id, hash", "tenant_id", tenantID, database.CursorPage{Limit: 200}, &records); err != nil {
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
		var rows []map[string]any
		if err := db.QueryRowsCursor(database.TblTenantCredentials, database.ColsSiemConfigs, "tenant_id", tenantID, database.CursorPage{Limit: 200}, &rows); err != nil || len(rows) == 0 {
			respond.OK(w, map[string]any{"tenant_id": tenantID, "webhook_url": "", "format": "CEF", "enabled": false})
			return
		}
		respond.OK(w, rows[0])
	}
}

func HandleUpdateComplianceSIEMConfig(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
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
			"tenant_id": tenantID, "webhook_url": body.WebhookURL, "format": body.Format,
			"enabled": body.Enabled, "secret_header": body.SecretHeader,
		}
		var ex []map[string]any
		// L0-E CAT-D FIX: existence check determines INSERT vs UPDATE path.
		// If this read fails and we default to INSERT, we get a duplicate-key error on every call.
		// Role enrichment: non-critical — if this fails, user response is returned without roles.
		readErr := db.QueryRowsCursor(database.TblTenantCredentials, "tenant_id", "tenant_id", tenantID, database.CursorPage{Limit: 200}, &ex)
		if readErr != nil {
			slog.Error("HandleUpsertSIEMConfig: existence check failed", "tenant_id", tenantID, "error", readErr)
			respond.ErrorWithCode(w, http.StatusServiceUnavailable, respond.ErrCodeUnavailable, "SIEM config temporarily unavailable — retry")
			return
		}
		var err error
		if len(ex) == 0 {
			err = db.InsertRow(database.TblSIEMConfigs, cfg)
		} else {
			err = db.UpdateRow(database.TblSIEMConfigs, "tenant_id", tenantID, cfg)
		}
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
		var rows []map[string]any
		if err := db.QueryRowsCursor(database.TblTenantCredentials, database.ColsSiemConfigs, "tenant_id", tenantID, database.CursorPage{Limit: 200}, &rows); err != nil || len(rows) == 0 {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "no SIEM config found")
			return
		}
		cfg := rows[0]
		url, _ := cfg["webhook_url"].(string)
		secret, _ := cfg["secret_header"].(string)
		format, _ := cfg["format"].(string)
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
		req, _ := http.NewRequest("POST", url, bytes.NewBuffer(payload))
		req.Header.Set("Content-Type", "application/json")
		if secret != "" {
			req.Header.Set("X-SIEM-Secret", secret)
		}
		client := httpclient.Default
		resp, err := client.Do(req)
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
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var body struct {
			Format     string `json:"format"`
			ReportType string `json:"report_type"`
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
		if err := db.InsertRow(database.TblExportJobs, map[string]any{
			"job_id": jobID, "tenant_id": tenantID, "format": body.Format,
			"report_type": body.ReportType, "status": "PENDING",
		}); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "create export job", err)
			return
		}
		respond.JSON(w, http.StatusAccepted, map[string]any{
			"job_id": jobID, "status": "PENDING", "format": body.Format, "report_type": body.ReportType,
		})
	}
}
