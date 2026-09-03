package main

// aocs-compliance: Compliance Engine — ZKP, DLP, violations, sanctions, audit.
//
// Owns:
//   - ZKP proof generation + batch worker pool
//   - DLP scanning + marketplace + webhook integrations
//   - Violation CRUD + resolve/release/quarantine/comments
//   - Sanctions CRUD + appeal
//   - CAE session audit logs
//   - Platform audit permission log
//   - Admin: audit-log, policy-extractions
//
// Cloud Run: 1vCPU, 512Mi, min-instances=0 (scale-to-zero), ingress=internal,
//            timeout=300s (ZKP batch jobs can be slow)
// Local port: 8085 (via AOCS_COMPLIANCE_PORT env var)

import (
	"log/slog"
	"net/http"
	"os"
	"time"

	// Handler packages
	hcompliance "github.com/ocx/compliance/internal/compliance/handlers/compliance"
	hsecurity "github.com/ocx/compliance/internal/compliance/handlers/security"

	// Infrastructure
	"github.com/ocx/shared/infra/config"
	"github.com/ocx/shared/infra/license"
	"github.com/ocx/shared/infra/middleware"
	"github.com/ocx/shared/infra/routecheck"
	"github.com/ocx/shared/infra/security"
	"github.com/ocx/shared/infra/serviceclient"
	"github.com/ocx/shared/svcboot"
	"golang.org/x/time/rate"
)

func main() {
	config.MustValidateRequired()
	// NEW-04 FIX: Read PORT from env so Cloud Run health checks work correctly.
	// Cloud Run injects PORT at startup — hardcoding "8085" bypasses it.
	compliancePort := os.Getenv("PORT")
	if compliancePort == "" {
		// PRD-04 FIX: log collision risk when defaulting.
		slog.Warn("PRD-04: PORT env var not set — defaulting to 8085. "+
			"Ensure this does not conflict with aocs-intel or aocs-studio "+
			"on co-located (non-Cloud Run) deployments.",
			"service", "aocs-compliance", "default_port", "8085",
		)
		compliancePort = "8085"
	}
	svc := svcboot.Boot("aocs-compliance", compliancePort)

	api := svc.API
	db := svc.DB
	pc := svc.PermChecker
	pgx := svc.PGXPool
	cfg := config.Get()

	_ = cfg // used by zkpVerifier and handlers

	// ── ocx-core-svc Service Client ─────────────────────────────────────────────────
	// Used by DLP handlers, GRA handlers, compliance report worker, and dashboards.
	r1URL := os.Getenv("INTERNAL_API_URL")
	if r1URL == "" {
		// PRD-02 FIX: aocs-system-svc runs on :8082, NOT :8080.
		r1URL = "http://aocs-platform:8082"
	}
	coreClient := serviceclient.New(
		"aocs-compliance",
		r1URL,
		os.Getenv("SERVICE_JWT_SECRET"),
		&http.Client{Timeout: 15 * time.Second},
	)

	// ── ZKP Batch Worker Pool (3 goroutines, 30s polling) ───────────────────
	// Processes pending batch ZKP jobs from the DB queue.
	hcompliance.StartZKPBatchWorkerPool(svc.BgCtx, db)
	slog.Info("ZKPBatchWorkerPool started", "workers", 3)

	// P-18 FIX: Start daily compliance report generator.
	// Was implemented in report_worker.go but never started — patent test P-18 requires
	// nexus_compliance_reports to have a row created by today's daily 00:00 UTC run.
	hcompliance.StartReportGenerator(svc.BgCtx, db, coreClient)
	slog.Info("P-18: ComplianceReportWorker started — daily 00:00 UTC report generation")

	// P-16 FIX: Start daily Sybil detection worker.
	// Was implemented in sybil_resistance_worker.go but never started — patent test P-16
	// requires core_trust_events (cross_org=true rows) to be created at daily 03:00 UTC.
	// NOTE: shar_trust was merged into core_trust_events — TblSybilRiskAssess now resolves
	// to "core_trust_events". Rows written with cross_org=false (sybil = single-tenant concern).
	hsecurity.StartSybilDetectionWorker(svc.BgCtx, db)
	slog.Info("P-16: SybilDetectionWorker started — daily 03:00 UTC sybil scan")

	// ── DLP Store ───────────────────────────────────────────────────────────
	dlpStore := hsecurity.NewDLPStore(db, coreClient)

	// M3 FIX: Use time.Minute constant instead of raw 60_000_000_000 nanoseconds.
	// Three-layer rate limiting for compliance:
	//   Layer 1 (API Gateway quota): per-consumer sliding window (300 req/min default).
	//   Layer 2 (Cloud Armor): IP-level DDoS protection.
	//   Layer 3a (here): 500/min — global HTTP guard for ALL compliance routes.
	//   Layer 3b (SecurityManager in routes.go): 100/min — tighter guard on
	//     sensitive cryptographic endpoints only (/nonce/validate, /sybil/check,
	//     /security/attacks). These are more expensive to compute and more
	//     attractive attack targets, so they get a stricter inner limit.
	// T1 FIX: Transform JSON response keys from snake_case → camelCase.
	svc.API.Use(middleware.CamelCaseResponse())
	complianceRL := security.NewAttackRateLimiter(500, time.Minute)
	svc.API.Use(middleware.AttackRateLimiterMiddleware(complianceRL))
	// Per-tenant token bucket (50 req/s, burst 100) — defense-in-depth layer.
	svc.API.Use(middleware.TenantRateLimiter(rate.Limit(50), 100, 5*time.Minute, "X-Tenant-ID"))
	slog.Info("SEC-RL-COMPLIANCE: AttackRateLimiter + TenantRateLimiter wired on svc.API",
		"global_limit", 500, "tenant_limit_rps", 50, "window", "1m")

	// LICENSE ENFORCEMENT: JWT-claims-based — zero DB calls per request.
	// 1. LicenseTamperGuard: 403 TOTAL HALT if contract tampered
	// 2. LicenseOperationalGuard: 402 WRITE BLOCK if payment failed
	// 3. LicenseFeatureGuard("compliance"): 403 if compliance module not in plan
	for _, mw := range middleware.LicenseStack() {
		svc.API.Use(mw)
	}
	svc.API.Use(middleware.LicenseFeatureGuard(license.FeatureCompliance))
	slog.Info("LICENSE: TamperGuard + OperationalGuard + FeatureGuard(compliance) wired on svc.API")
	// Fail-open: errors are logged, never block compliance recording.
	if db != nil {
		svc.API.Use(middleware.UsageMetering(db))
		slog.Info("UsageMetering wired on aocs-compliance API")
	}

	// ── Route registration ──────────────────────────────────────────────────────────────────
	registerComplianceRoutes(api, db, pc, pgx, dlpStore, coreClient)

	// Validate no duplicate path+method registrations — panics at startup if any
	// route is silently shadowed. gorilla/mux has no built-in duplicate detection.
	routecheck.ValidateNoDuplicates(svc.API)

	svcboot.Serve(svc)
}

func init() {
	level := slog.LevelInfo
	if os.Getenv("LOG_LEVEL") == "debug" {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})))
}
