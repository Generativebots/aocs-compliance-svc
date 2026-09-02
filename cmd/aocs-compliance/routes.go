package main

import (
	"os"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	hadmin "github.com/ocx/compliance/internal/compliance/handlers/admin"
	hsecurity "github.com/ocx/compliance/internal/compliance/handlers/security"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/middleware"
	"github.com/ocx/shared/infra/security"
	"github.com/ocx/shared/infra/serviceclient"
	"log/slog"
)

// routes.go — Route coordinator for aocs-compliance.
//
// aocs-compliance owns the COMPLIANCE LAYER:
//   routes_compliance.go → /compliance/*, /violations/*, /zkp/*, /evidence/*,
//                          /sanctions/*, /dlp/*, /rlhc/*, /regulator-*,
//                          /gra/compliance-*, /gra/regulatory-frameworks
//
// registerIntelComplianceRoutes has 28 params — all non-compliance deps are nil.
// Compliance handlers guard nil params at call site.
// ZKP verifier is constructed internally inside registerIntelComplianceRoutes.

func registerComplianceRoutes(
	api *mux.Router,
	db *database.SupabaseClient,
	pc *auth.PermissionChecker,
	pgx *database.PGXPool,
	dlpStore *hsecurity.DLPStore,
	coreClient *serviceclient.Client,
) {
	// ── SecurityManager — lightweight, all in-memory, no external deps ────────
	// Required to register /nonce/validate, /sybil/check, /security/attacks etc.
	// which are gated on secMgr != nil in registerIntelComplianceRoutes.
	nonceStore := security.NewNonceStore(15 * time.Minute)

	// S3 Fix: Cross-pod collusion detection backed by Supabase.
	// Redis L1 not available here (no Redis client injected into routes).
	// DB-only mode is valid — Redis L1 is additive performance optimization.
	var collusionStore security.CollusionStore
	if db != nil {
		collusionStore = security.NewDBCollusionStore(db, nil) // nil redis = DB-only
		slog.Info("S3: CollusionStore wired (DB mode — Redis L1 not wired in compliance)")
	}
	// Sybil detector thresholds read from env (panic in prod if unset).
	sybilMinConn, _ := strconv.Atoi(os.Getenv("SYBIL_MIN_CONNECTIONS"))
	if sybilMinConn <= 0 {
		sybilMinConn = 10 // safe default for dev
	}
	sybilThresh, _ := strconv.ParseFloat(os.Getenv("SYBIL_COLLUSION_THRESHOLD"), 64)
	if sybilThresh <= 0 {
		sybilThresh = 0.5
	}
	sybilDetector := security.NewSybilDetector(sybilMinConn, sybilThresh, nil)
	if collusionStore != nil {
		sybilDetector = sybilDetector.WithCollusionStore(collusionStore)
		slog.Info("S3: SybilDetector upgraded to cross-pod CollusionStore")
	}

	// S2 Fix: Load (or create once) the persistent Ed25519 signing key.
	// LoadOrCreateSigningKey reads from compliance.platform_signing_keys.
	// If no active key exists, it generates one and persists it.
	// PLATFORM_MASTER_KEY must be set — absent → fails-fast (by design).
	masterKey := os.Getenv("PLATFORM_MASTER_KEY")
	if masterKey != "" && db != nil {
		if _, err := security.LoadOrCreateSigningKey(nil, db, masterKey); err != nil {
			slog.Error("S2: LoadOrCreateSigningKey failed — evidence signing will use ZKPVerifier fallback",
				"error", err,
			)
		} else {
			slog.Info("S2: Persistent Ed25519 signing key loaded from DB")
		}
	} else {
		slog.Warn("S2: PLATFORM_MASTER_KEY not set or DB unavailable — signing key not loaded (dev/test only)")
	}

	// ── Admin routes (SuperAdmin only) ────────────────────────────────────────
	// POST /admin/rotate-signing-key — rotates the persistent Ed25519 key (S2)
	// SuperAdminRequired wraps the handler: blocks non-superadmin at HTTP layer.
	if pgx != nil {
		api.Handle("/admin/rotate-signing-key",
			middleware.SuperAdminRequired(pgx, hadmin.HandleRotateSigningKey(db))).
			Methods("POST")
		slog.Info("S2: POST /admin/rotate-signing-key registered (SuperAdmin only)")
	} else {
		slog.Warn("S2: /admin/rotate-signing-key NOT registered — pgx pool unavailable")
	}

	// SCAN-13: ChallengeVerifier secret — must be set in production via OCX_CHALLENGE_SECRET.
	challengeSecret := []byte(os.Getenv("OCX_CHALLENGE_SECRET"))
	if len(challengeSecret) == 0 {
		if os.Getenv("GOOGLE_CLOUD_PROJECT") != "" {
			panic("OCX_CHALLENGE_SECRET must be set in production — refusing to start with insecure default")
		}
		slog.Warn("OCX_CHALLENGE_SECRET not set — using insecure default (dev/test only)")
		challengeSecret = []byte("ocx-compliance-cv-secret-dev-only")
	}
	challengeVerifier := security.NewChallengeVerifier(challengeSecret)
	// M3 NOTE: This inner limiter applies ONLY to expensive crypto endpoints (/nonce, /sybil, /challenge).
	// SECURITY_RATE_LIMIT_RPM env allows ops to tune without redeployment.
	rateLimitRPM, _ := strconv.Atoi(os.Getenv("SECURITY_RATE_LIMIT_RPM"))
	if rateLimitRPM <= 0 {
		rateLimitRPM = 100
	}
	rateLimiter := security.NewAttackRateLimiter(rateLimitRPM, time.Minute)
	secMgr := security.NewSecurityManager(nonceStore, sybilDetector, challengeVerifier, rateLimiter)

	registerIntelComplianceRoutes(
		api, db, pc, pgx,
		dlpStore,
		nil,    // entropyMonitor — wire *escrow.EntropyMonitorLive adapter when aocs-hub is available
		secMgr,
		os.Getenv("INTENT_EXTRACTOR_URL"),
		coreClient,
	)
}
