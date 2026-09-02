package main

import (
	"os"
	"time"

	"github.com/gorilla/mux"
	hsecurity "github.com/ocx/compliance/internal/compliance/handlers/security"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
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
	sybilDetector := security.NewSybilDetector(10, 0.5, nil)
	// SCAN-13 FIX: Read ChallengeVerifier secret from env var (same as aocs-platform).
	// Previously hardcoded to "ocx-compliance-cv-secret" — any operator who knew
	// the string could forge valid challenge responses.
	challengeSecret := []byte(os.Getenv("OCX_CHALLENGE_SECRET"))
	if len(challengeSecret) == 0 {
		slog.Warn("OCX_CHALLENGE_SECRET not set — using insecure default (dev/test only)")
		challengeSecret = []byte("ocx-compliance-cv-secret-dev-only")
	}
	challengeVerifier := security.NewChallengeVerifier(challengeSecret)
	// M3 NOTE: This 100/min inner limiter is intentional defense-in-depth.
	// It applies ONLY to cryptographic endpoints (/nonce, /sybil, /challenge) which
	// are computationally expensive and attractive for DoS. The outer API-level
	// limiter (500/min in main.go) still guards all compliance routes first.
	rateLimiter := security.NewAttackRateLimiter(100, time.Minute)
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
