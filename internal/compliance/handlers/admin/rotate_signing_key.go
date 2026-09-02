package admin

// rotate_signing_key.go — POST /admin/rotate-signing-key
//
// Superadmin-only endpoint that rotates the Ed25519 evidence signing key.
//
// What rotation does:
//  1. Marks the current active key (compliance.platform_signing_keys) as
//     is_active=FALSE, rotated_at=NOW().
//  2. Generates a new Ed25519 keypair.
//  3. AES-256-GCM encrypts the private key with PLATFORM_MASTER_KEY.
//  4. Inserts the new row as is_active=TRUE.
//  5. Returns the new key_id.
//
// Historic evidence rows retain their signing_key_id — verification of old
// evidence still works because GetSigningKeyByID() looks up by key_id, not
// by is_active.
//
// The in-memory ZKPVerifier is NOT hot-reloaded by this endpoint — the
// compliance pod must be restarted (or rolled) to pick up the new public key
// for issuing NEW challenges. Existing challenges expire (defaultChallengeTTL).
//
// Authorization: SuperAdmin only — enforced by middleware.SuperAdminGuard.

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/infra/security"
)

// RotateSigningKeyDB is the DB interface needed by the rotate handler.
type RotateSigningKeyDB interface {
	security.SigningKeyDB
}

// HandleRotateSigningKey returns a SuperAdmin-only HTTP handler that rotates
// the active Ed25519 evidence signing key.
//
// POST /admin/rotate-signing-key
// Authorization: Bearer <superadmin-jwt>
// Response 200: { "status": "rotated", "new_key_id": "sk_XXXX" }
// Response 500: { "error": "..." }
func HandleRotateSigningKey(db RotateSigningKeyDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		masterKey := os.Getenv("PLATFORM_MASTER_KEY")
		if masterKey == "" {
			respond.JSON(w, http.StatusServiceUnavailable, map[string]string{
				"error": "PLATFORM_MASTER_KEY not configured — key rotation unavailable",
			})
			return
		}

		newKeyID, err := security.RotateSigningKey(r.Context(), db, masterKey)
		if err != nil {
			slog.Error("signing key rotation failed",
				"error", err,
				"endpoint", "POST /admin/rotate-signing-key",
			)
			respond.JSON(w, http.StatusInternalServerError, map[string]string{
				"error": "key rotation failed: " + err.Error(),
			})
			return
		}

		slog.Info("S2: signing key rotated successfully",
			"new_key_id", newKeyID,
			"note", "compliance pod must restart to use new key for issuing ZKP challenges",
		)

		respond.JSON(w, http.StatusOK, map[string]string{
			"status":     "rotated",
			"new_key_id": newKeyID,
			"note":       "restart compliance pod to activate new public key for ZKP challenge issuing",
		})
	}
}
