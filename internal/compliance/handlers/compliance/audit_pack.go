package compliance

// audit_pack.go — POST /compliance/audit-pack
//
// Builds a signed, offline-verifiable evidence bundle (zip) for auditors:
//
//	evidence.json     compl_evidence rows of the tenant (optionally one month)
//	obligations.json  compl_obligations rows (optionally one framework)
//	ledger.json       Merkle ledger slice (lv_merkle_ledger) + VerifyChain result
//	manifest.json     SHA-256 and size of every file above, plus key id / public key
//	manifest.sig      hex Ed25519 signature over the exact bytes of manifest.json
//	verify.py         standalone checker (hashes: stdlib only; signature: needs `cryptography`)
//
// Signing (F-08): each tenant gets its own Ed25519 key, derived deterministically from the platform
// key (compl_signing_keys, unwrapped with PLATFORM_MASTER_KEY) so nothing extra is stored. The tenant
// key signs the manifest; the platform key signs a certificate binding that tenant key to the tenant
// id (manifest.tenant_key_cert). A verifier trusts the platform public key, checks the certificate,
// then checks the manifest. Rotating the platform key keeps old packs verifiable because both public
// keys are embedded in the manifest.
//
// The zip is streamed straight to the HTTP response (no whole-archive buffer).

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/infra/ledger"
	"github.com/ocx/shared/infra/security"
	"github.com/ocx/shared/logger"
	"github.com/ocx/shared/respond"
)

var auditPackPeriod = regexp.MustCompile(`^\d{4}-(0[1-9]|1[0-2])$`)

// auditPackMaxRows bounds each section so a pack cannot exhaust memory.
const auditPackMaxRows = 10000

// AuditPackFile is one named file of the bundle.
type AuditPackFile struct {
	Name string
	Data []byte
}

type manifestFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

// BuildAuditPack zips the files, writes manifest.json (hashes + metadata), signs it and
// appends verify.py. It is pure so it can be tested without a database.
func BuildAuditPack(meta map[string]any, files []AuditPackFile, keyID string, priv ed25519.PrivateKey) ([]byte, error) {
	var buf bytes.Buffer
	if err := WriteAuditPack(&buf, meta, files, keyID, priv); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DeriveTenantKey derives the tenant's audit-pack signing key from the platform key and returns it
// with a certificate (platform signature over tenant id + tenant public key). Deterministic: the same
// platform key and tenant always give the same tenant key, and different tenants never share one.
func DeriveTenantKey(platform ed25519.PrivateKey, tenantID string) (ed25519.PrivateKey, []byte, error) {
	if len(platform) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("audit pack: invalid platform key")
	}
	if tenantID == "" {
		return nil, nil, fmt.Errorf("audit pack: tenant id required")
	}
	mac := hmac.New(sha256.New, platform.Seed())
	mac.Write([]byte("aocs-audit-pack-tenant-key|" + tenantID))
	priv := ed25519.NewKeyFromSeed(mac.Sum(nil))
	pub := priv.Public().(ed25519.PublicKey)
	return priv, ed25519.Sign(platform, tenantKeyCertMessage(tenantID, pub)), nil
}

func tenantKeyCertMessage(tenantID string, pub ed25519.PublicKey) []byte {
	return []byte("aocs-tenant-key|" + tenantID + "|" + hex.EncodeToString(pub))
}

// WriteAuditPack streams the signed bundle to w. Files are written first, then manifest.json,
// manifest.sig and verify.py; the manifest is computed from the in-memory file bytes before any
// byte is written, so the signature always covers exactly what is in the archive.
func WriteAuditPack(w io.Writer, meta map[string]any, files []AuditPackFile, keyID string, priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("audit pack: invalid signing key")
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	entries := make([]manifestFile, 0, len(files))
	for _, f := range files {
		sum := sha256.Sum256(f.Data)
		entries = append(entries, manifestFile{Name: f.Name, SHA256: hex.EncodeToString(sum[:]), Bytes: len(f.Data)})
	}
	pub := priv.Public().(ed25519.PublicKey)
	manifest := map[string]any{
		"version":    1,
		"algorithm":  "ed25519",
		"key_id":     keyID,
		"public_key": hex.EncodeToString(pub),
		"files":      entries,
	}
	for k, v := range meta {
		manifest[k] = v
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	sig := hex.EncodeToString(ed25519.Sign(priv, manifestBytes))

	zw := zip.NewWriter(w)
	write := func(name string, data []byte) error {
		fw, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = fw.Write(data)
		return err
	}
	for _, f := range files {
		if err := write(f.Name, f.Data); err != nil {
			return err
		}
	}
	if err := write("manifest.json", manifestBytes); err != nil {
		return err
	}
	if err := write("manifest.sig", []byte(sig)); err != nil {
		return err
	}
	if err := write("verify.py", []byte(auditPackVerifyPy)); err != nil {
		return err
	}
	return zw.Close()
}

func mustJSON(v any) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return []byte("null")
	}
	return b
}

// filterRows keeps rows whose any of the given timestamp keys starts with prefix ("" keeps all).
func filterRows(rows []map[string]any, prefix string, keys ...string) []map[string]any {
	if prefix == "" {
		return rows
	}
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		for _, k := range keys {
			if s, _ := r[k].(string); strings.HasPrefix(s, prefix) {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

func capRows(rows []map[string]any) []map[string]any {
	if len(rows) > auditPackMaxRows {
		return rows[:auditPackMaxRows]
	}
	return rows
}

// sectionCount describes one pack section for the manifest: how many rows exist, how many are
// included, and whether the row cap truncated it.
func sectionCount(total int) map[string]any {
	included := total
	if included > auditPackMaxRows {
		included = auditPackMaxRows
	}
	return map[string]any{"total": total, "included": included, "truncated": total > included}
}

// HandleAuditPack — POST /api/v1/compliance/audit-pack {framework?, period?("YYYY-MM")}
func HandleAuditPack(db *database.SupabaseClient, pgx *database.PGXPool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var req struct {
			Framework string `json:"framework"`
			Period    string `json:"period"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
		if r.ContentLength != 0 {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "invalid JSON body")
				return
			}
		}
		if req.Period != "" && !auditPackPeriod.MatchString(req.Period) {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeValidation, "period must be YYYY-MM")
			return
		}
		if len(req.Framework) > 64 {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeValidation, "framework too long")
			return
		}
		if pgx == nil || pgx.Pool() == nil {
			respond.Error(w, http.StatusServiceUnavailable, "audit pack unavailable: no database pool for ledger verification")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		key, err := security.LoadOrCreateSigningKey(ctx, db, os.Getenv("PLATFORM_MASTER_KEY"))
		if err != nil {
			logger.For("compliance/audit_pack").Error("signing key unavailable", "error", err)
			respond.Error(w, http.StatusServiceUnavailable, "audit pack unavailable: signing key not configured")
			return
		}

		var evidence, obligations, ledgerRows []map[string]any
		if err := db.QueryRowsCtx(ctx, database.TblComplEvidence, "*", "tenant_id", tenantID, &evidence); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "read evidence", err)
			return
		}
		if err := db.QueryRowsCtx(ctx, database.TblComplObligations, "*", "tenant_id", tenantID, &obligations); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "read obligations", err)
			return
		}
		if err := db.QueryRowsCtx(ctx, database.TblMerkleLedger,
			"reference_id,gate_id,verdict,previous_hash,current_hash,recorded_at",
			"tenant_id", tenantID, &ledgerRows); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "read ledger", err)
			return
		}
		report, err := ledger.NewLedgerStore(pgx.Pool()).VerifyChain(ctx, tenantID)
		if err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "verify ledger chain", err)
			return
		}

		if req.Framework != "" {
			kept := obligations[:0:0]
			for _, o := range obligations {
				if f, _ := o["framework"].(string); strings.EqualFold(f, req.Framework) {
					kept = append(kept, o)
				}
			}
			obligations = kept
		}
		evidence = filterRows(evidence, req.Period, "created_at", "collected_at")
		ledgerRows = filterRows(ledgerRows, req.Period, "recorded_at")
		// Totals are taken before capping so the signed manifest discloses any truncation.
		sections := map[string]any{
			"evidence":    sectionCount(len(evidence)),
			"obligations": sectionCount(len(obligations)),
			"ledger":      sectionCount(len(ledgerRows)),
		}
		evidence, ledgerRows, obligations = capRows(evidence), capRows(ledgerRows), capRows(obligations)

		files := []AuditPackFile{
			{Name: "evidence.json", Data: mustJSON(evidence)},
			{Name: "obligations.json", Data: mustJSON(obligations)},
			{Name: "ledger.json", Data: mustJSON(map[string]any{"entries": ledgerRows, "chain_verification": report})},
		}
		meta := map[string]any{
			"tenant_id":    tenantID,
			"framework":    req.Framework,
			"period":       req.Period,
			"generated_at": time.Now().UTC().Format(time.RFC3339),
			"row_cap":      auditPackMaxRows,
			"sections":     sections,
		}
		tenantPriv, cert, err := DeriveTenantKey(key.PrivateKey, tenantID)
		if err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "derive tenant signing key", err)
			return
		}
		meta["platform_key_id"] = key.KeyID
		meta["platform_public_key"] = hex.EncodeToString(key.PrivateKey.Public().(ed25519.PublicKey))
		meta["tenant_key_cert"] = hex.EncodeToString(cert)

		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", `attachment; filename="audit-pack.zip"`)
		w.WriteHeader(http.StatusOK)
		// Streamed: headers are out, so a failure now can only be logged (the client sees a truncated zip,
		// which fails verification by construction).
		if err := WriteAuditPack(w, meta, files, key.KeyID+"/"+tenantID, tenantPriv); err != nil {
			logger.For("compliance/audit_pack").Error("audit pack stream failed", "tenant_id", tenantID, "error", err)
		}
	}
}

const auditPackVerifyPy = `#!/usr/bin/env python3
"""Offline verifier for an AOCS audit pack. Run inside the unzipped folder.

Checks the SHA-256 of every file against manifest.json. If the 'cryptography'
package is installed it also verifies the Ed25519 signature over manifest.json.
"""
import hashlib, json, sys

manifest_bytes = open("manifest.json", "rb").read()
manifest = json.loads(manifest_bytes)
ok = True
for f in manifest["files"]:
    digest = hashlib.sha256(open(f["name"], "rb").read()).hexdigest()
    good = digest == f["sha256"]
    ok &= good
    print(("OK   " if good else "FAIL ") + f["name"])

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(manifest["public_key"]))
    pub.verify(bytes.fromhex(open("manifest.sig").read().strip()), manifest_bytes)
    print("OK   manifest signature (key %s)" % manifest["key_id"])
    # The tenant key must be certified by the platform key (trust anchor).
    if manifest.get("tenant_key_cert"):
        plat = Ed25519PublicKey.from_public_bytes(bytes.fromhex(manifest["platform_public_key"]))
        msg = ("aocs-tenant-key|%s|%s" % (manifest["tenant_id"], manifest["public_key"])).encode()
        plat.verify(bytes.fromhex(manifest["tenant_key_cert"]), msg)
        print("OK   tenant key certificate (platform key %s)" % manifest["platform_key_id"])
        print("NOTE compare platform_public_key with the one AOCS published for you")
except ImportError:
    print("SKIP signature checks: pip install cryptography to verify them")
except Exception:
    ok = False
    print("FAIL signature or key certificate")

sys.exit(0 if ok else 1)
`
