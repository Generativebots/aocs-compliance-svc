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

// auditPackPageSize is how many rows are fetched per database round trip while a section is
// spooled to disk (CM-05). Sections are NOT truncated: memory use is bounded by the page size,
// not by the tenant's row count.
const auditPackPageSize = 1000

// AuditPackFile is one named file of the bundle. Either Data holds the bytes, or Path names a
// spool file already written (its SHA-256 and size were computed while writing).
type AuditPackFile struct {
	Name string
	Data []byte
	Path string

	sha  string // set for Path-backed files
	size int
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
		if f.Path != "" {
			entries = append(entries, manifestFile{Name: f.Name, SHA256: f.sha, Bytes: f.size})
			continue
		}
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
		if f.Path == "" {
			if err := write(f.Name, f.Data); err != nil {
				return err
			}
			continue
		}
		if err := copySpooled(zw, f); err != nil {
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
		// Large tenants need minutes, not seconds: the pack is paged to disk, not held in memory.
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
		defer cancel()

		key, err := security.LoadOrCreateSigningKey(ctx, db, os.Getenv("PLATFORM_MASTER_KEY"))
		if err != nil {
			logger.For("compliance/audit_pack").Error("signing key unavailable", "error", err)
			respond.Error(w, http.StatusServiceUnavailable, "audit pack unavailable: signing key not configured")
			return
		}

		report, err := ledger.NewLedgerStore(pgx.Pool()).VerifyChain(ctx, tenantID)
		if err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "verify ledger chain", err)
			return
		}
		reportJSON, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "encode ledger report", err)
			return
		}

		spoolDir, err := os.MkdirTemp("", "audit-pack-*")
		if err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "audit pack spool", err)
			return
		}
		defer func() { _ = os.RemoveAll(spoolDir) }()

		files, sections, err := spoolAuditSections(ctx, pgx, spoolDir, tenantID, req.Framework, req.Period, reportJSON)
		if err != nil {
			logger.For("compliance/audit_pack").Error("audit pack spool failed", "tenant_id", tenantID, "error", err)
			respond.InternalError(w, http.StatusInternalServerError, "build audit pack", err)
			return
		}
		meta := map[string]any{
			"tenant_id":    tenantID,
			"framework":    req.Framework,
			"period":       req.Period,
			"generated_at": time.Now().UTC().Format(time.RFC3339),
			"page_size":    auditPackPageSize,
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
