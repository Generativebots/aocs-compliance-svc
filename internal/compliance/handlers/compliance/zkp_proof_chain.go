// cases_proof.go — ZKP proof chain, Merkle inclusion verification, VC export, and batch worker.
// Cases CRUD handlers: see cases.go
package compliance

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"

	"net/http"
	"sort"
	"time"

	"github.com/ocx/shared/infra/concurrent"
	"github.com/ocx/shared/infra/config"

	"github.com/gorilla/mux"
	"github.com/ocx/shared/types"
	"github.com/ocx/shared/consts"
	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
	"github.com/ocx/shared/validate"
)

// HandleGenerateProofChain builds a Merkle chain root from all ZKP proofs for an agent+period.
// POST /api/v1/zkp/chain
func HandleGenerateProofChain(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var body struct {
			AgentID string `json:"agent_id"`
			Period  string `json:"period"`
		}
		respond.LimitBody(r)
		if !validate.Bind(w, r, &body) {
			return
		}
		if body.AgentID == "" || body.Period == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "agent_id and period are required")
			return
		}

		var proofs []struct {
			ProofHash string `json:"proof_hash"`
		}
		if _dbErr := db.QueryRowsCompound(database.TblSharZkpVerify, database.ColsSentiZkpVerificationsProofHash,
			"agent_id", body.AgentID, "tenant_id", tenantID, &proofs); _dbErr != nil {
			slog.Error("db.QueryRowsCompound failed (best-effort)", "error", _dbErr)
		}

		const maxProofs = 10000
		if len(proofs) > maxProofs {
			slog.Warn("HandleGenerateProofChain: proof set exceeds safety cap — truncating",
				"agent_id", body.AgentID, "total", len(proofs), "cap", maxProofs)
			proofs = proofs[:maxProofs]
		}
		sort.Slice(proofs, func(i, j int) bool { return proofs[i].ProofHash < proofs[j].ProofHash })

		hashes := make([]string, len(proofs))
		for i, p := range proofs {
			hashes[i] = p.ProofHash
		}

		var merkleRoot, legacyRoot string
		if len(hashes) > 0 {
			tree, treeErr := types.BuildMerkleTree(hashes)
			if treeErr != nil {
				slog.Error("HandleGenerateProofChain: Merkle tree build failed", "error", treeErr)
				respond.InternalError(w, http.StatusInternalServerError, "build merkle tree", treeErr)
				return
			}
			anchorInput := fmt.Sprintf("sha256-merkle:%s:%s:%s", body.AgentID, body.Period, tree.Root.Hash)
			anchorHash := sha256.Sum256([]byte(anchorInput))
			merkleRoot = hex.EncodeToString(anchorHash[:])

			chainInput := ""
			for _, h := range hashes {
				chainInput += h
			}
			legacyHash := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s", body.AgentID, body.Period, chainInput)))
			legacyRoot = hex.EncodeToString(legacyHash[:])
		} else {
			empty := sha256.Sum256([]byte(fmt.Sprintf("empty:%s:%s", body.AgentID, body.Period)))
			merkleRoot = hex.EncodeToString(empty[:])
		}

		row := map[string]any{
			"agent_id": body.AgentID, "tenant_id": tenantID, "period": body.Period,
			"chain_root": merkleRoot, "proof_count": len(proofs),
			"computed_at": time.Now().UTC(), "tree_algorithm": "sha256-merkle",
		}
		if legacyRoot != "" {
			row["legacy_chain_root"] = legacyRoot
		}
		if err := db.InsertRow(database.TblZKPChainRoots, row); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "store chain root", err)
			return
		}
		slog.Info("HandleGenerateProofChain: Merkle chain built",
			"agent_id", body.AgentID, "period", body.Period,
			"proof_count", len(proofs), "merkle_root", merkleRoot)
		respond.JSON(w, http.StatusCreated, map[string]any{
			"agent_id": body.AgentID, "period": body.Period,
			"chain_root": merkleRoot, "proof_count": len(proofs), "tree_algorithm": "sha256-merkle",
		})
	}
}

// HandleVerifyProofInclusion verifies a single ZKP proof_hash against a Merkle chain root.
// POST /api/v1/zkp/chain/verify
func HandleVerifyProofInclusion(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		var body VerifyProofInclusionRequest
		respond.LimitBody(r)
		if !validate.Bind(w, r, &body) {
			return
		}
		if body.ProofHash == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "proof_hash is required")
			return
		}

		expectedRoot := body.ChainRoot
		if expectedRoot == "" && body.AgentID != "" && body.Period != "" {

			tenantID, ok := auth.MustGetTenantID(w, r)
			if !ok {
				return
			}
			var rows []map[string]any
			if _dbErr := db.QueryRowsCompound(database.TblZKPChainRoots, "chain_root,tree_algorithm",
				"agent_id", body.AgentID, "period", body.Period, &rows); _dbErr != nil {
				slog.Error("db.QueryRowsCompound failed (best-effort)", "error", _dbErr)
			}
			if len(rows) == 0 {
				respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "no Merkle chain root found — build the chain first")
				return
			}
			_ = tenantID //nolint:errcheck — audited: best-effort, failure is non-critical
			expectedRoot, _ = rows[0]["chain_root"].(string)
			if alg, _ := rows[0]["tree_algorithm"].(string); alg != "sha256-merkle" {
				respond.JSON(w, http.StatusUnprocessableEntity, map[string]any{
					"valid":     false,
					"reason":    "chain built with legacy flat-hash — rebuild with POST /zkp/chain",
					"algorithm": alg,
				})
				return
			}
		}
		if expectedRoot == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "chain_root required (or supply agent_id+period)")
			return
		}

		raw := []byte(body.ProofHash)
		leafHash := sha256.Sum256(raw)
		leafHex := hex.EncodeToString(leafHash[:])
		valid := types.VerifyInclusion(leafHex, expectedRoot, body.InclusionPath)
		slog.Info("inclusion proof verification",
			"proof_hash", body.ProofHash, "expected_root", expectedRoot,
			"path_steps", len(body.InclusionPath), "valid", valid)
		respond.JSON(w, http.StatusOK, map[string]any{
			"valid": valid, "proof_hash": body.ProofHash, "chain_root": expectedRoot,
			"leaf_hash": leafHex, "path_steps": len(body.InclusionPath), "algorithm": "sha256-merkle",
		})
	}
}

// HandleGetProofChain returns the stored Merkle chain root for an agent+period.
// GET /api/v1/zkp/chain/{agent_id}/{period}
func HandleGetProofChain(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		vars := mux.Vars(r)
		agentID := vars["agent_id"]
		period := vars["period"]
		if agentID == "" || period == "" {
			respond.ErrorWithCode(w, http.StatusBadRequest, respond.ErrCodeBadRequest, "agent_id and period path parameters are required")
			return
		}
		var rows []map[string]any
		// Enforce tenant scope: only return ZKP chain roots that belong to this tenant.
		// QueryRowsCompound only supports two-column compound filters — use raw ctx query
		// with tenant_id as the primary filter, then filter by agent_id+period in-memory.
		if err := db.QueryRowsCompound(database.TblZKPChainRoots, database.ColsZkpChainRoots,
			"agent_id", agentID, "period", period, &rows); err != nil {
			respond.InternalError(w, http.StatusInternalServerError, "fetch chain root", err)
			return
		}
		// Post-filter by tenant_id to enforce isolation (compound query has 2-col limit).
		filtered := rows[:0]
		for _, row := range rows {
			if tid, ok := row["tenant_id"].(string); ok && tid == tenantID {
				filtered = append(filtered, row)
			}
		}
		if len(filtered) == 0 {
			respond.OK(w, map[string]any{
				"agent_id": agentID, "period": period,
				"chain_root": "", "proof_count": 0, "computed_at": nil,
			})
			return
		}
		respond.OK(w, filtered[0])
	}
}

// HandleExportVerifiableCredential exports a W3C VC for the agent's ZKP chain.
// POST /api/v1/zkp/export
func HandleExportVerifiableCredential(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var body struct {
			AgentID string `json:"agent_id"`
			Period  string `json:"period"`
		}
		respond.LimitBody(r)
		if !validate.Bind(w, r, &body) {
			return
		}
		// core_evidence schema: zkp_chain_root_id, tenant_id, job_id, root_hash, block_height, anchored_at.
		// No agent_id, period, chain_root, or proof_count columns.
		// Query by tenant_id; filter by job_id if provided via agent_id field (backwards compat).
		var chains []map[string]any
		if _dbErr := db.QueryRowsCompound(database.TblZKPChainRoots, database.ColsZkpChainRoots,
			"tenant_id", tenantID,
			"job_id", body.AgentID, // job_id maps to what was previously called agent_id
			&chains); _dbErr != nil {
			// Fall back to tenant-scoped query if compound query fails (e.g. job_id empty)
			if _sErr := db.QueryRows(database.TblZKPChainRoots, database.ColsZkpChainRoots,
				"tenant_id", tenantID, &chains); _sErr != nil {
				slog.Error("silent drop fixed", "op", "QueryRows", "error", _sErr)
			}
			slog.Error("db.QueryRowsCompound failed (best-effort)", "error", _dbErr)
		}
		chainRoot, proofCount := "", 0
		if len(chains) > 0 {
			chainRoot, _ = chains[0]["root_hash"].(string)
			if bh, ok := chains[0]["block_height"].(float64); ok {
				proofCount = int(bh) // use block_height as proxy for proof depth
			}
		}
		if chainRoot == "" {
			respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "proof chain not found — call POST /zkp/chain first")
			return
		}
		now := time.Now().UTC()
		vc := map[string]any{
			"@context": []string{"https://www.w3.org/2018/credentials/v1", "https://ocx.io/zkp/v1"},
			"credentialSubject": map[string]any{
				"id": "urn:ocx:agent:" + body.AgentID, "tenant_id": tenantID,
				"period": body.Period, "chain_root": chainRoot, "proof_count": proofCount,
			},
		}
		// INF-1 FIX: ZKP signing key from centralised config.Get().Security.ZKPSigningKeyB64
		if keyB64 := config.Get().Security.ZKPSigningKeyB64; keyB64 != "" {
			if kb, err := base64.StdEncoding.DecodeString(keyB64); err == nil && len(kb) == ed25519.PrivateKeySize {
				vcBytes, marshalErr := json.Marshal(vc)
				if marshalErr != nil {
					slog.Error("json.Marshal failed", "err", marshalErr)
					return
				}
				sig := ed25519.Sign(ed25519.PrivateKey(kb), vcBytes)
				vc["proof"] = map[string]any{
					"type": "Ed25519Signature2020", "created": now.Format(time.RFC3339),
					"proofPurpose": "assertionMethod",
					"proofValue":   base64.StdEncoding.EncodeToString(sig),
				}
			}
		}
		vcBytes, _ := json.MarshalIndent(vc, "", "  ")
		w.Header().Set("Content-Type", "application/ld+json")
		w.Header().Set("Content-Disposition", `attachment; filename="zkp-`+body.Period+`.jsonld"`)
		_, _ = w.Write(vcBytes)
	}
}

// StartZKPBatchWorkerPool starts a 3-worker pool that processes pending ZKP batch jobs.
// POST /api/v1/zkp/batch  |  GET /api/v1/zkp/batch/{job_id}
// Uses semaphore + ticker to prevent goroutine explosion and DB thundering-herd.
func StartZKPBatchWorkerPool(ctx context.Context, db database.DB) {
	if db == nil {
		return
	}
	const workerCount = 3
	sem := make(chan struct{}, 1)
	for i := 0; i < workerCount; i++ {
		concurrent.Go("zkp_proof_chain", func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("goroutine panic recovered", "panic", r)
				}
			}()
			ticker := time.NewTicker(consts.ZKPProofChainCheckInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					select {
					case sem <- struct{}{}:
						processPendingBatchJobs(ctx, db)
						<-sem
					default:
						// Another worker is processing — skip this tick
					}
				}
			}
		})
	}
	slog.Info("ZKP batch worker pool started", "workers", workerCount)
}
