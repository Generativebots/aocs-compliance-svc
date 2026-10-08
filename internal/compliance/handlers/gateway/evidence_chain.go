package gateway

// evidence_chain.go — serialised, tenant-scoped append to the compl_evidence
// hash chain (P-03 tamper evidence).
//
// Previously each writer read ALL of a tenant's evidence rows without ORDER
// BY, took whichever came back last as the previous hash, ignored read
// errors (restarting the chain from the zero hash) and could interleave with
// concurrent writers, forking the chain. Rows were also stamped VERIFIED
// before any verification and the insert lacked the NOT NULL title column.
//
// appendEvidence now, inside ONE transaction:
//  1. takes a per-tenant advisory transaction lock (serialises writers),
//  2. reads the current chain head (newest row with a chain_hash),
//  3. computes chain_hash = sha256(prev_hash + ":" + content_hash),
//  4. inserts the row linked by prev_hash / prev_evidence_id, with
//     created_at = clock_timestamp() so order follows commit order.
// Any error aborts the transaction and is returned to the caller.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/ocx/shared/idgen"
	"github.com/ocx/shared/infra/database"
)

const zeroChainHash = "0000000000000000000000000000000000000000000000000000000000000000"

type evidenceEntry struct {
	TenantID     string
	AgentID      string
	ActionType   string
	EvidenceType string // compl_evidence.evidence_type CHECK value
	Title        string
	ContentHash  string
	Metadata     map[string]any
}

type evidenceReceipt struct {
	EvidenceID string
	PrevHash   string
	ChainHash  string
}

func appendEvidence(ctx context.Context, db database.DB, e evidenceEntry) (evidenceReceipt, error) {
	var rc evidenceReceipt
	if db == nil {
		return rc, fmt.Errorf("appendEvidence: database unavailable")
	}
	if e.TenantID == "" || e.ContentHash == "" {
		return rc, fmt.Errorf("appendEvidence: tenant_id and content_hash are required")
	}
	if e.EvidenceType == "" {
		e.EvidenceType = "AUDIT_LOG"
	}
	if e.Title == "" {
		e.Title = e.ActionType
	}
	meta := e.Metadata
	if meta == nil {
		meta = map[string]any{}
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return rc, fmt.Errorf("appendEvidence: metadata: %w", err)
	}

	err = db.WithTransaction(ctx, func(tx database.DB) error {
		var lock []map[string]any
		if err := tx.QueryRawCtx(ctx,
			`SELECT 1 AS locked FROM (SELECT pg_advisory_xact_lock(hashtext('compl_evidence_chain:' || $1))) l`,
			&lock, e.TenantID); err != nil {
			return fmt.Errorf("chain lock: %w", err)
		}
		var head []struct {
			EvidenceID string `json:"evidence_id"`
			ChainHash  string `json:"chain_hash"`
		}
		if err := tx.QueryRawCtx(ctx,
			`SELECT evidence_id, chain_hash FROM compl_evidence
			  WHERE tenant_id = $1 AND chain_hash IS NOT NULL AND chain_hash <> ''
			  ORDER BY created_at DESC, evidence_id DESC LIMIT 1`,
			&head, e.TenantID); err != nil {
			return fmt.Errorf("chain head: %w", err)
		}
		prevHash, prevID := zeroChainHash, ""
		if len(head) > 0 {
			prevHash, prevID = head[0].ChainHash, head[0].EvidenceID
		}
		sum := sha256.Sum256([]byte(prevHash + ":" + e.ContentHash))
		chainHash := hex.EncodeToString(sum[:])
		evidenceID := idgen.GenID()

		var prevArg any
		if prevID != "" {
			prevArg = prevID
		}
		var out []map[string]any
		if err := tx.QueryRawCtx(ctx,
			`INSERT INTO compl_evidence
			   (evidence_id, tenant_id, agent_id, action_type, evidence_type, title,
			    content_hash, chain_hash, prev_hash, prev_evidence_id, status, metadata,
			    created_at, collected_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'RECORDED',$11::jsonb,
			    clock_timestamp(), clock_timestamp())
			 RETURNING evidence_id`,
			&out, evidenceID, e.TenantID, e.AgentID, e.ActionType, e.EvidenceType, e.Title,
			e.ContentHash, chainHash, prevHash, prevArg, string(metaJSON)); err != nil {
			return fmt.Errorf("evidence insert: %w", err)
		}
		rc = evidenceReceipt{EvidenceID: evidenceID, PrevHash: prevHash, ChainHash: chainHash}
		return nil
	})
	if err != nil {
		return evidenceReceipt{}, err
	}
	return rc, nil
}
