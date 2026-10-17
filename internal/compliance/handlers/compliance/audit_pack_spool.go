package compliance

// audit_pack_spool.go — CM-05: the audit pack is paged, not capped.
//
// Each section (evidence / obligations / ledger) is read from the database one page at a time and
// written to a temp file. SHA-256 and size are computed WHILE writing, so the signed manifest covers
// the exact bytes later copied into the zip, and memory use is bounded by auditPackPageSize rather
// than by the tenant's row count. Sections are complete (never truncated).

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ocx/shared/infra/database"
)

// rowEmitter receives one row of a section.
type rowEmitter func(row map[string]any) error

// spoolSection writes `[row,row,...]` (or, when tailKey != "", `{"entries":[...],"<tailKey>":<tail>}`)
// to a new file in dir, returning the file descriptor for the pack and the number of rows written.
func spoolSection(dir, name, tailKey string, tail []byte, iterate func(emit rowEmitter) error) (AuditPackFile, int, error) {
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		return AuditPackFile{}, 0, err
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	var size int
	w := io.MultiWriter(f, h)
	write := func(b []byte) error {
		n, err := w.Write(b)
		size += n
		return err
	}

	open, closeArr := "[", "]"
	if tailKey != "" {
		open, closeArr = `{"entries":[`, "]"
	}
	if err := write([]byte(open)); err != nil {
		return AuditPackFile{}, 0, err
	}
	count := 0
	emit := func(row map[string]any) error {
		b, err := json.Marshal(row)
		if err != nil {
			return err
		}
		sep := "\n"
		if count > 0 {
			sep = ",\n"
		}
		count++
		return write(append([]byte(sep), b...))
	}
	if err := iterate(emit); err != nil {
		return AuditPackFile{}, 0, err
	}
	if err := write([]byte("\n" + closeArr)); err != nil {
		return AuditPackFile{}, 0, err
	}
	if tailKey != "" {
		if err := write([]byte(`,"` + tailKey + `":`)); err != nil {
			return AuditPackFile{}, 0, err
		}
		if err := write(tail); err != nil {
			return AuditPackFile{}, 0, err
		}
		if err := write([]byte("}")); err != nil {
			return AuditPackFile{}, 0, err
		}
	}
	if err := f.Sync(); err != nil {
		return AuditPackFile{}, 0, err
	}
	return AuditPackFile{Name: name, Path: path, sha: hex.EncodeToString(h.Sum(nil)), size: size}, count, nil
}

// copySpooled streams a spool file into the zip.
func copySpooled(zw *zip.Writer, f AuditPackFile) error {
	src, err := os.Open(f.Path)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	fw, err := zw.Create(f.Name)
	if err != nil {
		return err
	}
	_, err = io.Copy(fw, src)
	return err
}

// keysetPages calls emit for every row of `table` for the tenant, ordered by keyCol, fetching
// auditPackPageSize rows per query. extraWhere may reference $3.. (extraArgs); $1 is the tenant and
// $2 the keyset cursor.
func keysetPages(ctx context.Context, pg *database.PGXPool, tenantID, table, keyCol, extraWhere string, extraArgs []any, emit rowEmitter) error {
	after := ""
	for {
		sql := fmt.Sprintf(`SELECT row_to_json(t) FROM (SELECT * FROM %s WHERE tenant_id=$1 AND %s > $2 AND (%s) ORDER BY %s LIMIT %d) t`,
			table, keyCol, extraWhere, keyCol, auditPackPageSize)
		args := append([]any{tenantID, after}, extraArgs...)
		rows, err := pg.RunTenantQuery(ctx, tenantID, sql, args...)
		if err != nil {
			return fmt.Errorf("%s page after %q: %w", table, after, err)
		}
		for _, r := range rows {
			if err := emit(r); err != nil {
				return err
			}
		}
		if len(rows) < auditPackPageSize {
			return nil
		}
		last, _ := rows[len(rows)-1][keyCol].(string)
		if last == "" || last == after {
			return fmt.Errorf("%s: keyset column %s missing in page", table, keyCol)
		}
		after = last
	}
}

// offsetPages is keysetPages for sources without a single-column key (the merkle ledger view):
// ORDER BY orderCols is a total order, paged with LIMIT/OFFSET. $1 is the tenant.
func offsetPages(ctx context.Context, pg *database.PGXPool, tenantID, selectCols, table, extraWhere, orderCols string, extraArgs []any, emit rowEmitter) error {
	for offset := 0; ; offset += auditPackPageSize {
		sql := fmt.Sprintf(`SELECT row_to_json(t) FROM (SELECT %s FROM %s WHERE tenant_id=$1 AND (%s) ORDER BY %s LIMIT %d OFFSET %d) t`,
			selectCols, table, extraWhere, orderCols, auditPackPageSize, offset)
		rows, err := pg.RunTenantQuery(ctx, tenantID, sql, append([]any{tenantID}, extraArgs...)...)
		if err != nil {
			return fmt.Errorf("%s offset %d: %w", table, offset, err)
		}
		for _, r := range rows {
			if err := emit(r); err != nil {
				return err
			}
		}
		if len(rows) < auditPackPageSize {
			return nil
		}
	}
}

// spoolAuditSections pages evidence, obligations and the ledger slice to spool files.
// The period filter ("YYYY-MM", UTC) and framework filter are applied in SQL.
func spoolAuditSections(ctx context.Context, pg *database.PGXPool, dir, tenantID, framework, period string, ledgerReport []byte) ([]AuditPackFile, map[string]any, error) {
	sections := map[string]any{}
	var files []AuditPackFile

	evFile, n, err := spoolSection(dir, "evidence.json", "", nil, func(emit rowEmitter) error {
		return keysetPages(ctx, pg, tenantID, database.TblComplEvidence, "evidence_id",
			`$3::text = '' OR to_char(created_at AT TIME ZONE 'UTC','YYYY-MM') = $3::text OR to_char(collected_at AT TIME ZONE 'UTC','YYYY-MM') = $3::text`,
			[]any{period}, emit)
	})
	if err != nil {
		return nil, nil, fmt.Errorf("evidence: %w", err)
	}
	files = append(files, evFile)
	sections["evidence"] = completeSection(n)

	obFile, n, err := spoolSection(dir, "obligations.json", "", nil, func(emit rowEmitter) error {
		return keysetPages(ctx, pg, tenantID, database.TblComplObligations, "control_id",
			`$3::text = '' OR lower(framework) = lower($3::text)`, []any{framework}, emit)
	})
	if err != nil {
		return nil, nil, fmt.Errorf("obligations: %w", err)
	}
	files = append(files, obFile)
	sections["obligations"] = completeSection(n)

	ldFile, n, err := spoolSection(dir, "ledger.json", "chain_verification", ledgerReport, func(emit rowEmitter) error {
		return offsetPages(ctx, pg, tenantID,
			"reference_id,gate_id,verdict,previous_hash,current_hash,recorded_at", database.TblMerkleLedger,
			`$2::text = '' OR to_char(recorded_at AT TIME ZONE 'UTC','YYYY-MM') = $2::text`,
			"recorded_at, current_hash", []any{period}, emit)
	})
	if err != nil {
		return nil, nil, fmt.Errorf("ledger: %w", err)
	}
	files = append(files, ldFile)
	sections["ledger"] = completeSection(n)
	return files, sections, nil
}

// completeSection describes a section in the signed manifest. Sections are never truncated.
func completeSection(n int) map[string]any {
	return map[string]any{"total": n, "included": n, "truncated": false}
}
