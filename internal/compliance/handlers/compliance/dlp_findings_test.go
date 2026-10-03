package compliance

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/ocx/shared/infra/database"
)

type fakeCompoundReader struct {
	rows                 []map[string]any
	err                  error
	table, cols          string
	col1, val1, col2, v2 string
}

func (f *fakeCompoundReader) QueryRowsCompound(table, selectCols, col1, val1, col2, val2 string, dest interface{}) error {
	f.table, f.cols, f.col1, f.val1, f.col2, f.v2 = table, selectCols, col1, val1, col2, val2
	if f.err != nil {
		return f.err
	}
	b, _ := json.Marshal(f.rows)
	return json.Unmarshal(b, dest)
}

func TestLoadDLPFinding_QueryShape(t *testing.T) {
	f := &fakeCompoundReader{rows: []map[string]any{{"audit_log_id": "f1", "action_type": "dlp.finding"}}}
	row, err := loadDLPFinding(f, "t1", "f1")
	if err != nil {
		t.Fatal(err)
	}
	if row["audit_log_id"] != "f1" {
		t.Fatalf("row = %v", row)
	}
	if f.table != database.TblCoreAudit || f.cols != colsDLPFindingRecord {
		t.Fatalf("query (%q, %q)", f.table, f.cols)
	}
	if f.col1 != "audit_log_id" || f.val1 != "f1" || f.col2 != "tenant_id" || f.v2 != "t1" {
		t.Fatalf("filters (%s=%s, %s=%s)", f.col1, f.val1, f.col2, f.v2)
	}
}

func TestLoadDLPFinding_NotFound(t *testing.T) {
	for name, rows := range map[string][]map[string]any{
		"absent":       nil,
		"other_action": {{"audit_log_id": "f1", "action_type": "gate.request"}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadDLPFinding(&fakeCompoundReader{rows: rows}, "t1", "f1")
			if !errors.Is(err, errDLPFindingNotFound) {
				t.Fatalf("err = %v, want not found", err)
			}
		})
	}
}

func TestLoadDLPFinding_ReadErrorIsNotNotFound(t *testing.T) {
	boom := errors.New("connection reset")
	_, err := loadDLPFinding(&fakeCompoundReader{err: boom}, "t1", "f1")
	if !errors.Is(err, boom) || errors.Is(err, errDLPFindingNotFound) {
		t.Fatalf("err = %v", err)
	}
}
