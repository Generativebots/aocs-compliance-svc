package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ocx/shared/infra/database"
)

type fakeSybilStore struct {
	rows    []agentSeenRow
	readErr error
	gotQ    database.SystemScopeQuery
	gotCtx  context.Context
	inserts []struct {
		table string
		row   map[string]any
	}
}

func (f *fakeSybilStore) QuerySystemScopeCtx(ctx context.Context, q database.SystemScopeQuery, dest interface{}) error {
	f.gotCtx, f.gotQ = ctx, q
	if f.readErr != nil {
		return f.readErr
	}
	b, _ := json.Marshal(f.rows)
	return json.Unmarshal(b, dest)
}

func (f *fakeSybilStore) InsertRow(table string, row interface{}) error {
	f.inserts = append(f.inserts, struct {
		table string
		row   map[string]any
	}{table, row.(map[string]any)})
	return nil
}

func agentsOnIP(tenant, ip string, n int) []agentSeenRow {
	out := make([]agentSeenRow, n)
	for i := range out {
		out[i] = agentSeenRow{TenantID: tenant, AgentID: fmt.Sprintf("%s-a%d", tenant, i), LastIP: ip}
	}
	return out
}

func TestClusterSybil_PerTenantOnly(t *testing.T) {
	// 3 agents of t1 + 3 of t2 share one IP: neither tenant reaches the
	// threshold on its own, and tenants must never be merged.
	rows := append(agentsOnIP("t1", "203.0.113.7", 3), agentsOnIP("t2", "203.0.113.7", 3)...)
	if got := clusterSybil(rows); len(got) != 0 {
		t.Fatalf("cross-tenant agents were clustered: %+v", got)
	}
}

func TestClusterSybil_FlagsLargeSameTenantCluster(t *testing.T) {
	rows := append(agentsOnIP("t1", "203.0.113.7", 6), agentsOnIP("t2", "203.0.113.7", 2)...)
	rows = append(rows, agentSeenRow{TenantID: "t1", AgentID: "t1-a0", LastIP: "203.0.113.7"}) // duplicate
	got := clusterSybil(rows)
	if len(got) != 6 {
		t.Fatalf("want 6 findings, got %d: %+v", len(got), got)
	}
	for _, f := range got {
		if f.TenantID != "t1" || f.IP != "203.0.113.7" {
			t.Fatalf("unexpected finding %+v", f)
		}
		if f.RiskScore < sybilMaxRisk {
			t.Fatalf("risk %v below threshold", f.RiskScore)
		}
		if len(f.CorrelatedAgents) != 5 {
			t.Fatalf("correlated = %v", f.CorrelatedAgents)
		}
		for _, o := range f.CorrelatedAgents {
			if o == f.AgentID || o[:2] != "t1" {
				t.Fatalf("correlated list leaks self or other tenant: %v", f.CorrelatedAgents)
			}
		}
	}
}

func TestClusterSybil_Thresholds(t *testing.T) {
	// 5 agents → risk 0.75 < 0.85 → not flagged; 6 → 0.90 → flagged.
	if got := clusterSybil(agentsOnIP("t", "1.1.1.1", 5)); len(got) != 0 {
		t.Fatalf("5-agent cluster flagged: %d", len(got))
	}
	if got := clusterSybil(agentsOnIP("t", "1.1.1.1", 6)); len(got) != 6 {
		t.Fatalf("6-agent cluster not flagged: %d", len(got))
	}
	if sybilRisk(10) != 1 {
		t.Fatal("risk must cap at 1")
	}
	// Rows missing identity or IP are ignored.
	bad := []agentSeenRow{{TenantID: "", AgentID: "a", LastIP: "x"}, {TenantID: "t", AgentID: "", LastIP: "x"}, {TenantID: "t", AgentID: "a", LastIP: ""}}
	if got := clusterSybil(bad); len(got) != 0 {
		t.Fatalf("incomplete rows produced findings: %+v", got)
	}
}

func TestRunSybilScan_QueryAndWrites(t *testing.T) {
	now := time.Date(2026, 10, 4, 3, 0, 0, 0, time.UTC)
	f := &fakeSybilStore{rows: agentsOnIP("t1", "203.0.113.7", 6)}
	if err := runSybilScan(context.Background(), f, now); err != nil {
		t.Fatal(err)
	}
	q := f.gotQ
	if q.Table != database.TblCoreAgentTelemetry || q.SinceColumn != "last_seen_at" ||
		!q.Since.Equal(now.Add(-sybilWindow)) || q.MaxRows != sybilMaxRows {
		t.Fatalf("query = %+v", q)
	}
	if len(q.NotNull) != 1 || q.NotNull[0] != "last_ip" {
		t.Fatalf("NotNull = %v", q.NotNull)
	}
	if len(f.inserts) != 6 {
		t.Fatalf("want 6 IDS events, got %d", len(f.inserts))
	}
	for _, ins := range f.inserts {
		if ins.table != database.TblSharIdsEvents {
			t.Fatalf("finding written to %s; must only go to core_ids_events", ins.table)
		}
		if ins.row["tenant_id"] != "t1" || ins.row["signature_id"] != sybilSignatureID {
			t.Fatalf("row = %v", ins.row)
		}
		if _, ok := ins.row["score"]; ok {
			t.Fatal("must not write a trust score")
		}
	}
}

func TestRunSybilScan_ReadErrorWritesNothing(t *testing.T) {
	boom := database.ErrSystemScopeRowCap
	f := &fakeSybilStore{readErr: boom}
	if err := runSybilScan(context.Background(), f, time.Now()); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if len(f.inserts) != 0 {
		t.Fatal("no writes expected after a failed read")
	}
}

func TestSybilIDSEventColumnsExist(t *testing.T) {
	// Every key must be a core_ids_events column (checked against live schema
	// on 2026-10-04; see database/schema in ocx-core-svc).
	cols := map[string]bool{
		"id": true, "tenant_id": true, "agent_id": true, "signature_id": true, "severity": true,
		"description": true, "source_ip": true, "dest_ip": true, "blocked": true, "verdict": true,
		"anomaly_score": true, "tx_id": true, "tool_name": true, "created_at": true,
		"detected_at": true, "event_type": true, "raw_payload": true,
	}
	row := sybilIDSEvent(sybilFinding{TenantID: "t", AgentID: "a", IP: "1.1.1.1", RiskScore: 0.9}, time.Now())
	for k := range row {
		if !cols[k] {
			t.Errorf("core_ids_events has no column %q", k)
		}
	}
}
