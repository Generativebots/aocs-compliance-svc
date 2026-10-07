package compliance

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/ocx/shared/infra/config"
	"github.com/ocx/shared/infra/database"
)

type ccStore struct {
	violations  map[string]string // tenant → JSON rows
	obligations map[string]string
	updates     []ccUpdate
	compound    [][]string
}

type ccUpdate struct {
	tenant, control, status string
	meta                    map[string]any
}

func (s *ccStore) ListAllTenants() ([]config.TenantRow, error) {
	return []config.TenantRow{{TenantID: "t1"}, {TenantID: "t2"}}, nil
}

func (s *ccStore) QueryRowsCtx(_ context.Context, table, _, col, val string, dest interface{}) error {
	if table != database.TblComplObligations || col != "tenant_id" {
		panic("unexpected read " + table)
	}
	return unmarshalOrEmpty(s.obligations[val], dest)
}

func (s *ccStore) QueryRowsCompoundCtx(_ context.Context, table, _, c1, v1, c2, v2 string, dest interface{}) error {
	s.compound = append(s.compound, []string{table, c1, v1, c2, v2})
	return unmarshalOrEmpty(s.violations[v1], dest)
}

func (s *ccStore) UpdateRowCompound(table, c1, v1, c2, v2 string, updates interface{}) error {
	m := updates.(map[string]any)
	meta, _ := m["metadata"].(map[string]any)
	s.updates = append(s.updates, ccUpdate{tenant: v2, control: v1, status: m["status"].(string), meta: meta})
	return nil
}

func unmarshalOrEmpty(body string, dest interface{}) error {
	if body == "" {
		body = "[]"
	}
	return json.Unmarshal([]byte(body), dest)
}

const t1Obligations = `[
 {"control_id":"c-dlp","control_ref":"164.514(b)","status":"COMPLIANT","metadata":{"evidence_ref":"evlt_dlp_scanner"}},
 {"control_id":"c-audit","control_ref":"164.312(b)","status":"COMPLIANT","metadata":{"evidence_ref":"evlt_merkle_chain"}},
 {"control_id":"c-iso","control_ref":"A.7.4","status":"COMPLIANT","metadata":{"violation_types":["DLP_EXFILTRATION"]}},
 {"control_id":"c-named","control_ref":"GOV-1","status":"COMPLIANT","metadata":{}},
 {"control_id":"c-manual","control_ref":"164.312(a)(1)","status":"IN_PROGRESS","metadata":{"evidence_ref":"evlt_dlp_scanner"}}
]`

func TestContinuousCompliance_FlagsOnlyLinkedControls(t *testing.T) {
	s := &ccStore{
		violations: map[string]string{
			"t1": `[{"violation_id":"v1","violation_type":"DLP_EXFILTRATION","details":{"direction":"ingress"}},
			        {"violation_id":"v2","violation_type":"OTHER","details":{"control_refs":["GOV-1"]}},
			        {"violation_id":"v3","violation_type":"UNMAPPED","details":null}]`,
		},
		obligations: map[string]string{"t1": t1Obligations},
	}
	n := reconcileTenantObligations(context.Background(), s, "t1", time.Unix(0, 0).UTC())
	if n != 3 {
		t.Fatalf("changed = %d, want 3 (updates %+v)", n, s.updates)
	}
	got := map[string]ccUpdate{}
	for _, u := range s.updates {
		got[u.control] = u
	}
	for _, c := range []string{"c-dlp", "c-iso", "c-named"} {
		u, ok := got[c]
		if !ok || u.status != "IN_PROGRESS" || u.tenant != "t1" {
			t.Fatalf("%s must be flagged IN_PROGRESS, got %+v", c, u)
		}
		flag, _ := u.meta[autoFlagKey].(map[string]any)
		if flag["prior_status"] != "COMPLIANT" {
			t.Fatalf("%s flag must record prior status, got %v", c, u.meta)
		}
	}
	if _, ok := got["c-audit"]; ok {
		t.Fatal("audit control is unrelated to a DLP violation and must not change")
	}
	if _, ok := got["c-manual"]; ok {
		t.Fatal("an obligation a human set to IN_PROGRESS must not be touched")
	}
	if ev := got["c-dlp"].meta["evidence_ref"]; ev != "evlt_dlp_scanner" {
		t.Fatalf("existing metadata must be preserved, got %v", got["c-dlp"].meta)
	}
	if s.compound[0][3] != "status" || s.compound[0][4] != "OPEN" || s.compound[0][2] != "t1" {
		t.Fatalf("violations must be read per tenant with status=OPEN, got %v", s.compound[0])
	}
}

func TestContinuousCompliance_RestoresWhenViolationsClose(t *testing.T) {
	s := &ccStore{
		obligations: map[string]string{"t1": `[
		 {"control_id":"c-dlp","control_ref":"164.514(b)","status":"IN_PROGRESS",
		  "metadata":{"evidence_ref":"evlt_dlp_scanner","continuous_compliance_flag":{"prior_status":"COMPLIANT","violation_ids":["v1"]}}},
		 {"control_id":"c-manual","status":"IN_PROGRESS","metadata":{}}]`},
	}
	n := reconcileTenantObligations(context.Background(), s, "t1", time.Now())
	if n != 1 || s.updates[0].control != "c-dlp" || s.updates[0].status != "COMPLIANT" {
		t.Fatalf("flagged obligation must be restored, got %+v", s.updates)
	}
	if _, still := s.updates[0].meta[autoFlagKey]; still {
		t.Fatal("flag must be cleared on restore")
	}
	if s.updates[0].meta["evidence_ref"] != "evlt_dlp_scanner" {
		t.Fatal("other metadata must survive restore")
	}
}

func TestContinuousCompliance_NoRewriteWhenUnchanged(t *testing.T) {
	s := &ccStore{
		violations: map[string]string{"t1": `[{"violation_id":"v1","violation_type":"DLP_EXFILTRATION"}]`},
		obligations: map[string]string{"t1": `[
		 {"control_id":"c-dlp","status":"IN_PROGRESS",
		  "metadata":{"evidence_ref":"evlt_dlp_scanner","continuous_compliance_flag":{"prior_status":"COMPLIANT","violation_ids":["v1"]}}}]`},
	}
	if n := reconcileTenantObligations(context.Background(), s, "t1", time.Now()); n != 0 || len(s.updates) != 0 {
		t.Fatalf("unchanged flag must not be rewritten, got %+v", s.updates)
	}
}

func TestContinuousCompliance_TenantsAreIsolated(t *testing.T) {
	s := &ccStore{
		violations:  map[string]string{"t2": `[{"violation_id":"v9","violation_type":"DLP_EXFILTRATION"}]`},
		obligations: map[string]string{"t1": t1Obligations, "t2": `[]`},
	}
	evaluateContinuousCompliance(context.Background(), s)
	for _, u := range s.updates {
		if u.tenant == "t1" {
			t.Fatalf("a violation in t2 must not change t1 obligations: %+v", u)
		}
	}
}
