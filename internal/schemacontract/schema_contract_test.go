// Package schemacontract holds the schema contract test for this service.
//
// It fails CI when Go code passes a column to a shared database method that
// the service's checked-in schema (database/schema/*.sql) does not define —
// the class of bug that otherwise only surfaces at runtime as SQLSTATE 42703.
//
// Reads of relations owned by another service are checked against that
// service's schema when its repo is checked out as a sibling directory (the
// standard multi-repo layout, also used for the shared-go replace directive).
// In an isolated checkout those reads are counted as "unverified" and logged.
package schemacontract

import (
	"testing"

	"github.com/ocx/shared/infra/database/schemacheck"
)

const (
	serviceRoot = "../.."
	schemaDir   = "../../database/schema"
)

// siblingSchemas are the other schema-owning repos, relative to this package.
var siblingSchemas = []string{
	"../../../aocs-system-svc/database/schema",
	"../../../ocx-core-svc/database/schema",
	"../../../ocx-extension-svc/database/schema",
	"../../../aocs-compliance-svc/database/schema",
	"../../../ocx-connectors-svc/database/schema",
	"../../../aocs-studio-svc/database/schema",
}

func TestSchemaContract(t *testing.T) {
	rep, err := schemacheck.CheckService(serviceRoot, schemaDir, siblingSchemas...)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Uses) == 0 {
		t.Fatal("no database call sites found — scanner or paths are broken")
	}
	dynamic := 0
	for _, u := range rep.Uses {
		dynamic += u.Dynamic
	}
	t.Logf("call sites=%d own-schema=%d cross-repo=%d unverified=%d dynamic-args=%d",
		len(rep.Uses), len(rep.Uses)-rep.CrossRepo-len(rep.Foreign), rep.CrossRepo, len(rep.Foreign), dynamic)
	for _, v := range rep.Violations {
		t.Error(v.String())
	}
}
