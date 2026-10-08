package regulatory

import (
	"log/slog"
	"net/http"

	"github.com/ocx/shared/respond"
)

// reportReadFailed answers 503 when an input of a compliance report could not
// be read. A report built from a failed read (e.g. "no open violations"
// because the violations query errored) is a false clean report.
func reportReadFailed(w http.ResponseWriter, tenantID string, err error) {
	slog.Error("compliance report: input read failed — report not produced", "tenant_id", tenantID, "error", err)
	respond.ErrorWithCode(w, http.StatusServiceUnavailable, respond.ErrCodeUnavailable,
		"compliance data could not be read; report not generated")
}
