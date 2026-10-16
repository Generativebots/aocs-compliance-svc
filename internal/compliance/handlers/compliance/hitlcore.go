package compliance

// hitlcore.go — HITL case access goes through the ocx-core-svc internal API (Row 9).
// core_hitl, core_hitl_votes and core_hitl_sla are owned by core; compliance never writes
// them directly. Reads that only need lists use the compl_core_projection read model.

import (
	"errors"
	"net/http"

	"github.com/ocx/shared/infra/serviceclient"
	"github.com/ocx/shared/respond"
)

var pkgHITLCore *serviceclient.Client

// SetHITLCore wires the core client used by handlers that were not given one explicitly.
// Called once from cmd/aocs-compliance/main.go.
func SetHITLCore(c *serviceclient.Client) { pkgHITLCore = c }

// hitlCore returns the hub client wired by SetHITLCore. Handlers also receive the general core
// client (which may target a different upstream), so it is only the fallback when no hub client
// was wired (e.g. handlers constructed directly in tests).
func hitlCore(explicit ...*serviceclient.Client) *serviceclient.Client {
	if pkgHITLCore != nil {
		return pkgHITLCore
	}
	for _, c := range explicit {
		if c != nil {
			return c
		}
	}
	return nil
}

// requireHITLCore writes a 503 and returns false when no core client is configured.
func requireHITLCore(w http.ResponseWriter, c *serviceclient.Client) bool {
	if c == nil {
		respond.ErrorWithCode(w, http.StatusServiceUnavailable, respond.ErrCodeUnavailable,
			"ocx-core-svc is not configured; HITL case writes are served by core")
		return false
	}
	return true
}

// writeHITLCoreErr maps a core client error onto the response. It returns the conflicting
// status (when err is a 409 precondition failure) so callers can tailor the body.
func writeHITLCoreErr(w http.ResponseWriter, err error, op string) {
	var conflict *serviceclient.HITLConflictError
	switch {
	case errors.Is(err, serviceclient.ErrHITLNotFound):
		respond.ErrorWithCode(w, http.StatusNotFound, respond.ErrCodeNotFound, "case not found")
	case errors.As(err, &conflict):
		respond.ErrorWithCode(w, http.StatusConflict, respond.ErrCodeConflict, op+": "+conflict.Error())
	default:
		respond.InternalError(w, http.StatusBadGateway, op, err)
	}
}
