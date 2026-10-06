// Package admin — Consolidated dashboard view handlers.
//
// Each handler executes a SINGLE SQL view query that replaces N parallel
// frontend fetches with one consolidated JSON payload.
//
//	GET /monitor/ops-health  → v_ops_health_dashboard   (operate/health page)
//	GET /trust/dashboard     → v_trust_dashboard        (economics/trust page)
//	GET /gate/dashboard      → v_gate_dashboard         (operate/gate page)
//	GET /jury/dashboard      → v_jury_dashboard         (govern/jury page)
//	GET /jury-leaderboard    → v_jury_leaderboard       (govern/jury leaderboard tab)
//
// Views are read via PostgREST exactly like tables (QueryRows / QueryRowsCompound).
// No pagination needed — each view returns a single summary row (or ordered leaderboard).
package reports

// HandleGetJuryLeaderboard returns the jury leaderboard from v_jury_leaderboard.
// GET /api/v1/jury-leaderboard
// Returns ranked list of jurors by vote count and approval rate for the caller's tenant.

// Handlers for previously unused DB views (wired 2026-07-19)
