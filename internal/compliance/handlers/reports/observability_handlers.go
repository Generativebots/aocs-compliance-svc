// Package analytics — observability handlers for agent telemetry, config, and copilot logs.
//
// P3 handlers: these three tables existed in Go models and Supabase but had no
// HTTP API exposure. Added 2026-08-07 as part of the database sync audit.
//
// Routes (register in routes_intel.go):
//
//	GET /api/v1/agents/{agent_id}/telemetry    → HandleListAgentTelemetry
//	GET /api/v1/agents/{agent_id}/config       → HandleGetAgentConfig
//	GET /api/v1/copilot/interaction-log        → HandleListCopilotInteractionLog
package reports
