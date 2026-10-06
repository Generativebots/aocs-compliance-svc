package reports

// view_handlers.go — Handlers that query DB materialised views instead of raw joins.
//
// Analytics handlers were doing raw table joins in code (expensive, inconsistent).
// These handlers query the pre-computed DB views directly, which the DB materialises
// from the same underlying tables — results are consistent and orders of magnitude faster.
//
// Views queried:
//   vw_agent_dashboard   — per-agent stats (trust score, gate verdicts, HITL rates)
//   vw_compliance_kpis   — compliance summary metrics per tenant
//
// Circular flow:
//   Agent gate calls → core_events / core_verdicts
//   DB views → vw_agent_dashboard, vw_compliance_kpis (live aggregation)
//   These handlers → read views → UI dashboards
