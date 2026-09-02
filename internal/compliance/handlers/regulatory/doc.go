// Package regulatory — EU AI Act & privacy regulatory filing handlers.
//
// This package produces machine-readable, downloadable regulatory artefacts
// intended for formal submission to supervisory authorities:
//
//	GET  /compliance/regulatory/eu-ai-act/report            — generate Article 13 transparency report
//	POST /compliance/regulatory/eu-ai-act/report/submit     — file report with declaration hash
//	GET  /compliance/regulatory/eu-ai-act/report/{id}       — retrieve filed report
//
// Distinction from handlers/compliance/eu_ai_act.go:
//   - compliance/eu_ai_act.go  → live transparency "card" for operators (interactive dashboard)
//   - regulatory/eu_ai_act_report.go → formal filing artefact with SHA-256 hash, version lock,
//     notified body reference — designed to be exported and submitted to a supervisory authority
//     (Article 71, Regulation (EU) 2024/1689).
//
// Permission: compliance:write (Auditor or Superadmin only)
package regulatory
