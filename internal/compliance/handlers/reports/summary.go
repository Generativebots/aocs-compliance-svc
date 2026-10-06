// Package handlers — Analytics, Reports, Dashboards, Export handlers.
//
// These are DB-backed implementations for analytics features. Reports and
// compliance reports use the compliance_reports table. Dashboards use
// platform_config for storage. Export jobs are computed at request time.
package reports

import (
	"github.com/ocx/shared/idgen"
)

// HandleGetAnalyticsQuery — POST /api/v1/analytics/query
// Was returning HTTP 501. Now performs real DB reads across key
// analytics tables and returns aggregated results keyed to the requested metric.

// generatePlatformID generates a platform-standard ID: YYYYMM + 8 UPPERCASE alphanumeric chars.
func generatePlatformID() string { return idgen.GenID() }

// REPORTS — CRUD backed by compliance_reports table

// HandleListReports removed — duplicate of handlers.HandleListComplianceReports.
// Admin /reports route wired to handlers.HandleListComplianceReports in main.go.

// EXPORT — stateless export generation

// DASHBOARDS — stored in platform_config as JSON

// NOTE: HandleDeleteDashboard is declared in analytics_economics.go.
// NOTE: HandleGetAnalyticsQuery (full implementation) is declared below in analytics_economics.go.
// Do NOT re-declare here — duplicate symbol compile error.
