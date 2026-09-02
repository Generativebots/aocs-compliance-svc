// Package analytics provides HTTP handlers for resource metrics, dependency
// graphs, usage analytics, and intelligence reporting.
//
// All handlers are read-only and return aggregated metrics to the dashboard.
// They accept [database.DB] for dependency injection and unit testability.
package reports
