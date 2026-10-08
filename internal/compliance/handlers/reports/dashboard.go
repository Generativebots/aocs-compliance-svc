// Package handlers — BFF Claims Aggregation Handlers
//
// Each handler aggregates multiple table reads into a single HTTP response
// using errgroup for concurrent sub-queries inside the Go process.
//
// Pattern:
//
//	Browser → 1 GET /api/v1/{module}/dashboard → Go (N parallel DB queries) → 1 JSON response
//
// This eliminates N frontend HTTP roundtrips, replacing them with N in-process goroutines
// sharing a single TCP connection pool to Supabase.
package reports

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/ocx/shared/infra/auth"
	"github.com/ocx/shared/infra/concurrent"
	"github.com/ocx/shared/infra/database"
	"github.com/ocx/shared/respond"
)

// HELPER: run N queries concurrently, return false if any failed fatally

type dbQuery struct {
	fn func() error
}

// runConcurrent runs N DB queries in parallel, scoped to the HTTP request context.
//
// Now the request context is the root: client disconnect cancels all sub-queries.
func runConcurrent(ctx context.Context, queries []dbQuery) {
	// 10s hard cap overlaid on the request context — whichever fires first wins.
	// Guards against slow Supabase responses causing connection pool starvation.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(len(queries))
	for _, q := range queries {
		q := q
		concurrent.Go("dashboard", func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("goroutine panic recovered", "error", r)
				}
			}()
			defer wg.Done()
			select {
			case <-ctx.Done():
				slog.Warn("dashboard query cancelled", "reason", ctx.Err())
				return
			default:
				_ = q.fn()
			}
		})
	}
	wg.Wait()
}

// 1. GRA DASHBOARD — GET /api/v1/gra/dashboard
//    Replaces: /gra/status + /gra/intents + /gra/actions  (3 → 1)

// 2. CONTRACTS DASHBOARD — GET /api/v1/contracts/dashboard
//    Replaces: /contracts/ebcl + /contracts/executions  (2 → 1)

// 4. ESC / TRI-FACTOR DASHBOARD — GET /api/v1/esc/dashboard
//    Replaces: /esc/history + /esc/stats + /hitl/decisions  (3 → 1)

// 5. ACT DASHBOARD — GET /api/v1/act/dashboard
//    Replaces: /act/versions + /act/deployments + /act/approvals  (3 → 1)

// 6. ZKP DASHBOARD — GET /api/v1/zkp/dashboard
//    Replaces: /zkp/verifications + /zkp/stats  (2 → 1)

// 7. HITL/RLHC FEEDBACK DASHBOARD — GET /api/v1/hitl/rlhc/dashboard
//    Replaces: /hitl/rlhc/clusters + /hitl/rlhc/feedback  (2 → 1)

func HandleGetRLHCClaims(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}

		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}

		var clusters []map[string]any
		var feedback []map[string]any

		runConcurrent(r.Context(), []dbQuery{
			{fn: func() error {
				return db.QueryRowsCtx(r.Context(), database.TblRLHCClusters, database.ColsQcoreRlhcCorrectionClusters, "tenant_id", tenantID, &clusters)
			}},
			{fn: func() error {
				return db.QueryRowsCtx(r.Context(), database.TblCoreHitl, database.ColsHitlDecisions, "tenant_id", tenantID, &feedback)
			}},
		})

		respond.JSON(w, http.StatusOK, map[string]any{
			"clusters": orEmpty(clusters),
			"feedback": orEmpty(feedback),
		})
	}
}

// 8. SECURITY DASHBOARD — GET /api/v1/security/dashboard
//    Replaces: /security/attacks + /traffic/inspect  (2 → 1)

// 9. DLP DASHBOARD — GET /api/v1/dlp/dashboard
//    Replaces: /dlp/status + /dlp/integrations + /marketplace/dlp  (3 → 1)

// 10. TENANT ACCESS DASHBOARD — GET /api/v1/tenant/access/dashboard
//     Replaces: /permissions + /roles + /departments  (3 → 1)

func HandleGetAccessClaims(db database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if respond.RequireDB(w, db) {
			return
		}
		// Roles/permissions: platform templates (tenant_id IS NULL) plus the
		// caller's own tenant rows. Departments are tenant-owned.
		tenantID, ok := auth.MustGetTenantID(w, r)
		if !ok {
			return
		}
		var permissions []map[string]any
		var roles []map[string]any
		var departments []map[string]any

		runConcurrent(r.Context(), []dbQuery{
			{fn: func() error {
				// syst_role_perms is dropped — expand syst_roles.permissions
				// (platform templates + this tenant's roles).
				rows, err := database.ListRolePerms(r.Context(), db, tenantID, "")
				permissions = rows
				return err
			}},
			{fn: func() error {
				// syst_roles is a global catalog (D5); keep templates + own tenant.
				var all []map[string]any
				if err := db.QueryRowsCtx(r.Context(), database.TblSystRoles, database.ColsAocsPlatformRoles, "", "", &all); err != nil {
					return err
				}
				for _, row := range all {
					if t, _ := row["tenant_id"].(string); t == "" || t == tenantID {
						roles = append(roles, row)
					}
				}
				return nil
			}},
			{fn: func() error {
				return db.QueryRowsCtx(r.Context(), database.TblSystDepartments, database.ColsAocsPlatformDepartments, "tenant_id", tenantID, &departments)
			}},
		})

		respond.JSON(w, http.StatusOK, map[string]any{
			"permissions": orEmpty(permissions),
			"roles":       orEmpty(roles),
			"departments": orEmpty(departments),
		})
	}
}

// 11. SOVEREIGNTY DASHBOARD — GET /api/v1/platform/sovereignty/dashboard
//     Replaces: /platform/tenants + /platform/config  (2 → 1)

// 12. ANALYTICS DASHBOARD — GET /api/v1/analytics/dashboard
//     Replaces: analytics/overview + analytics/kpis + analytics/metrics  (3 → 1)

// 13. FED DASHBOARD — GET /api/v1/fed/dashboard
//     Replaces: /fed/nodes + /fed/metrics + /neef/growth + /fed/trust  (4 → 1)

// 14. FED GOV DASHBOARD — GET /api/v1/fed/gov/dashboard
//     Replaces: /gov/proposals + /gov/committee  (2 → 1)

// HandleGetTrustTaxClaims lives in dashboard_analytics.go (same package).
// The stub comment previously here was a maintenance hazard — removed.
