// Package analytics — read handlers for previously write-only analytics tables.
//
// These handlers expose data written by domain/gate layers but never surfaced
// via API routes. Each is tenant-scoped, paginated, and injection-safe.
package reports

import (
	"net/http"
	"strconv"

	"github.com/ocx/shared/infra/database"
)

func parseLimit(r *http.Request, def, max int) database.PageParams {
	limit := def
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= max {
		limit = n
	}
	offset := 0
	if n, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && n >= 0 {
		offset = n
	}
	return database.PageParams{Limit: limit, Offset: offset}
}
