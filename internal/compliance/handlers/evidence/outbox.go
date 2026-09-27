package evaluation

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/ocx/shared/infra/database"
)

type outboxItem struct {
	Table     string
	Row       any
	Attempts  int
	CreatedAt time.Time
}

var (
	outboxMu    sync.Mutex
	outboxQueue []outboxItem
	maxOutbox   = 5000
)

// QueueEvidenceOutbox pushes a failed evidence insertion to the outbox for async retry (GAP-BE3).
func QueueEvidenceOutbox(table string, row any) {
	outboxMu.Lock()
	defer outboxMu.Unlock()

	if len(outboxQueue) >= maxOutbox {
		slog.Error("QueueEvidenceOutbox: queue buffer full, dropping oldest event", "table", table)
		outboxQueue = outboxQueue[1:]
	}

	outboxQueue = append(outboxQueue, outboxItem{
		Table:     table,
		Row:       row,
		Attempts:  0,
		CreatedAt: time.Now().UTC(),
	})
	slog.Info("QueueEvidenceOutbox: event buffered for background retry", "table", table, "pending_count", len(outboxQueue))
}

// StartEvidenceOutboxWorker runs a background worker that periodically retries buffered evidence writes.
func StartEvidenceOutboxWorker(ctx context.Context, db database.DB) {
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				drainOutbox(ctx, db)
			}
		}
	}()
}

func drainOutbox(ctx context.Context, db database.DB) {
	outboxMu.Lock()
	if len(outboxQueue) == 0 {
		outboxMu.Unlock()
		return
	}
	items := make([]outboxItem, len(outboxQueue))
	copy(items, outboxQueue)
	outboxQueue = nil
	outboxMu.Unlock()

	var remaining []outboxItem
	for _, item := range items {
		if ctx.Err() != nil {
			remaining = append(remaining, item)
			continue
		}

		err := db.InsertRow(item.Table, item.Row)
		if err == nil {
			slog.Info("evidence outbox retry succeeded", "table", item.Table)
		} else {
			item.Attempts++
			if item.Attempts < 5 {
				remaining = append(remaining, item)
			} else {
				slog.Error("evidence outbox retry permanently exhausted", "table", item.Table, "attempts", item.Attempts, "err", err)
			}
		}
	}

	if len(remaining) > 0 {
		outboxMu.Lock()
		outboxQueue = append(remaining, outboxQueue...)
		if len(outboxQueue) > maxOutbox {
			outboxQueue = outboxQueue[:maxOutbox]
		}
		outboxMu.Unlock()
	}
}
