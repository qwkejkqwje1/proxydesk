package storage

import (
	"context"
	"testing"
	"time"

	"github.com/proxydesk/proxydesk/internal/model"
	"github.com/proxydesk/proxydesk/internal/parsers"
)

func TestStoreMigrateUpsertDeduplicationAndPersistence(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	credStore := model.NewCredentialStore()
	stats := parsers.ParseTXT("http://198.51.100.10:8080\nsocks5://user:pass@198.51.100.20:1080\nhttp://198.51.100.10:8080\n", "http", false)
	if stats.UniqueCount != 2 {
		t.Fatalf("expected 2 unique candidates, got %d", stats.UniqueCount)
	}

	n, err := store.UpsertCandidates(context.Background(), 1, stats.Candidates, credStore, time.Now())
	if err != nil || n != 2 {
		t.Fatalf("upsert failed: n=%d err=%v", n, err)
	}

	// Re-upserting the same candidates from a second source must not create duplicates,
	// and must increment sources_count to 2.
	_, err = store.UpsertCandidates(context.Background(), 2, stats.Candidates, credStore, time.Now())
	if err != nil {
		t.Fatalf("second upsert failed: %v", err)
	}
	_ = store.Close()

	// Reopen database to verify persistence across restarts
	store2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer store2.Close()

	list, total, err := store2.ListProxies(ProxyQueryFilter{Limit: 10})
	if err != nil || total != 2 || len(list) != 2 {
		t.Fatalf("expected 2 persisted proxies after restart, got total=%d err=%v", total, err)
	}
	for _, p := range list {
		if p.Status != model.StatusUnknown {
			t.Fatalf("imported proxy must have status 'unknown', got %s", p.Status)
		}
		if p.SourcesCount != 2 {
			t.Fatalf("expected sources_count=2, got %d", p.SourcesCount)
		}
	}
}
