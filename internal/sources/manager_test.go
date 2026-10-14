package sources

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/proxydesk/proxydesk/internal/diagnostics"
	"github.com/proxydesk/proxydesk/internal/model"
	"github.com/proxydesk/proxydesk/internal/storage"
)

func TestSourceManagerETag304BackoffAndSSRFBlock(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	clk := model.NewFakeClock(time.Date(2026, 10, 13, 15, 0, 0, 0, time.UTC))
	logger := diagnostics.NewRotatingLogger(dir, 1024*1024, 2)
	credStore := model.NewCredentialStore()
	mgr := NewManager(store, credStore, logger, clk, 42, 1024)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1-etag"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/oversize") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(strings.Repeat("198.51.100.1:8080\n", 200)))
			return
		}
		w.Header().Set("ETag", `"v1-etag"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("http://198.51.100.10:8080\nsocks5://198.51.100.11:1080\n"))
	}))
	defer srv.Close()

	// 1. By default, loopback URL source without AllowPrivate=true must be blocked at Dial time by SSRF Control
	srcBlocked := storage.SourceRecord{
		ID:              10,
		Name:            "Local Test Blocked",
		Kind:            "url",
		Location:        srv.URL + "/list.txt",
		Format:          "txt",
		DefaultProtocol: "http",
		AllowPrivate:    false,
		TimeoutSec:      5,
		Enabled:         true,
	}
	_, err = mgr.RefreshSource(context.Background(), srcBlocked)
	if !errors.Is(err, ErrSSRFBlockedAddress) {
		t.Fatalf("expected ErrSSRFBlockedAddress when AllowPrivate=false, got %v", err)
	}

	// 2. With explicit AllowPrivate=true on the specific source, fetch succeeds and stores ETag
	id, err := store.CreateSource(storage.SourceRecord{
		Name:              "Local Test Allowed",
		Kind:              "url",
		Location:          srv.URL + "/list.txt",
		Format:            "txt",
		DefaultProtocol:   "http",
		AllowPrivate:      true,
		UpdateIntervalSec: 600,
		TimeoutSec:        5,
		Enabled:           true,
	})
	if err != nil {
		t.Fatal(err)
	}
	srcs, _ := store.ListSources()
	var created storage.SourceRecord
	for _, s := range srcs {
		if int64(s.ID) == id {
			created = s
		}
	}

	prog, err := mgr.RefreshSource(context.Background(), created)
	if err != nil || prog.Status != "ok" || prog.TotalUnique != 2 {
		t.Fatalf("expected ok refresh with 2 unique proxies, got prog=%+v err=%v", prog, err)
	}

	// 3. Second fetch sends If-None-Match and handles HTTP 304 Not Modified cleanly
	srcs, _ = store.ListSources()
	for _, s := range srcs {
		if int64(s.ID) == id {
			created = s
		}
	}
	prog304, err := mgr.RefreshSource(context.Background(), created)
	if err != nil || prog304.Status != "not_modified" {
		t.Fatalf("expected not_modified on ETag match, got prog=%+v err=%v", prog304, err)
	}

	// 4. Oversized body (> 1024 bytes) triggers ErrSourceResponseTooLarge and sets backoff
	created.Location = srv.URL + "/oversize"
	created.ETag = ""
	_, errOversize := mgr.RefreshSource(context.Background(), created)
	if !errors.Is(errOversize, ErrSourceResponseTooLarge) {
		t.Fatalf("expected ErrSourceResponseTooLarge, got %v", errOversize)
	}
}
