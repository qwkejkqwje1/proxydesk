package lock

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInstanceLockDetectsRunningInstanceAndRecoversFromStale(t *testing.T) {
	dir := t.TempDir()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/health" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")

	firstLock, existing, err := Acquire(dir, addr)
	if err != nil || existing != nil {
		t.Fatalf("first acquire failed: err=%v existing=%v", err, existing)
	}
	defer firstLock.Release()

	// Second acquire while first server is live must return ErrInstanceAlreadyRunning
	_, existing2, err2 := Acquire(dir, addr)
	if !errors.Is(err2, ErrInstanceAlreadyRunning) {
		t.Fatalf("expected ErrInstanceAlreadyRunning, got %v", err2)
	}
	if existing2 == nil || existing2.APIURL != srv.URL {
		t.Fatalf("unexpected existing metadata: %+v", existing2)
	}

	// If server stops (simulated crash leaving stale lock), next Acquire recovers cleanly
	srv.Close()
	recoveredLock, _, err3 := Acquire(dir, "127.0.0.1:18443")
	if err3 != nil {
		t.Fatalf("expected recovery from stale lock, got %v", err3)
	}
	_ = recoveredLock.Release()
}
