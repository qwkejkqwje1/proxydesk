package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/proxydesk/proxydesk/internal/checker"
	"github.com/proxydesk/proxydesk/internal/config"
	"github.com/proxydesk/proxydesk/internal/diagnostics"
	"github.com/proxydesk/proxydesk/internal/dns"
	"github.com/proxydesk/proxydesk/internal/gateway"
	"github.com/proxydesk/proxydesk/internal/model"
	"github.com/proxydesk/proxydesk/internal/pools"
	"github.com/proxydesk/proxydesk/internal/scoring"
	"github.com/proxydesk/proxydesk/internal/sources"
	"github.com/proxydesk/proxydesk/internal/storage"
)

func TestAPISecurityHostOriginTokenAndManualImport(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.ResolvedDataDir = dir

	store, err := storage.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	clk := model.NewFakeClock(time.Date(2026, 10, 13, 18, 0, 0, 0, time.UTC))
	credStore := model.NewCredentialStore()
	token, _ := GenerateSessionToken()
	logger := diagnostics.NewRotatingLogger(dir, 1024*1024, 2, token)
	srcMgr := sources.NewManager(store, credStore, logger, clk, 1, cfg.Budgets.MaxSourceBodyBytes)
	chk := checker.NewChecker(&cfg, credStore, clk, nil)
	scr := scoring.NewScorer(&cfg, store, clk)
	sel := pools.NewSelector(clk, 1)
	dnsSrv := dns.NewServer(clk, 1024, false, nil)
	gw := gateway.NewGateway(&cfg, credStore, sel, dnsSrv, clk, nil)

	srv := NewServer(&cfg, store, credStore, srcMgr, chk, scr, sel, gw, dnsSrv, logger, nil, token)
	handler := srv.Handler()

	// 1. DNS Rebinding test: foreign Host header must be rejected with 403 Forbidden
	reqRebind := httptest.NewRequest(http.MethodGet, "http://evil-rebind.com:18443/api/v1/overview", nil)
	reqRebind.Header.Set("X-ProxyDesk-Token", token)
	wRebind := httptest.NewRecorder()
	handler.ServeHTTP(wRebind, reqRebind)
	if wRebind.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for DNS rebinding Host, got %d", wRebind.Code)
	}

	// 2. Cross-Origin request test: foreign Origin header must be rejected with 403 Forbidden
	reqOrigin := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:18443/api/v1/proxies/import", strings.NewReader(`{}`))
	reqOrigin.Header.Set("Origin", "https://attacker.example.com")
	reqOrigin.Header.Set("X-ProxyDesk-Token", token)
	wOrigin := httptest.NewRecorder()
	handler.ServeHTTP(wOrigin, reqOrigin)
	if wOrigin.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for cross-origin POST, got %d", wOrigin.Code)
	}

	// 3. Missing token test: request without X-ProxyDesk-Token must return 401 Unauthorized
	reqNoTok := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:18443/api/v1/proxies", nil)
	wNoTok := httptest.NewRecorder()
	handler.ServeHTTP(wNoTok, reqNoTok)
	if wNoTok.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized without token, got %d", wNoTok.Code)
	}

	// 4. Valid loopback import request with valid token succeeds and stores unknown status proxies
	importBody := `{"content":"http://198.51.100.10:8080\nsocks5://user:SecretPass99@203.0.113.20:1080\n","default_protocol":"http"}`
	reqImport := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:18443/api/v1/proxies/import", strings.NewReader(importBody))
	reqImport.Header.Set("X-ProxyDesk-Token", token)
	wImport := httptest.NewRecorder()
	handler.ServeHTTP(wImport, reqImport)
	if wImport.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on manual import, got %d: %s", wImport.Code, wImport.Body.String())
	}

	// 5. Diagnostic bundle must not contain session token or proxy password (INV-05)
	reqDiag := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:18443/api/v1/diagnostics/bundle", nil)
	reqDiag.Header.Set("X-ProxyDesk-Token", token)
	wDiag := httptest.NewRecorder()
	handler.ServeHTTP(wDiag, reqDiag)
	if wDiag.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on diagnostic bundle, got %d", wDiag.Code)
	}
	if bytes.Contains(wDiag.Body.Bytes(), []byte("SecretPass99")) || bytes.Contains(wDiag.Body.Bytes(), []byte(token)) {
		t.Fatal("INV-05 violated: diagnostic bundle leaked token or password")
	}
}
