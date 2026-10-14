package api

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/proxydesk/proxydesk/internal/app"
	"github.com/proxydesk/proxydesk/internal/checker"
	"github.com/proxydesk/proxydesk/internal/config"
	"github.com/proxydesk/proxydesk/internal/diagnostics"
	"github.com/proxydesk/proxydesk/internal/dns"
	"github.com/proxydesk/proxydesk/internal/gateway"
	"github.com/proxydesk/proxydesk/internal/model"
	"github.com/proxydesk/proxydesk/internal/parsers"
	"github.com/proxydesk/proxydesk/internal/pools"
	"github.com/proxydesk/proxydesk/internal/rules"
	"github.com/proxydesk/proxydesk/internal/scoring"
	"github.com/proxydesk/proxydesk/internal/sources"
	"github.com/proxydesk/proxydesk/internal/storage"
)

type Server struct {
	app          *app.App
	cfg          *config.Config
	store        *storage.Store
	credStore    *model.CredentialStore
	sourceMgr    *sources.Manager
	checker      *checker.Checker
	scorer       *scoring.Scorer
	poolSelector *pools.Selector
	gateway      *gateway.Gateway
	dnsServer    *dns.Server
	logger       *diagnostics.RotatingLogger
	uiFS         fs.FS
	token        string

	sseMu         sync.Mutex
	sseClients    map[chan string]struct{}
	droppedEvents atomic.Int64
}

func GenerateSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func NewServerWithApp(application *app.App, uiFS fs.FS, token string) *Server {
	return &Server{
		app:          application,
		cfg:          application.Cfg,
		store:        application.Store,
		credStore:    application.CredStore,
		sourceMgr:    application.SourceMgr,
		checker:      application.Checker,
		scorer:       application.Scorer,
		poolSelector: application.PoolSelector,
		gateway:      application.Gateway,
		dnsServer:    application.DNSServer,
		logger:       application.Logger,
		uiFS:         uiFS,
		token:        token,
		sseClients:   make(map[chan string]struct{}),
	}
}

func NewServer(
	cfg *config.Config,
	store *storage.Store,
	credStore *model.CredentialStore,
	sourceMgr *sources.Manager,
	chk *checker.Checker,
	scorer *scoring.Scorer,
	poolSel *pools.Selector,
	gw *gateway.Gateway,
	dnsSrv *dns.Server,
	logger *diagnostics.RotatingLogger,
	uiFS fs.FS,
	token string,
) *Server {
	return &Server{
		cfg:          cfg,
		store:        store,
		credStore:    credStore,
		sourceMgr:    sourceMgr,
		checker:      chk,
		scorer:       scorer,
		poolSelector: poolSel,
		gateway:      gw,
		dnsServer:    dnsSrv,
		logger:       logger,
		uiFS:         uiFS,
		token:        token,
		sseClients:   make(map[chan string]struct{}),
	}
}

func (s *Server) Token() string {
	return s.token
}

func (s *Server) syncApp() {
	if s.app != nil {
		_ = s.app.SyncRuntimeState()
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/health", s.handleHealth)

	mux.HandleFunc("/api/v1/overview", s.requireToken(s.handleOverview))
	mux.HandleFunc("/api/v1/proxies", s.requireToken(s.handleProxies))
	mux.HandleFunc("/api/v1/proxies/import", s.requireToken(s.handleManualImport))
	mux.HandleFunc("/api/v1/proxies/check", s.requireToken(s.handleCheckProxies))
	mux.HandleFunc("/api/v1/proxies/check/cancel", s.requireToken(s.handleCancelCheck))
	mux.HandleFunc("/api/v1/proxies/export", s.requireToken(s.handleExportProxies))

	mux.HandleFunc("/api/v1/sources", s.requireToken(s.handleSources))
	mux.HandleFunc("/api/v1/sources/import", s.requireToken(s.handleImportSources))
	mux.HandleFunc("/api/v1/sources/refresh", s.requireToken(s.handleRefreshSource))
	mux.HandleFunc("/api/v1/sources/cancel", s.requireToken(s.handleCancelSource))
	mux.HandleFunc("/api/v1/sources/export", s.requireToken(s.handleExportSources))

	mux.HandleFunc("/api/v1/pools", s.requireToken(s.handlePools))
	mux.HandleFunc("/api/v1/pools/activate", s.requireToken(s.handleActivatePool))
	mux.HandleFunc("/api/v1/pools/select", s.requireToken(s.handlePoolSelect))

	mux.HandleFunc("/api/v1/gateway/connections", s.requireToken(s.handleGatewayConnections))
	mux.HandleFunc("/api/v1/gateway/toggle", s.requireToken(s.handleGatewayToggle))

	mux.HandleFunc("/api/v1/dns/groups", s.requireToken(s.handleDNSGroups))
	mux.HandleFunc("/api/v1/dns/test", s.requireToken(s.handleDNSTest))

	mux.HandleFunc("/api/v1/rules/dns", s.requireToken(s.handleDNSRules))
	mux.HandleFunc("/api/v1/rules/routing", s.requireToken(s.handleRoutingRules))
	mux.HandleFunc("/api/v1/rules/test", s.requireToken(s.handleRulesDryRun))

	mux.HandleFunc("/api/v1/diagnostics/logs", s.requireToken(s.handleLogs))
	mux.HandleFunc("/api/v1/diagnostics/bundle", s.requireToken(s.handleDiagnosticBundle))
	mux.HandleFunc("/api/v1/backup/create", s.requireToken(s.handleBackupCreate))
	mux.HandleFunc("/api/v1/backup/restore", s.requireToken(s.handleBackupRestore))
	mux.HandleFunc("/api/v1/config/export", s.requireToken(s.handleExportConfig))
	mux.HandleFunc("/api/v1/events", s.requireToken(s.handleSSE))

	mux.HandleFunc("/", s.handleUI)

	return s.securityMiddleware(mux)
}

func (s *Server) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isAllowedLoopbackHost(r.Host) {
			http.Error(w, "Forbidden Host header (DNS rebinding protection)", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			if !strings.HasPrefix(origin, "http://127.0.0.1:") && !strings.HasPrefix(origin, "http://localhost:") && !strings.HasPrefix(origin, "http://[::1]:") {
				http.Error(w, "Forbidden Origin header", http.StatusForbidden)
				return
			}
		}
		if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" && sfs != "none" {
			http.Error(w, "Cross-site request blocked by Sec-Fetch-Site policy", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; img-src 'self' data:;")

		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireToken(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		gotToken := r.Header.Get("X-ProxyDesk-Token")
		if gotToken == "" && r.URL.Path == "/api/v1/events" {
			gotToken = r.URL.Query().Get("token")
		}
		if subtle.ConstantTimeCompare([]byte(gotToken), []byte(s.token)) != 1 {
			http.Error(w, `{"error":"unauthorized: invalid or missing X-ProxyDesk-Token"}`, http.StatusUnauthorized)
			return
		}
		fn(w, r)
	}
}

func isAllowedLoopbackHost(hostPort string) bool {
	if hostPort == "" {
		return false
	}
	host := hostPort
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		host = h
	}
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": s.cfg.Version})
}

// handleOverview returns real database counts AND actual bound listener addresses + bind errors
// (never reporting unstarted config addresses as running — STABILIZATION-01 Section 2).
func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	_, totalProxies, _ := s.store.ListProxies(storage.ProxyQueryFilter{Limit: 1})
	_, healthyCount, _ := s.store.ListProxies(storage.ProxyQueryFilter{Status: "healthy", Limit: 1})
	_, unknownCount, _ := s.store.ListProxies(storage.ProxyQueryFilter{Status: "unknown", Limit: 1})
	_, degradedCount, _ := s.store.ListProxies(storage.ProxyQueryFilter{Status: "degraded", Limit: 1})
	_, quarantinedCount, _ := s.store.ListProxies(storage.ProxyQueryFilter{Status: "quarantined", Limit: 1})
	srcs, _ := s.store.ListSources()

	var lState app.ListenerState
	if s.app != nil {
		lState = s.app.ListenerState()
	} else {
		lState = app.ListenerState{BindErrors: map[string]string{}}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"proxies_total":       totalProxies,
		"proxies_healthy":     healthyCount,
		"proxies_unknown":     unknownCount,
		"proxies_degraded":    degradedCount,
		"proxies_quarantined": quarantinedCount,
		"sources_total":       len(srcs),
		"listeners":           lState,
		"http_gateway_addr":   lState.HTTPGatewayBoundAddr,
		"socks5_gateway_addr": lState.SOCKS5GatewayBoundAddr,
		"dns_listen_addr":     lState.DNSUDPBoundAddr,
		"dns_tcp_addr":        lState.DNSTCPBoundAddr,
		"bind_errors":         lState.BindErrors,
		"dns_resolution_mode": s.cfg.DNSResolutionMode,
		"strict_proxy_only":   s.cfg.StrictProxyOnly,
		"budgets":             s.cfg.Budgets,
	})
}

func (s *Server) handleProxies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	filter := storage.ProxyQueryFilter{
		Search:   q.Get("search"),
		Protocol: q.Get("protocol"),
		Status:   q.Get("status"),
		SortBy:   q.Get("sort_by"),
		SortDesc: q.Get("sort_dir") != "asc",
		Limit:    limit,
		Offset:   offset,
	}
	items, total, err := s.store.ListProxies(filter)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items,
		"total": total,
	})
}

func (s *Server) handleManualImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, s.cfg.Budgets.MaxSourceBodyBytes+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read request body"})
		return
	}
	if int64(len(bodyBytes)) > s.cfg.Budgets.MaxSourceBodyBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "input exceeds max_source_body_bytes limit"})
		return
	}

	var req struct {
		Content         string `json:"content"`
		DefaultProtocol string `json:"default_protocol"`
		AllowPrivate    bool   `json:"allow_private"`
	}
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	stats := parsers.ParseTXT(req.Content, req.DefaultProtocol, req.AllowPrivate)
	upserted, err := s.store.UpsertCandidates(r.Context(), 0, stats.Candidates, s.credStore, time.Now().UTC())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.syncApp()
	s.logger.Log("INFO", "import", fmt.Sprintf("Manual import processed: valid=%d unique=%d errors=%d", stats.ValidCount, stats.UniqueCount, stats.ErrorCount))
	writeJSON(w, http.StatusOK, map[string]any{
		"total_lines":  stats.TotalLines,
		"valid_count":  stats.ValidCount,
		"unique_count": stats.UniqueCount,
		"error_count":  stats.ErrorCount,
		"upserted":     upserted,
	})
}

func (s *Server) handleCheckProxies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	proxies, _, err := s.store.ListProxies(storage.ProxyQueryFilter{Limit: 500})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	runCheck := func(ctx context.Context) {
		lastBroadcast := time.Time{}
		s.checker.RunBatch(ctx, proxies, func(done, total int, res checker.CycleResult) {
			for _, p := range proxies {
				if p.ID == res.ProxyID {
					_, _, _ = s.scorer.SaveCycleAndPrune(p, res)
					break
				}
			}
			if done == total || time.Since(lastBroadcast) >= 150*time.Millisecond {
				lastBroadcast = time.Now()
				s.broadcastSSE(fmt.Sprintf(`{"type":"check_progress","done":%d,"total":%d}`, done, total))
			}
		})
		s.syncApp()
	}

	if r.URL.Query().Get("sync") == "1" {
		runCheck(r.Context())
		writeJSON(w, http.StatusOK, map[string]any{"status": "completed", "checked": len(proxies)})
		return
	}

	go runCheck(context.Background())
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "started", "queued": len(proxies)})
}

func (s *Server) handleCancelCheck(w http.ResponseWriter, r *http.Request) {
	cancelled := s.checker.CancelBatch()
	writeJSON(w, http.StatusOK, map[string]any{"cancelled": cancelled})
}

func (s *Server) handleExportProxies(w http.ResponseWriter, r *http.Request) {
	format := strings.ToLower(r.URL.Query().Get("format"))
	proto := strings.ToLower(r.URL.Query().Get("protocol"))
	if proto == "all" {
		proto = ""
	}
	items, _, err := s.store.ListProxies(storage.ProxyQueryFilter{Protocol: proto, Limit: 500})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if format == "json" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(items)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for _, p := range items {
		if proto == "" {
			_, _ = fmt.Fprintf(w, "%s://%s:%d\n", p.Protocol, p.Host, p.Port)
		} else {
			_, _ = fmt.Fprintf(w, "%s:%d\n", p.Host, p.Port)
		}
	}
}

// --- Sources CRUD + Import/Export/Refresh ---

func (s *Server) handleSources(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		list, err := s.store.ListSources()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": list})

	case http.MethodPost:
		var src storage.SourceRecord
		if err := json.NewDecoder(io.LimitReader(r.Body, 65536)).Decode(&src); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid source JSON"})
			return
		}
		id, err := s.store.CreateSource(src)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"id": id})

	case http.MethodPut:
		var src storage.SourceRecord
		if err := json.NewDecoder(io.LimitReader(r.Body, 65536)).Decode(&src); err != nil || src.ID <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid source update payload"})
			return
		}
		if err := s.store.UpdateSource(src); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"updated": src.ID})

	case http.MethodDelete:
		id, _ := strconv.Atoi(r.URL.Query().Get("id"))
		if id <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing source id"})
			return
		}
		if err := s.store.DeleteSource(id); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": id})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleImportSources(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var list []storage.SourceRecord
	if err := json.NewDecoder(io.LimitReader(r.Body, 1024*1024)).Decode(&list); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid sources JSON array"})
		return
	}
	imported := 0
	for _, src := range list {
		if src.Name == "" || src.Location == "" {
			continue
		}
		if _, err := s.store.CreateSource(src); err == nil {
			imported++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"imported": imported})
}

func (s *Server) handleRefreshSource(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SourceID int `json:"source_id"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req)
	src, err := s.store.GetSource(req.SourceID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "source not found"})
		return
	}
	prog, err := s.sourceMgr.RefreshSource(r.Context(), src)
	s.syncApp()
	if err != nil {
		writeJSON(w, http.StatusBadGateway, prog)
		return
	}
	writeJSON(w, http.StatusOK, prog)
}

func (s *Server) handleCancelSource(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SourceID int64 `json:"source_id"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req)
	ok := s.sourceMgr.CancelSource(req.SourceID)
	writeJSON(w, http.StatusOK, map[string]any{"cancelled": ok})
}

func (s *Server) handleExportSources(w http.ResponseWriter, r *http.Request) {
	data, err := s.sourceMgr.ExportSourcesJSON()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(data)
}

// --- Pools CRUD, Activation & Selection ---

func (s *Server) handlePools(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		list, err := s.store.ListPools()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": list})

	case http.MethodPost:
		var p storage.PoolRecord
		if err := json.NewDecoder(io.LimitReader(r.Body, 65536)).Decode(&p); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid pool JSON"})
			return
		}
		id, err := s.store.CreatePool(p)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		s.syncApp()
		writeJSON(w, http.StatusCreated, map[string]any{"id": id})

	case http.MethodPut:
		var p storage.PoolRecord
		if err := json.NewDecoder(io.LimitReader(r.Body, 65536)).Decode(&p); err != nil || p.ID <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid pool update payload"})
			return
		}
		if err := s.store.UpdatePool(p); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		s.syncApp()
		writeJSON(w, http.StatusOK, map[string]any{"updated": p.ID})

	case http.MethodDelete:
		id, _ := strconv.Atoi(r.URL.Query().Get("id"))
		if id <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing pool id"})
			return
		}
		if err := s.store.DeletePool(id); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		s.syncApp()
		writeJSON(w, http.StatusOK, map[string]any{"deleted": id})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleActivatePool(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		PoolID        int  `json:"pool_id"`
		ActiveProxyID *int `json:"active_proxy_id,omitempty"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || req.PoolID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid pool activation request"})
		return
	}
	if err := s.store.SetActivePool(req.PoolID, req.ActiveProxyID); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.syncApp()
	writeJSON(w, http.StatusOK, map[string]any{"activated_pool_id": req.PoolID})
}

func (s *Server) handlePoolSelect(w http.ResponseWriter, r *http.Request) {
	var poolCfg pools.PoolConfig
	if err := json.NewDecoder(io.LimitReader(r.Body, 16384)).Decode(&poolCfg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid pool config"})
		return
	}
	cands, _, err := s.store.ListProxies(storage.ProxyQueryFilter{Limit: 500})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	chosen, trace, selErr := s.poolSelector.Select(poolCfg, cands, pools.SelectionRequest{
		RequireConnect:   poolCfg.RequireConnect,
		RequireRemoteDNS: poolCfg.RequireRemoteDNS,
		CapabilityTTL:    time.Duration(s.cfg.CapabilityTTLMinutes) * time.Minute,
	})
	if selErr != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error":          selErr.Error(),
			"decision_trace": trace,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"selected":       chosen,
		"decision_trace": trace,
	})
}

// --- Gateway Connections & Toggle ---

func (s *Server) handleGatewayConnections(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"connections": s.gateway.RecentConnections(),
	})
}

func (s *Server) handleGatewayToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Enable bool `json:"enable"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid toggle payload"})
		return
	}
	if s.app == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "app lifecycle manager not attached"})
		return
	}
	if req.Enable {
		_ = s.app.StartGateway()
	} else {
		s.app.StopGateway()
	}
	writeJSON(w, http.StatusOK, s.app.ListenerState())
}

// --- DNS Groups, DNS Rules, Routing Rules ---

func (s *Server) handleDNSGroups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		list, err := s.store.ListDNSGroups()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": list})

	case http.MethodPost:
		var g storage.DNSGroupRecord
		if err := json.NewDecoder(io.LimitReader(r.Body, 65536)).Decode(&g); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid DNS group JSON"})
			return
		}
		id, err := s.store.CreateDNSGroup(g)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		s.syncApp()
		writeJSON(w, http.StatusCreated, map[string]any{"id": id})

	case http.MethodPut:
		var g storage.DNSGroupRecord
		if err := json.NewDecoder(io.LimitReader(r.Body, 65536)).Decode(&g); err != nil || g.ID <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid DNS group update payload"})
			return
		}
		if err := s.store.UpdateDNSGroup(g); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		s.syncApp()
		writeJSON(w, http.StatusOK, map[string]any{"updated": g.ID})

	case http.MethodDelete:
		id, _ := strconv.Atoi(r.URL.Query().Get("id"))
		if id <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing DNS group id"})
			return
		}
		if err := s.store.DeleteDNSGroup(id); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		s.syncApp()
		writeJSON(w, http.StatusOK, map[string]any{"deleted": id})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleDNSRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		list, err := s.store.ListDNSRules()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": list})

	case http.MethodPost, http.MethodPut:
		var rule rules.DNSRule
		if err := json.NewDecoder(io.LimitReader(r.Body, 65536)).Decode(&rule); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid DNS rule JSON"})
			return
		}
		id, err := s.store.SaveDNSRule(rule)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		s.syncApp()
		writeJSON(w, http.StatusOK, map[string]any{"id": id})

	case http.MethodDelete:
		id, _ := strconv.Atoi(r.URL.Query().Get("id"))
		if id <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing DNS rule id"})
			return
		}
		if err := s.store.DeleteDNSRule(id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		s.syncApp()
		writeJSON(w, http.StatusOK, map[string]any{"deleted": id})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleRoutingRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		list, err := s.store.ListRoutingRules()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": list})

	case http.MethodPost, http.MethodPut:
		var rule rules.RoutingRule
		if err := json.NewDecoder(io.LimitReader(r.Body, 65536)).Decode(&rule); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid routing rule JSON"})
			return
		}
		id, err := s.store.SaveRoutingRule(rule)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		s.syncApp()
		writeJSON(w, http.StatusOK, map[string]any{"id": id})

	case http.MethodDelete:
		id, _ := strconv.Atoi(r.URL.Query().Get("id"))
		if id <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing routing rule id"})
			return
		}
		if err := s.store.DeleteRoutingRule(id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		s.syncApp()
		writeJSON(w, http.StatusOK, map[string]any{"deleted": id})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleDNSTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
		QType  string `json:"qtype"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	qt := dns.TypeA
	if strings.ToUpper(req.QType) == "AAAA" {
		qt = dns.TypeAAAA
	}
	ips, rcode, ttl, trace, err := s.dnsServer.ResolveWithTTL(r.Context(), req.Domain, qt)
	var ipList []string
	for _, ip := range ips {
		ipList = append(ipList, ip.String())
	}
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"domain":         req.Domain,
		"ips":            ipList,
		"rcode":          rcode,
		"ttl":            ttl,
		"decision_trace": trace,
		"error":          errMsg,
	})
}

func (s *Server) handleRulesDryRun(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain       string              `json:"domain"`
		DNSRules     []rules.DNSRule     `json:"dns_rules"`
		RoutingRules []rules.RoutingRule `json:"routing_rules"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 65536)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid dry-run payload"})
		return
	}
	dRules := req.DNSRules
	if len(dRules) == 0 {
		dRules, _ = s.store.ListDNSRules()
	}
	rRules := req.RoutingRules
	if len(rRules) == 0 {
		rRules, _ = s.store.ListRoutingRules()
	}
	now := time.Now().UTC()
	dRule, dTrace := rules.EvaluateDNS(req.Domain, dRules, 1, now)
	rRule, rTrace := rules.EvaluateRoute(req.Domain, rRules, s.cfg.DNSResolutionMode, s.cfg.StrictProxyOnly, now)
	writeJSON(w, http.StatusOK, map[string]any{
		"dns_rule":    dRule,
		"dns_trace":   dTrace,
		"route_rule":  rRule,
		"route_trace": rTrace,
	})
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"entries": s.logger.Recent(200),
	})
}

func (s *Server) handleDiagnosticBundle(w http.ResponseWriter, r *http.Request) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	cfgBytes, _ := json.MarshalIndent(s.cfg, "", "  ")
	safeCfg := diagnostics.RedactString(string(cfgBytes), s.token)
	if f, err := zw.Create("config_redacted.json"); err == nil {
		_, _ = f.Write([]byte(safeCfg))
	}

	logs := s.logger.Recent(500)
	logsBytes, _ := json.MarshalIndent(logs, "", "  ")
	safeLogs := diagnostics.RedactString(string(logsBytes), s.token)
	if f, err := zw.Create("logs_redacted.json"); err == nil {
		_, _ = f.Write([]byte(safeLogs))
	}

	_ = zw.Close()
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="proxydesk-diagnostics.zip"`)
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) handleBackupCreate(w http.ResponseWriter, r *http.Request) {
	backupPath := filepath.Join(s.cfg.ResolvedDataDir, "proxydesk-backup.db")
	if err := s.store.CreateBackup(backupPath); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := storage.ValidateBackupVersion(backupPath); err != nil {
		_ = os.Remove(backupPath)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"backup_file": "proxydesk-backup.db", "schema_version": storage.CurrentSchemaVersion})
}

func (s *Server) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		BackupFile string `json:"backup_file"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req)
	fileName := filepath.Base(req.BackupFile)
	if fileName == "" || fileName == "." || fileName == "/" {
		fileName = "proxydesk-backup.db"
	}
	backupPath := filepath.Join(s.cfg.ResolvedDataDir, fileName)
	if err := s.store.RestoreFromBackup(backupPath); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.syncApp()
	writeJSON(w, http.StatusOK, map[string]any{"restored": fileName, "schema_version": storage.CurrentSchemaVersion})
}

func (s *Server) handleExportConfig(w http.ResponseWriter, r *http.Request) {
	cfgBytes, _ := json.MarshalIndent(s.cfg, "", "  ")
	safe := diagnostics.RedactString(string(cfgBytes), s.token)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write([]byte(safe))
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}
	s.sseMu.Lock()
	if len(s.sseClients) >= s.cfg.Budgets.MaxSSEClients {
		s.sseMu.Unlock()
		http.Error(w, "Max SSE clients budget reached", http.StatusTooManyRequests)
		return
	}
	ch := make(chan string, 16)
	s.sseClients[ch] = struct{}{}
	s.sseMu.Unlock()

	defer func() {
		s.sseMu.Lock()
		delete(s.sseClients, ch)
		s.sseMu.Unlock()
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	_, _ = fmt.Fprintf(w, "data: {\"type\":\"connected\"}\n\n")
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case msg := <-ch:
			_, _ = fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		}
	}
}

func (s *Server) broadcastSSE(payload string) {
	s.sseMu.Lock()
	defer s.sseMu.Unlock()
	for ch := range s.sseClients {
		select {
		case ch <- payload:
		default:
			s.droppedEvents.Add(1)
		}
	}
}

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if s.uiFS == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, `<!doctype html><html><head><meta name="proxydesk-token" content="%s"></head><body>ProxyDesk UI</body></html>`, s.token)
		return
	}
	reqPath := strings.TrimPrefix(r.URL.Path, "/")
	if reqPath == "" || reqPath == "index.html" {
		raw, err := fs.ReadFile(s.uiFS, "index.html")
		if err != nil {
			http.Error(w, "UI index.html not found", http.StatusNotFound)
			return
		}
		injected := strings.Replace(string(raw), "__PROXYDESK_SESSION_TOKEN__", s.token, 1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(injected))
		return
	}
	http.FileServer(http.FS(s.uiFS)).ServeHTTP(w, r)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
