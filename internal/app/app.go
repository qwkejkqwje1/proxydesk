package app

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
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

type ListenerState struct {
	APIBoundAddr           string            `json:"api_bound_addr"`
	HTTPGatewayBoundAddr   string            `json:"http_gateway_bound_addr"`
	SOCKS5GatewayBoundAddr string            `json:"socks5_gateway_bound_addr"`
	DNSUDPBoundAddr        string            `json:"dns_udp_bound_addr"`
	DNSTCPBoundAddr        string            `json:"dns_tcp_bound_addr"`
	GatewayRunning         bool              `json:"gateway_running"`
	DNSRunning             bool              `json:"dns_running"`
	BindErrors             map[string]string `json:"bind_errors"`
}

type App struct {
	Cfg          *config.Config
	Store        *storage.Store
	CredStore    *model.CredentialStore
	SourceMgr    *sources.Manager
	Checker      *checker.Checker
	Scorer       *scoring.Scorer
	PoolSelector *pools.Selector
	DNSServer    *dns.Server
	Gateway      *gateway.Gateway
	Logger       *diagnostics.RotatingLogger
	Clock        model.Clock

	mu            sync.RWMutex
	appCtx        context.Context
	appCancel     context.CancelFunc
	apiLn         net.Listener
	apiHTTPServer *http.Server

	gwCtx        context.Context
	gwCancel     context.CancelFunc
	httpGwLn     net.Listener
	httpGwServer *http.Server
	socks5GwLn   net.Listener

	dnsCtx    context.Context
	dnsCancel context.CancelFunc
	dnsUDP    net.PacketConn
	dnsTCP    net.Listener

	state ListenerState
}

func New(cfg *config.Config, store *storage.Store, clock model.Clock, customRootCAs *x509.CertPool, token string) *App {
	if clock == nil {
		clock = model.RealClock{}
	}
	credStore := model.NewCredentialStore()
	logger := diagnostics.NewRotatingLogger(cfg.ResolvedDataDir, cfg.Budgets.MaxLogFileBytes, cfg.Budgets.MaxLogFiles, token)
	srcMgr := sources.NewManager(store, credStore, logger, clock, 1, cfg.Budgets.MaxSourceBodyBytes)
	chk := checker.NewChecker(cfg, credStore, clock, customRootCAs)
	scr := scoring.NewScorer(cfg, store, clock)
	poolSel := pools.NewSelector(clock, 1)
	dnsSrv := dns.NewServer(clock, cfg.Budgets.MaxDNSCacheEntries, cfg.EnableDNSQueryLog, customRootCAs)

	a := &App{
		Cfg:          cfg,
		Store:        store,
		CredStore:    credStore,
		SourceMgr:    srcMgr,
		Checker:      chk,
		Scorer:       scr,
		PoolSelector: poolSel,
		DNSServer:    dnsSrv,
		Logger:       logger,
		Clock:        clock,
		state: ListenerState{
			BindErrors: make(map[string]string),
		},
	}

	gw := gateway.NewGateway(cfg, credStore, poolSel, dnsSrv, clock, func(proxyID int, dialErr error) {
		logger.Log("WARN", "gateway", fmt.Sprintf("Upstream proxy id=%d dial failed: %v", proxyID, dialErr))
		a.markProxyDialFailure(proxyID, dialErr)
	})
	a.Gateway = gw
	return a
}

func (a *App) markProxyDialFailure(proxyID int, dialErr error) {
	items, _, err := a.Store.ListProxies(storage.ProxyQueryFilter{Limit: 500})
	if err != nil {
		return
	}
	for _, p := range items {
		if p.ID == proxyID {
			cycle := checker.CycleResult{
				ProxyID:          p.ID,
				CheckedAt:        a.Clock.Now(),
				Outcome:          checker.OutcomeFailure,
				TargetsTested:    1,
				TargetsSucceeded: 0,
				Capabilities:     p.Capabilities,
				SummaryError:     "gateway dial failure: " + dialErr.Error(),
			}
			_, _, _ = a.Scorer.SaveCycleAndPrune(p, cycle)
			_ = a.SyncRuntimeState()
			return
		}
	}
}

func (a *App) SyncRuntimeState() error {
	poolsList, err := a.Store.ListPools()
	if err != nil {
		return err
	}
	var activePoolRec storage.PoolRecord
	if len(poolsList) > 0 {
		activePoolRec = poolsList[0]
	} else {
		activePoolRec = storage.PoolRecord{
			ID:              1,
			Name:            "Default Reliable Pool",
			Kind:            "reliable",
			Strategy:        "failover",
			RequireConnect:  true,
			HysteresisDelta: 5.0,
		}
	}

	allProxies, _, err := a.Store.ListProxies(storage.ProxyQueryFilter{Limit: 500})
	if err != nil {
		return err
	}
	candidates := allProxies
	if activePoolRec.Kind == "manual" && len(activePoolRec.MemberProxyIDs) > 0 {
		memberSet := make(map[int]struct{}, len(activePoolRec.MemberProxyIDs))
		for _, id := range activePoolRec.MemberProxyIDs {
			memberSet[id] = struct{}{}
		}
		var filtered []storage.ProxyRecord
		for _, p := range allProxies {
			if _, ok := memberSet[p.ID]; ok {
				filtered = append(filtered, p)
			}
		}
		candidates = filtered
	}

	routeRules, err := a.Store.ListRoutingRules()
	if err != nil {
		return err
	}

	poolCfg := pools.PoolConfig{
		ID:               activePoolRec.ID,
		Name:             activePoolRec.Name,
		Kind:             activePoolRec.Kind,
		Strategy:         activePoolRec.Strategy,
		RequiredProtocol: activePoolRec.RequiredProtocol,
		RequireConnect:   activePoolRec.RequireConnect,
		RequireRemoteDNS: activePoolRec.RequireRemoteDNS,
		MinScore:         activePoolRec.MinScore,
		CountryCode:      activePoolRec.CountryCode,
		HysteresisDelta:  activePoolRec.HysteresisDelta,
		ActiveProxyID:    activePoolRec.ActiveProxyID,
	}
	a.Gateway.UpdateState(routeRules, poolCfg, candidates)

	dnsGroupRecs, err := a.Store.ListDNSGroups()
	if err != nil {
		return err
	}
	var dnsGroups []dns.DNSGroup
	defaultDNSGroupID := 1
	for _, g := range dnsGroupRecs {
		if g.IsDefault {
			defaultDNSGroupID = g.ID
		}
		var ups []dns.UpstreamEndpoint
		for _, u := range g.Upstreams {
			ups = append(ups, dns.UpstreamEndpoint{Protocol: u.Protocol, Address: u.Address})
		}
		dnsGroups = append(dnsGroups, dns.DNSGroup{
			ID:                  g.ID,
			Name:                g.Name,
			Upstreams:           ups,
			BootstrapIPs:        g.BootstrapIPs,
			AllowPublicFallback: g.AllowPublicFallback,
		})
	}
	dnsRules, err := a.Store.ListDNSRules()
	if err != nil {
		return err
	}
	a.DNSServer.SetConfig(dnsGroups, defaultDNSGroupID, dnsRules, a.Cfg.EnableDNSQueryLog)
	return nil
}

func (a *App) ListenerState() ListenerState {
	a.mu.RLock()
	defer a.mu.RUnlock()
	errsCopy := make(map[string]string, len(a.state.BindErrors))
	for k, v := range a.state.BindErrors {
		errsCopy[k] = v
	}
	st := a.state
	st.BindErrors = errsCopy
	return st
}

func (a *App) Start(parentCtx context.Context, apiHandler http.Handler, schedulerInterval time.Duration) error {
	if err := a.SyncRuntimeState(); err != nil {
		return fmt.Errorf("sync initial runtime state: %w", err)
	}

	ctx, cancel := context.WithCancel(parentCtx)
	a.mu.Lock()
	a.appCtx = ctx
	a.appCancel = cancel
	a.mu.Unlock()

	apiLn, err := net.Listen("tcp", a.Cfg.APIListenAddr)
	if err != nil {
		a.mu.Lock()
		a.state.BindErrors["api"] = err.Error()
		a.mu.Unlock()
		cancel()
		return fmt.Errorf("bind API listener %s: %w", a.Cfg.APIListenAddr, err)
	}
	a.mu.Lock()
	a.apiLn = apiLn
	a.state.APIBoundAddr = apiLn.Addr().String()
	delete(a.state.BindErrors, "api")
	a.apiHTTPServer = &http.Server{
		Handler:           apiHandler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	a.mu.Unlock()

	go func() {
		_ = a.apiHTTPServer.Serve(apiLn)
	}()

	_ = a.StartGateway()
	_ = a.StartDNS()

	if schedulerInterval <= 0 {
		schedulerInterval = 15 * time.Second
	}
	go a.schedulerLoop(ctx, schedulerInterval)
	return nil
}

func (a *App) StartGateway() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.state.GatewayRunning {
		return nil
	}
	baseCtx := a.appCtx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	gwCtx, gwCancel := context.WithCancel(baseCtx)
	a.gwCtx = gwCtx
	a.gwCancel = gwCancel

	var firstErr error

	httpLn, err := net.Listen("tcp", a.Cfg.HTTPGatewayAddr)
	if err != nil {
		a.state.HTTPGatewayBoundAddr = ""
		a.state.BindErrors["http_gateway"] = err.Error()
		firstErr = err
	} else {
		a.httpGwLn = httpLn
		a.state.HTTPGatewayBoundAddr = httpLn.Addr().String()
		delete(a.state.BindErrors, "http_gateway")
		srv := &http.Server{
			Handler:           http.HandlerFunc(a.Gateway.ServeHTTPProxy),
			ReadHeaderTimeout: 10 * time.Second,
		}
		a.httpGwServer = srv
		go func() {
			_ = srv.Serve(httpLn)
		}()
	}

	socksLn, err := net.Listen("tcp", a.Cfg.SOCKS5GatewayAddr)
	if err != nil {
		a.state.SOCKS5GatewayBoundAddr = ""
		a.state.BindErrors["socks5_gateway"] = err.Error()
		if firstErr == nil {
			firstErr = err
		}
	} else {
		a.socks5GwLn = socksLn
		a.state.SOCKS5GatewayBoundAddr = socksLn.Addr().String()
		delete(a.state.BindErrors, "socks5_gateway")
		go func() {
			_ = a.Gateway.ServeSOCKS5(gwCtx, socksLn)
		}()
	}

	a.state.GatewayRunning = a.httpGwLn != nil || a.socks5GwLn != nil
	return firstErr
}

func (a *App) StopGateway() {
	a.mu.Lock()
	if a.gwCancel != nil {
		a.gwCancel()
		a.gwCancel = nil
	}
	if a.httpGwServer != nil {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = a.httpGwServer.Shutdown(shutCtx)
		cancel()
		a.httpGwServer = nil
	}
	if a.httpGwLn != nil {
		_ = a.httpGwLn.Close()
		a.httpGwLn = nil
	}
	if a.socks5GwLn != nil {
		_ = a.socks5GwLn.Close()
		a.socks5GwLn = nil
	}
	a.state.HTTPGatewayBoundAddr = ""
	a.state.SOCKS5GatewayBoundAddr = ""
	a.state.GatewayRunning = false
	a.mu.Unlock()

	a.Gateway.CloseAllActive()
}

func (a *App) StartDNS() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.state.DNSRunning {
		return nil
	}
	baseCtx := a.appCtx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	dnsCtx, dnsCancel := context.WithCancel(baseCtx)
	a.dnsCtx = dnsCtx
	a.dnsCancel = dnsCancel

	var firstErr error

	udpConn, err := net.ListenPacket("udp", a.Cfg.DNSListenAddr)
	if err != nil {
		a.state.DNSUDPBoundAddr = ""
		a.state.BindErrors["dns_udp"] = err.Error()
		firstErr = err
	} else {
		a.dnsUDP = udpConn
		a.state.DNSUDPBoundAddr = udpConn.LocalAddr().String()
		delete(a.state.BindErrors, "dns_udp")
		go func() {
			_ = a.DNSServer.ServeUDP(dnsCtx, udpConn)
		}()
	}

	tcpAddr := a.Cfg.DNSListenAddr
	if a.state.DNSUDPBoundAddr != "" && strings.HasSuffix(a.Cfg.DNSListenAddr, ":0") {
		tcpAddr = a.state.DNSUDPBoundAddr
	}
	tcpLn, err := net.Listen("tcp", tcpAddr)
	if err != nil && tcpAddr != a.Cfg.DNSListenAddr {
		tcpLn, err = net.Listen("tcp", a.Cfg.DNSListenAddr)
	}
	if err != nil {
		a.state.DNSTCPBoundAddr = ""
		a.state.BindErrors["dns_tcp"] = err.Error()
		if firstErr == nil {
			firstErr = err
		}
	} else {
		a.dnsTCP = tcpLn
		a.state.DNSTCPBoundAddr = tcpLn.Addr().String()
		delete(a.state.BindErrors, "dns_tcp")
		go func() {
			_ = a.DNSServer.ServeTCP(dnsCtx, tcpLn)
		}()
	}

	a.state.DNSRunning = a.dnsUDP != nil || a.dnsTCP != nil
	return firstErr
}

func (a *App) StopDNS() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.dnsCancel != nil {
		a.dnsCancel()
		a.dnsCancel = nil
	}
	if a.dnsUDP != nil {
		_ = a.dnsUDP.Close()
		a.dnsUDP = nil
	}
	if a.dnsTCP != nil {
		_ = a.dnsTCP.Close()
		a.dnsTCP = nil
	}
	a.state.DNSUDPBoundAddr = ""
	a.state.DNSTCPBoundAddr = ""
	a.state.DNSRunning = false
}

func (a *App) schedulerLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.RunSchedulerTick(ctx)
		}
	}
}

func (a *App) RunSchedulerTick(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	dueSrcs, err := a.SourceMgr.DueSources()
	if err == nil && len(dueSrcs) > 0 {
		for _, src := range dueSrcs {
			if ctx.Err() != nil {
				return
			}
			_, _ = a.SourceMgr.RefreshSource(ctx, src)
		}
		_ = a.SyncRuntimeState()
	}

	dueProxies, err := a.Store.DueProxiesForRecheck(a.Clock.Now(), 32)
	if err == nil && len(dueProxies) > 0 {
		a.Checker.RunBatch(ctx, dueProxies, func(done, total int, res checker.CycleResult) {
			for _, p := range dueProxies {
				if p.ID == res.ProxyID {
					_, _, _ = a.Scorer.SaveCycleAndPrune(p, res)
					break
				}
			}
		})
		_ = a.SyncRuntimeState()
	}
}

func (a *App) Shutdown(ctx context.Context) error {
	a.mu.Lock()
	if a.appCancel != nil {
		a.appCancel()
	}
	apiSrv := a.apiHTTPServer
	apiLn := a.apiLn
	a.mu.Unlock()

	a.SourceMgr.CancelAll()
	a.Checker.CancelBatch()
	a.StopGateway()
	a.StopDNS()

	if apiSrv != nil {
		_ = apiSrv.Shutdown(ctx)
	}
	if apiLn != nil {
		_ = apiLn.Close()
	}
	return nil
}
