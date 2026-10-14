package gateway

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/proxydesk/proxydesk/internal/config"
	"github.com/proxydesk/proxydesk/internal/dns"
	"github.com/proxydesk/proxydesk/internal/model"
	"github.com/proxydesk/proxydesk/internal/pools"
	"github.com/proxydesk/proxydesk/internal/rules"
	"github.com/proxydesk/proxydesk/internal/storage"
)

var (
	ErrRouteBlocked            = errors.New("connection blocked by routing rule (INV-01)")
	ErrNoHealthyProxyAvailable = errors.New("no healthy proxy available and strict_proxy_only is enabled (INV-02)")
	ErrMaxConnectionsReached   = errors.New("maximum concurrent gateway connections reached")
)

type ActiveConnectionInfo struct {
	ID             int64               `json:"id"`
	Protocol       string              `json:"protocol"` // "http_connect", "http_forward", "socks5"
	Target         string              `json:"target"`   // redacted unless LogDomains=true
	RoutedVia      string              `json:"routed_via"`
	StartedAt      time.Time           `json:"started_at"`
	ClosedAt       *time.Time          `json:"closed_at,omitempty"`
	BytesUp        int64               `json:"bytes_up"`
	BytesDown      int64               `json:"bytes_down"`
	Active         bool                `json:"active"`
	DecisionTraces []model.DecisionTrace `json:"decision_traces"`
}

type Gateway struct {
	cfg          *config.Config
	credStore    *model.CredentialStore
	poolSelector *pools.Selector
	dnsServer    *dns.Server
	clock        model.Clock

	mu           sync.RWMutex
	routeRules   []rules.RoutingRule
	activePool   pools.PoolConfig
	candidates   []storage.ProxyRecord
	onProxyError func(proxyID int, err error)

	connSeq      atomic.Int64
	activeCount  atomic.Int32
	ringMu       sync.Mutex
	connRing     []*ActiveConnectionInfo
}

func NewGateway(cfg *config.Config, credStore *model.CredentialStore, selector *pools.Selector, dnsSrv *dns.Server, clock model.Clock, onProxyError func(proxyID int, err error)) *Gateway {
	if clock == nil {
		clock = model.RealClock{}
	}
	return &Gateway{
		cfg:          cfg,
		credStore:    credStore,
		poolSelector: selector,
		dnsServer:    dnsSrv,
		clock:        clock,
		onProxyError: onProxyError,
		connRing:     make([]*ActiveConnectionInfo, 0, cfg.Budgets.MaxActiveConnRing),
	}
}

func (g *Gateway) UpdateState(routeRules []rules.RoutingRule, activePool pools.PoolConfig, candidates []storage.ProxyRecord) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.routeRules = append([]rules.RoutingRule(nil), routeRules...)
	g.activePool = activePool
	g.candidates = append([]storage.ProxyRecord(nil), candidates...)
}

func (g *Gateway) RecentConnections() []ActiveConnectionInfo {
	g.ringMu.Lock()
	defer g.ringMu.Unlock()
	out := make([]ActiveConnectionInfo, len(g.connRing))
	for i, c := range g.connRing {
		out[i] = *c
	}
	return out
}

// RouteAndDial evaluates routing rules, DNS resolution mode (Remote DNS vs Managed DNS),
// and establishes an upstream connection with pre-handshake failover.
// Strictly enforces INV-01 (block never dials), INV-02 (proxy-only never falls back to direct),
// and INV-07 (failover only before tunnel confirmation / payload transmission).
func (g *Gateway) RouteAndDial(ctx context.Context, targetHost, targetPort string, requireConnect bool) (net.Conn, *storage.ProxyRecord, []model.DecisionTrace, error) {
	g.mu.RLock()
	rRules := g.routeRules
	poolCfg := g.activePool
	cands := g.candidates
	strict := g.cfg.StrictProxyOnly
	allowDirect := g.cfg.AllowDirectFallback
	defResMode := g.cfg.DNSResolutionMode
	ipv6Pol := g.cfg.IPv6Policy
	capTTL := time.Duration(g.cfg.CapabilityTTLMinutes) * time.Minute
	g.mu.RUnlock()

	now := g.clock.Now()
	var traces []model.DecisionTrace

	matchedRoute, routeTrace := rules.EvaluateRoute(targetHost, rRules, defResMode, strict, now)
	traces = append(traces, routeTrace)

	// INV-01: Route 'block' NEVER dials or resolves the target!
	if matchedRoute.Action == "block" {
		return nil, nil, traces, ErrRouteBlocked
	}

	// Determine dial target host (Remote DNS passes original hostname to upstream; Managed DNS resolves via DNS server while preserving Host/SNI)
	connectHost := targetHost
	if matchedRoute.ResolutionMode == "managed_dns" && net.ParseIP(targetHost) == nil && g.dnsServer != nil {
		resolvedIP, dnsTrace, err := g.resolveManagedDNS(ctx, targetHost, ipv6Pol)
		traces = append(traces, dnsTrace)
		if err != nil {
			return nil, nil, traces, fmt.Errorf("managed_dns resolution failed: %w", err)
		}
		connectHost = resolvedIP.String()
	}

	// Explicit direct route (only if action == "direct" AND (!strict || allowDirect))
	if matchedRoute.Action == "direct" {
		if strict && !allowDirect {
			return nil, nil, traces, ErrNoHealthyProxyAvailable
		}
		d := net.Dialer{Timeout: 5 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(connectHost, targetPort))
		return conn, nil, traces, err
	}

	// Proxy or Pool route: attempt up to 3 candidates with pre-tunnel failover (INV-07)
	excluded := make(map[int]string)
	maxAttempts := 3
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req := pools.SelectionRequest{
			RequireConnect:   requireConnect,
			RequireRemoteDNS: matchedRoute.ResolutionMode == "remote_dns" && net.ParseIP(connectHost) == nil,
			CapabilityTTL:    capTTL,
			ExcludeProxyIDs:  excluded,
		}
		chosen, poolTrace, err := g.poolSelector.Select(poolCfg, cands, req)
		traces = append(traces, poolTrace)
		if err != nil {
			// INV-02: Never fall back to direct when pool has no candidates in proxy-only mode!
			return nil, nil, traces, fmt.Errorf("%w: %v", ErrNoHealthyProxyAvailable, err)
		}

		upConn, dialErr := g.dialViaProxy(ctx, *chosen, connectHost, targetPort, requireConnect)
		if dialErr == nil {
			return upConn, chosen, traces, nil
		}

		// Record failure before tunnel confirmation and try next candidate in pool
		excluded[chosen.ID] = dialErr.Error()
		if g.onProxyError != nil {
			g.onProxyError(chosen.ID, dialErr)
		}
	}

	return nil, nil, traces, ErrNoHealthyProxyAvailable
}

func (g *Gateway) resolveManagedDNS(ctx context.Context, host string, ipv6Policy string) (net.IP, model.DecisionTrace, error) {
	if ipv6Policy == "ipv4_only" || ipv6Policy == "prefer_ipv4" || ipv6Policy == "" {
		ips, rcode, trace, err := g.dnsServer.Resolve(ctx, host, dns.TypeA)
		if err == nil && rcode == dns.RcodeSuccess && len(ips) > 0 {
			return ips[0], trace, nil
		}
		if ipv6Policy == "ipv4_only" {
			if err != nil {
				return nil, trace, err
			}
			return nil, trace, fmt.Errorf("no IPv4 A record found (rcode=%d)", rcode)
		}
	}
	ips6, rcode6, trace6, err6 := g.dnsServer.Resolve(ctx, host, dns.TypeAAAA)
	if err6 == nil && rcode6 == dns.RcodeSuccess && len(ips6) > 0 {
		return ips6[0], trace6, nil
	}
	return nil, trace6, fmt.Errorf("managed DNS found no usable A/AAAA record (err=%v, rcode=%d)", err6, rcode6)
}

func (g *Gateway) dialViaProxy(ctx context.Context, p storage.ProxyRecord, connectHost, targetPort string, establishTunnel bool) (net.Conn, error) {
	d := net.Dialer{Timeout: 4 * time.Second}
	proxyAddr := net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}

	var creds model.Credentials
	if p.HasAuth && g.credStore != nil {
		creds, _ = g.credStore.Get(p.DedupKey)
	}

	if p.Protocol == "socks5" {
		if err := negotiateSOCKS5Upstream(conn, creds, connectHost, targetPort); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	}

	// HTTP upstream proxy
	if establishTunnel {
		targetAddr := net.JoinHostPort(connectHost, targetPort)
		var b strings.Builder
		fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)
		if creds.Username != "" || creds.Password != "" {
			authB64 := base64.StdEncoding.EncodeToString([]byte(creds.Username + ":" + creds.Password))
			fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n", authB64)
		}
		b.WriteString("\r\n")
		if _, err := io.WriteString(conn, b.String()); err != nil {
			_ = conn.Close()
			return nil, err
		}
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			_ = conn.Close()
			return nil, fmt.Errorf("upstream CONNECT status %d", resp.StatusCode)
		}
	}
	return conn, nil
}

// ServeHTTPProxy handles both HTTP CONNECT tunnels and plain HTTP forward proxy requests on loopback.
// Enforces INV-07 (never replays non-idempotent requests after payload send) and strips Proxy-Authorization headers.
func (g *Gateway) ServeHTTPProxy(w http.ResponseWriter, r *http.Request) {
	if int(g.activeCount.Add(1)) > g.cfg.Budgets.MaxGatewayConns {
		g.activeCount.Add(-1)
		http.Error(w, "Max gateway connections exceeded", http.StatusServiceUnavailable)
		return
	}
	defer g.activeCount.Add(-1)

	if r.Method == http.MethodConnect {
		g.handleHTTPConnect(w, r)
		return
	}
	g.handleHTTPForward(w, r)
}

func (g *Gateway) handleHTTPConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
		port = "443"
	}
	upConn, chosen, traces, err := g.RouteAndDial(r.Context(), host, port, true)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, ErrRouteBlocked) {
			status = http.StatusForbidden
		}
		http.Error(w, err.Error(), status)
		return
	}
	defer upConn.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	// Tunnel is confirmed ONLY here. Once 200 Connection Established is sent to client,
	// no replay or hidden reconnection is ever attempted (INV-07).
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	routedVia := "direct"
	if chosen != nil {
		routedVia = fmt.Sprintf("%s://%s:%d", chosen.Protocol, chosen.Host, chosen.Port)
	}
	info := g.registerConnection("http_connect", host+":"+port, routedVia, traces)
	g.relayBidirectional(clientConn, upConn, info)
}

func (g *Gateway) handleHTTPForward(w http.ResponseWriter, r *http.Request) {
	// Never allow client Proxy-Authorization or Proxy-Connection headers to leak to origin servers!
	r.Header.Del("Proxy-Authorization")
	r.Header.Del("Proxy-Connection")

	host := r.URL.Hostname()
	port := r.URL.Port()
	if port == "" {
		port = "80"
	}

	// Establish tunnel/connection to target via selected proxy (or SOCKS5)
	upConn, chosen, traces, err := g.RouteAndDial(r.Context(), host, port, true)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, ErrRouteBlocked) {
			status = http.StatusForbidden
		}
		http.Error(w, err.Error(), status)
		return
	}
	defer upConn.Close()

	routedVia := "direct"
	if chosen != nil {
		routedVia = fmt.Sprintf("%s://%s:%d", chosen.Protocol, chosen.Host, chosen.Port)
	}
	info := g.registerConnection("http_forward", host+":"+port, routedVia, traces)
	defer g.closeConnectionInfo(info)

	// INV-07: Once we begin writing the HTTP request to upConn, we NEVER retry/replay on another proxy!
	r.RequestURI = ""
	if err := r.Write(upConn); err != nil {
		http.Error(w, "upstream write error", http.StatusBadGateway)
		return
	}
	br := bufio.NewReader(upConn)
	resp, err := http.ReadResponse(br, r)
	if err != nil {
		http.Error(w, "upstream read error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	n, _ := io.Copy(w, resp.Body)
	atomic.AddInt64(&info.BytesDown, n)
}

func (g *Gateway) registerConnection(proto, target, routedVia string, traces []model.DecisionTrace) *ActiveConnectionInfo {
	displayTarget := "[redacted-host]"
	if g.cfg.LogDomains {
		displayTarget = target
	}
	info := &ActiveConnectionInfo{
		ID:             g.connSeq.Add(1),
		Protocol:       proto,
		Target:         displayTarget,
		RoutedVia:      routedVia,
		StartedAt:      g.clock.Now(),
		Active:         true,
		DecisionTraces: traces,
	}
	g.ringMu.Lock()
	maxRing := g.cfg.Budgets.MaxActiveConnRing
	if maxRing <= 0 {
		maxRing = 200
	}
	if len(g.connRing) >= maxRing {
		copy(g.connRing, g.connRing[1:])
		g.connRing[len(g.connRing)-1] = info
	} else {
		g.connRing = append(g.connRing, info)
	}
	g.ringMu.Unlock()
	return info
}

func (g *Gateway) closeConnectionInfo(info *ActiveConnectionInfo) {
	now := g.clock.Now()
	g.ringMu.Lock()
	info.Active = false
	info.ClosedAt = &now
	g.ringMu.Unlock()
}

func (g *Gateway) relayBidirectional(clientConn, upConn net.Conn, info *ActiveConnectionInfo) {
	defer g.closeConnectionInfo(info)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, _ := io.Copy(upConn, clientConn)
		atomic.AddInt64(&info.BytesUp, n)
		if tc, ok := upConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(clientConn, upConn)
		atomic.AddInt64(&info.BytesDown, n)
		if tc, ok := clientConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()
}

func negotiateSOCKS5Upstream(conn net.Conn, creds model.Credentials, host, portStr string) error {
	hasAuth := creds.Username != "" || creds.Password != ""
	if hasAuth {
		_, _ = conn.Write([]byte{0x05, 0x02, 0x00, 0x02})
	} else {
		_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
	}
	m := make([]byte, 2)
	if _, err := io.ReadFull(conn, m); err != nil {
		return err
	}
	if m[1] == 0x02 {
		buf := append([]byte{0x01, byte(len(creds.Username))}, []byte(creds.Username)...)
		buf = append(buf, byte(len(creds.Password)))
		buf = append(buf, []byte(creds.Password)...)
		if _, err := conn.Write(buf); err != nil {
			return err
		}
		ar := make([]byte, 2)
		if _, err := io.ReadFull(conn, ar); err != nil || ar[1] != 0x00 {
			return errors.New("SOCKS5 upstream auth failed")
		}
	} else if m[1] != 0x00 {
		return errors.New("SOCKS5 upstream auth method rejected")
	}

	port, _ := strconv.Atoi(portStr)
	req := []byte{0x05, 0x01, 0x00}
	if ip4 := net.ParseIP(host).To4(); ip4 != nil {
		req = append(req, 0x01)
		req = append(req, ip4...)
	} else {
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port&0xFF))
	if _, err := conn.Write(req); err != nil {
		return err
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil || hdr[1] != 0x00 {
		return errors.New("SOCKS5 upstream connect failed")
	}
	discard := 6
	if hdr[3] == 0x03 {
		l := make([]byte, 1)
		_, _ = io.ReadFull(conn, l)
		discard = int(l[0]) + 2
	} else if hdr[3] == 0x04 {
		discard = 18
	}
	_, err := io.ReadFull(conn, make([]byte, discard))
	return err
}
