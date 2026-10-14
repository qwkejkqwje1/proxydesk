package gateway

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
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
	ErrCorruptSOCKS5Packet     = errors.New("malformed or unsupported SOCKS5 packet")
)

// bufferedConn wraps a net.Conn and a bufio.Reader so that any bytes already buffered
// during HTTP CONNECT or Hijack header parsing are never lost when relaying traffic.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func wrapBufferedConn(c net.Conn, br *bufio.Reader) net.Conn {
	if br == nil || br.Buffered() == 0 {
		return c
	}
	return &bufferedConn{Conn: c, r: br}
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	if b.r != nil && b.r.Buffered() > 0 {
		return b.r.Read(p)
	}
	b.r = nil
	return b.Conn.Read(p)
}

func (b *bufferedConn) CloseWrite() error {
	if tc, ok := b.Conn.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	return nil
}

type ActiveConnectionInfo struct {
	ID             int64                 `json:"id"`
	Protocol       string                `json:"protocol"` // "http_connect", "http_forward", "socks5"
	Target         string                `json:"target"`
	RoutedVia      string                `json:"routed_via"`
	StartedAt      time.Time             `json:"started_at"`
	ClosedAt       *time.Time            `json:"closed_at,omitempty"`
	BytesUp        int64                 `json:"bytes_up"`
	BytesDown      int64                 `json:"bytes_down"`
	Active         bool                  `json:"active"`
	DecisionTraces []model.DecisionTrace `json:"decision_traces"`
}

// connEntry is the internal race-free representation stored in the ring buffer.
type connEntry struct {
	id             int64
	protocol       string
	target         string
	routedVia      string
	startedAt      time.Time
	closedAt       *time.Time
	bytesUp        atomic.Int64
	bytesDown      atomic.Int64
	active         bool
	decisionTraces []model.DecisionTrace
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

	connSeq     atomic.Int64
	activeCount atomic.Int32
	ringMu      sync.Mutex
	connRing    []*connEntry
	openSockets map[int64][2]net.Conn
	connWG      sync.WaitGroup
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
		connRing:     make([]*connEntry, 0, cfg.Budgets.MaxActiveConnRing),
		openSockets:  make(map[int64][2]net.Conn),
	}
}

func (g *Gateway) UpdateState(routeRules []rules.RoutingRule, activePool pools.PoolConfig, candidates []storage.ProxyRecord) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.routeRules = append([]rules.RoutingRule(nil), routeRules...)
	g.activePool = activePool
	g.candidates = append([]storage.ProxyRecord(nil), candidates...)
}

// RecentConnections returns a race-free snapshot of active and recent connections.
func (g *Gateway) RecentConnections() []ActiveConnectionInfo {
	g.ringMu.Lock()
	defer g.ringMu.Unlock()
	out := make([]ActiveConnectionInfo, len(g.connRing))
	for i, c := range g.connRing {
		var closedCopy *time.Time
		if c.closedAt != nil {
			t := *c.closedAt
			closedCopy = &t
		}
		out[i] = ActiveConnectionInfo{
			ID:             c.id,
			Protocol:       c.protocol,
			Target:         c.target,
			RoutedVia:      c.routedVia,
			StartedAt:      c.startedAt,
			ClosedAt:       closedCopy,
			BytesUp:        c.bytesUp.Load(),
			BytesDown:      c.bytesDown.Load(),
			Active:         c.active,
			DecisionTraces: append([]model.DecisionTrace(nil), c.decisionTraces...),
		}
	}
	return out
}

// CloseAllActive forcefully closes all active hijacked HTTP CONNECT and SOCKS5 connections
// and waits for relay goroutines to exit cleanly (STABILIZATION-01 Section 2 & 4).
func (g *Gateway) CloseAllActive() {
	g.ringMu.Lock()
	sockets := make([][2]net.Conn, 0, len(g.openSockets))
	for _, pair := range g.openSockets {
		sockets = append(sockets, pair)
	}
	g.ringMu.Unlock()

	for _, pair := range sockets {
		if pair[0] != nil {
			_ = pair[0].Close()
		}
		if pair[1] != nil {
			_ = pair[1].Close()
		}
	}
	g.connWG.Wait()
}

// RouteAndDial evaluates routing rules, DNS resolution mode (Remote DNS vs Managed DNS),
// and establishes an upstream connection with bounded pre-handshake failover.
func (g *Gateway) RouteAndDial(parentCtx context.Context, targetHost, targetPort string, requireConnect bool) (net.Conn, *storage.ProxyRecord, []model.DecisionTrace, error) {
	g.mu.RLock()
	rRules := g.routeRules
	poolCfg := g.activePool
	cands := g.candidates
	strict := g.cfg.StrictProxyOnly
	allowDirect := g.cfg.AllowDirectFallback
	defResMode := g.cfg.DNSResolutionMode
	ipv6Pol := g.cfg.IPv6Policy
	capTTL := time.Duration(g.cfg.CapabilityTTLMinutes) * time.Minute
	totalTimeout := time.Duration(g.cfg.Budgets.CheckTotalTimeoutMs) * time.Millisecond
	g.mu.RUnlock()

	if totalTimeout <= 0 {
		totalTimeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(parentCtx, totalTimeout)
	defer cancel()

	now := g.clock.Now()
	var traces []model.DecisionTrace

	matchedRoute, routeTrace := rules.EvaluateRoute(targetHost, rRules, defResMode, strict, now)
	traces = append(traces, routeTrace)

	// INV-01: Route 'block' NEVER dials or resolves the target!
	if matchedRoute.Action == "block" {
		return nil, nil, traces, ErrRouteBlocked
	}

	connectHost := targetHost
	if matchedRoute.ResolutionMode == "managed_dns" && net.ParseIP(targetHost) == nil && g.dnsServer != nil {
		resolvedIP, dnsTrace, err := g.resolveManagedDNS(ctx, targetHost, ipv6Pol)
		traces = append(traces, dnsTrace)
		if err != nil {
			return nil, nil, traces, fmt.Errorf("managed_dns resolution failed: %w", err)
		}
		connectHost = resolvedIP.String()
	}

	if matchedRoute.Action == "direct" {
		if strict && !allowDirect {
			return nil, nil, traces, ErrNoHealthyProxyAvailable
		}
		d := net.Dialer{Timeout: 4 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(connectHost, targetPort))
		return conn, nil, traces, err
	}

	// If rule targets a specific proxy ID ("proxy" action), filter candidates to that proxy
	effectiveCands := cands
	if matchedRoute.Action == "proxy" && matchedRoute.TargetProxyID != nil {
		var filtered []storage.ProxyRecord
		for _, c := range cands {
			if c.ID == *matchedRoute.TargetProxyID {
				filtered = append(filtered, c)
			}
		}
		effectiveCands = filtered
	}

	excluded := make(map[int]string)
	maxAttempts := 3
	if len(effectiveCands) > 0 && len(effectiveCands) < maxAttempts {
		maxAttempts = len(effectiveCands)
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if ctx.Err() != nil {
			return nil, nil, traces, ctx.Err()
		}
		req := pools.SelectionRequest{
			RequireConnect:   requireConnect,
			RequireRemoteDNS: matchedRoute.ResolutionMode == "remote_dns" && net.ParseIP(connectHost) == nil,
			CapabilityTTL:    capTTL,
			ExcludeProxyIDs:  excluded,
		}
		chosen, poolTrace, err := g.poolSelector.Select(poolCfg, effectiveCands, req)
		traces = append(traces, poolTrace)
		if err != nil {
			return nil, nil, traces, fmt.Errorf("%w: %v", ErrNoHealthyProxyAvailable, err)
		}

		upConn, dialErr := g.dialViaProxy(ctx, *chosen, connectHost, targetPort, requireConnect)
		if dialErr == nil {
			return upConn, chosen, traces, nil
		}

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
	connTimeout := time.Duration(g.cfg.Budgets.CheckConnectTimeoutMs) * time.Millisecond
	if connTimeout <= 0 {
		connTimeout = 4 * time.Second
	}
	hsTimeout := time.Duration(g.cfg.Budgets.CheckHandshakeTimeoutMs) * time.Millisecond
	if hsTimeout <= 0 {
		hsTimeout = 4 * time.Second
	}

	d := net.Dialer{Timeout: connTimeout}
	proxyAddr := net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}

	// Ensure context cancellation during handshake immediately interrupts blocking I/O
	stopWatch := make(chan struct{})
	var watchClosed atomic.Bool
	closeWatch := func() {
		if watchClosed.CompareAndSwap(false, true) {
			close(stopWatch)
		}
	}
	defer closeWatch()

	go func() {
		select {
		case <-ctx.Done():
			if !watchClosed.Load() {
				_ = conn.SetDeadline(time.Now())
			}
		case <-stopWatch:
		}
	}()

	_ = conn.SetDeadline(time.Now().Add(hsTimeout))

	var creds model.Credentials
	if p.HasAuth && g.credStore != nil {
		creds, _ = g.credStore.Get(p.DedupKey)
	}

	if p.Protocol == "socks5" {
		if err := negotiateSOCKS5Upstream(conn, creds, connectHost, targetPort); err != nil {
			_ = conn.Close()
			return nil, err
		}
		// Handshake succeeded: stop cancellation watcher and clear handshake deadline!
		closeWatch()
		_ = conn.SetDeadline(time.Time{})
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
		closeWatch()
		_ = conn.SetDeadline(time.Time{})
		// Preserve any bytes already buffered in br after the CONNECT 200 OK headers!
		return wrapBufferedConn(conn, br), nil
	}

	closeWatch()
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// ServeHTTPProxy handles both HTTP CONNECT tunnels and plain HTTP forward proxy requests on loopback.
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
	rawClientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		return
	}
	defer rawClientConn.Close()

	_ = rawClientConn.SetDeadline(time.Time{})
	_, _ = rawClientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Wrap rawClientConn with clientBuf.Reader so any pipelined bytes after CONNECT are never lost!
	var clientConn net.Conn = rawClientConn
	if clientBuf != nil {
		clientConn = wrapBufferedConn(rawClientConn, clientBuf.Reader)
	}

	routedVia := "direct"
	if chosen != nil {
		routedVia = fmt.Sprintf("%s://%s:%d", chosen.Protocol, chosen.Host, chosen.Port)
	}
	entry := g.registerConnection("http_connect", host+":"+port, routedVia, traces, clientConn, upConn)
	g.relayBidirectional(clientConn, upConn, entry)
}

func (g *Gateway) handleHTTPForward(w http.ResponseWriter, r *http.Request) {
	r.Header.Del("Proxy-Authorization")
	r.Header.Del("Proxy-Connection")

	host := r.URL.Hostname()
	port := r.URL.Port()
	if port == "" {
		port = "80"
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

	routedVia := "direct"
	if chosen != nil {
		routedVia = fmt.Sprintf("%s://%s:%d", chosen.Protocol, chosen.Host, chosen.Port)
	}
	entry := g.registerConnection("http_forward", host+":"+port, routedVia, traces, nil, upConn)
	defer g.closeConnectionEntry(entry)

	// INV-07: Never replay request once writing to upConn begins
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
	entry.bytesDown.Add(n)
}

// ServeSOCKS5 runs the local SOCKS5 listener on loopback (STABILIZATION-01 Section 2, 4, 6).
func (g *Gateway) ServeSOCKS5(ctx context.Context, ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			continue
		}
		go g.handleSOCKS5Client(ctx, conn)
	}
}

func (g *Gateway) handleSOCKS5Client(parentCtx context.Context, clientConn net.Conn) {
	defer clientConn.Close()
	if int(g.activeCount.Add(1)) > g.cfg.Budgets.MaxGatewayConns {
		g.activeCount.Add(-1)
		return
	}
	defer g.activeCount.Add(-1)

	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(clientConn)

	// 1. Read SOCKS5 greeting: VER, NMETHODS, METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil || hdr[0] != 0x05 || hdr[1] == 0 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	supportsNoAuth := false
	for _, m := range methods {
		if m == 0x00 {
			supportsNoAuth = true
			break
		}
	}
	if !supportsNoAuth {
		_, _ = clientConn.Write([]byte{0x05, 0xFF})
		return
	}
	if _, err := clientConn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 2. Read SOCKS5 request: VER(5), CMD(1=CONNECT), RSV(0), ATYP(1=IPv4, 3=Domain, 4=IPv6), DST.ADDR, DST.PORT
	reqHdr := make([]byte, 4)
	if _, err := io.ReadFull(br, reqHdr); err != nil || reqHdr[0] != 0x05 {
		return
	}
	if reqHdr[1] != 0x01 {
		// Reject BIND (0x02) or UDP ASSOCIATE (0x03) with Command Not Supported (0x07), never direct fallback!
		_, _ = clientConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var targetHost string
	switch reqHdr[3] {
	case 0x01: // IPv4
		ip4 := make([]byte, 4)
		if _, err := io.ReadFull(br, ip4); err != nil {
			return
		}
		targetHost = net.IP(ip4).String()
	case 0x03: // Domain
		domLenBuf := make([]byte, 1)
		if _, err := io.ReadFull(br, domLenBuf); err != nil || domLenBuf[0] == 0 {
			return
		}
		domBytes := make([]byte, int(domLenBuf[0]))
		if _, err := io.ReadFull(br, domBytes); err != nil {
			return
		}
		targetHost = string(domBytes)
	case 0x04: // IPv6
		ip6 := make([]byte, 16)
		if _, err := io.ReadFull(br, ip6); err != nil {
			return
		}
		targetHost = net.IP(ip6).String()
	default:
		_, _ = clientConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(br, portBuf); err != nil {
		return
	}
	portNum := int(binary.BigEndian.Uint16(portBuf))
	if portNum < 1 || portNum > 65535 {
		return
	}
	targetPort := strconv.Itoa(portNum)

	upConn, chosen, traces, err := g.RouteAndDial(parentCtx, targetHost, targetPort, true)
	if err != nil {
		rep := byte(0x04) // Host unreachable
		if errors.Is(err, ErrRouteBlocked) {
			rep = 0x02 // Connection not allowed by ruleset (INV-01)
		}
		_, _ = clientConn.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upConn.Close()

	// Clear client handshake deadline and send SOCKS5 success reply
	_ = clientConn.SetDeadline(time.Time{})
	if _, err := clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	wrappedClient := wrapBufferedConn(clientConn, br)
	routedVia := "direct"
	if chosen != nil {
		routedVia = fmt.Sprintf("%s://%s:%d", chosen.Protocol, chosen.Host, chosen.Port)
	}
	entry := g.registerConnection("socks5", net.JoinHostPort(targetHost, targetPort), routedVia, traces, wrappedClient, upConn)
	g.relayBidirectional(wrappedClient, upConn, entry)
}

func (g *Gateway) registerConnection(proto, target, routedVia string, traces []model.DecisionTrace, clientConn, upConn net.Conn) *connEntry {
	displayTarget := "[redacted-host]"
	if g.cfg.LogDomains {
		displayTarget = target
	}
	id := g.connSeq.Add(1)
	entry := &connEntry{
		id:             id,
		protocol:       proto,
		target:         displayTarget,
		routedVia:      routedVia,
		startedAt:      g.clock.Now(),
		active:         true,
		decisionTraces: traces,
	}
	g.ringMu.Lock()
	maxRing := g.cfg.Budgets.MaxActiveConnRing
	if maxRing <= 0 {
		maxRing = 200
	}
	if len(g.connRing) >= maxRing {
		copy(g.connRing, g.connRing[1:])
		g.connRing[len(g.connRing)-1] = entry
	} else {
		g.connRing = append(g.connRing, entry)
	}
	if clientConn != nil || upConn != nil {
		g.openSockets[id] = [2]net.Conn{clientConn, upConn}
	}
	g.ringMu.Unlock()
	return entry
}

func (g *Gateway) closeConnectionEntry(entry *connEntry) {
	now := g.clock.Now()
	g.ringMu.Lock()
	entry.active = false
	entry.closedAt = &now
	delete(g.openSockets, entry.id)
	g.ringMu.Unlock()
}

func (g *Gateway) relayBidirectional(clientConn, upConn net.Conn, entry *connEntry) {
	g.connWG.Add(1)
	defer g.connWG.Done()
	defer g.closeConnectionEntry(entry)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, _ := io.Copy(upConn, clientConn)
		entry.bytesUp.Add(n)
		if cw, ok := upConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(clientConn, upConn)
		entry.bytesDown.Add(n)
		if cw, ok := clientConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	wg.Wait()
}

// negotiateSOCKS5Upstream performs an RFC 1928 / RFC 1929 SOCKS5 client handshake with full validation
// of versions, auth methods, IPv4/Domain/IPv6 ATYP, and field lengths.
func negotiateSOCKS5Upstream(conn net.Conn, creds model.Credentials, host, portStr string) error {
	hasAuth := creds.Username != "" || creds.Password != ""
	if hasAuth {
		if len(creds.Username) > 255 || len(creds.Password) > 255 {
			return fmt.Errorf("%w: credentials exceed 255 bytes", ErrCorruptSOCKS5Packet)
		}
		if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
			return err
		}
	} else {
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			return err
		}
	}

	m := make([]byte, 2)
	if _, err := io.ReadFull(conn, m); err != nil {
		return err
	}
	if m[0] != 0x05 {
		return fmt.Errorf("%w: invalid SOCKS5 version %d", ErrCorruptSOCKS5Packet, m[0])
	}
	if m[1] == 0x02 {
		if !hasAuth {
			return errors.New("SOCKS5 upstream requires username/password auth, none provided")
		}
		buf := make([]byte, 0, 3+len(creds.Username)+len(creds.Password))
		buf = append(buf, 0x01, byte(len(creds.Username)))
		buf = append(buf, []byte(creds.Username)...)
		buf = append(buf, byte(len(creds.Password)))
		buf = append(buf, []byte(creds.Password)...)
		if _, err := conn.Write(buf); err != nil {
			return err
		}
		ar := make([]byte, 2)
		if _, err := io.ReadFull(conn, ar); err != nil {
			return err
		}
		if ar[0] != 0x01 || ar[1] != 0x00 {
			return errors.New("SOCKS5 upstream username/password authentication failed")
		}
	} else if m[1] != 0x00 {
		return fmt.Errorf("SOCKS5 upstream rejected authentication methods (code 0x%02x)", m[1])
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("%w: invalid target port %q", ErrCorruptSOCKS5Packet, portStr)
	}

	req := []byte{0x05, 0x01, 0x00}
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		req = append(req, 0x01)
		req = append(req, ip4...)
	} else if ip6 := ip.To16(); ip6 != nil {
		req = append(req, 0x04)
		req = append(req, ip6...)
	} else {
		if len(host) == 0 || len(host) > 255 {
			return fmt.Errorf("%w: domain length %d invalid", ErrCorruptSOCKS5Packet, len(host))
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port&0xFF))

	if _, err := conn.Write(req); err != nil {
		return err
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return err
	}
	if hdr[0] != 0x05 {
		return fmt.Errorf("%w: invalid SOCKS5 connect reply version %d", ErrCorruptSOCKS5Packet, hdr[0])
	}
	if hdr[1] != 0x00 {
		return fmt.Errorf("SOCKS5 upstream connect failed with reply code 0x%02x", hdr[1])
	}

	var discard int
	switch hdr[3] {
	case 0x01:
		discard = 4 + 2
	case 0x04:
		discard = 16 + 2
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return err
		}
		discard = int(l[0]) + 2
	default:
		return fmt.Errorf("%w: invalid SOCKS5 reply ATYP 0x%02x", ErrCorruptSOCKS5Packet, hdr[3])
	}
	_, err = io.ReadFull(conn, make([]byte, discard))
	return err
}
