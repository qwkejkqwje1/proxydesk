package gateway

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/proxydesk/proxydesk/internal/config"
	"github.com/proxydesk/proxydesk/internal/model"
	"github.com/proxydesk/proxydesk/internal/pools"
	"github.com/proxydesk/proxydesk/internal/rules"
	"github.com/proxydesk/proxydesk/internal/storage"
)

func TestInvariant_BlockRouteNeverDialsAndProxyOnlyNeverFallsBackToDirect(t *testing.T) {
	t0 := time.Date(2026, 10, 13, 17, 0, 0, 0, time.UTC)
	clk := model.NewFakeClock(t0)
	cfg := config.DefaultConfig()
	cfg.StrictProxyOnly = true
	cfg.AllowDirectFallback = false

	var originConns atomic.Int32
	originLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer originLn.Close()
	go func() {
		for {
			c, err := originLn.Accept()
			if err != nil {
				return
			}
			originConns.Add(1)
			_ = c.Close()
		}
	}()

	_, originPort, _ := net.SplitHostPort(originLn.Addr().String())
	sel := pools.NewSelector(clk, 1)
	gw := NewGateway(&cfg, model.NewCredentialStore(), sel, nil, clk, nil)

	// 1. INV-01: 'block' rule must return ErrRouteBlocked and originConns must remain 0
	gw.UpdateState(
		[]rules.RoutingRule{{ID: 1, Priority: 1, Enabled: true, MatchType: rules.MatchExact, Pattern: "127.0.0.1", Action: "block"}},
		pools.PoolConfig{ID: 1, Name: "Default", Kind: "reliable", Strategy: "failover"},
		nil,
	)
	_, _, _, errBlock := gw.RouteAndDial(context.Background(), "127.0.0.1", originPort, true)
	if !errors.Is(errBlock, ErrRouteBlocked) {
		t.Fatalf("expected ErrRouteBlocked, got %v", errBlock)
	}
	if originConns.Load() != 0 {
		t.Fatalf("INV-01 violated: block route dialed target (%d connections)!", originConns.Load())
	}

	// 2. INV-02: 'pool' route with no healthy proxies must return ErrNoHealthyProxyAvailable and NEVER dial origin directly
	gw.UpdateState(
		[]rules.RoutingRule{{ID: 2, Priority: 1, Enabled: true, MatchType: rules.MatchAll, Pattern: "*", Action: "pool"}},
		pools.PoolConfig{ID: 1, Name: "Default", Kind: "reliable", Strategy: "failover"},
		[]storage.ProxyRecord{},
	)
	_, _, _, errPool := gw.RouteAndDial(context.Background(), "127.0.0.1", originPort, true)
	if !errors.Is(errPool, ErrNoHealthyProxyAvailable) {
		t.Fatalf("expected ErrNoHealthyProxyAvailable, got %v", errPool)
	}
	if originConns.Load() != 0 {
		t.Fatalf("INV-02 violated: proxy-only mode fell back to direct connection!")
	}
}

func TestGatewayPreservesBufferedBytesAndClearsHandshakeDeadline(t *testing.T) {
	t0 := time.Date(2026, 10, 13, 17, 30, 0, 0, time.UTC)
	clk := model.NewFakeClock(t0)
	cfg := config.DefaultConfig()
	cfg.Budgets.CheckHandshakeTimeoutMs = 150 // Short 150ms handshake deadline

	// Upstream proxy sends "HTTP/1.1 200 Connection Established\r\n\r\n" AND immediately pipelines "EARLY_BANNER\n"
	// in the exact same write so bufio.Reader buffers "EARLY_BANNER\n"!
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()
	go func() {
		for {
			c, err := upLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				br := bufio.NewReader(conn)
				_, _ = http.ReadRequest(br)
				_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\nEARLY_BANNER\n")
				// Sleep 250ms (> 150ms handshake deadline) to verify handshake deadline was cleared!
				time.Sleep(250 * time.Millisecond)
				_, _ = io.WriteString(conn, "LATE_PAYLOAD\n")
			}(c)
		}
	}()

	_, upPortStr, _ := net.SplitHostPort(upLn.Addr().String())
	upPort, _ := strconv.Atoi(upPortStr)
	confirmed := model.CapabilityRecord{State: model.CapabilityConfirmed, VerifiedAt: &t0}

	sel := pools.NewSelector(clk, 1)
	gw := NewGateway(&cfg, model.NewCredentialStore(), sel, nil, clk, nil)
	gw.UpdateState(
		nil,
		pools.PoolConfig{ID: 1, Name: "Pool", Kind: "reliable", Strategy: "failover", RequireConnect: true},
		[]storage.ProxyRecord{
			{ID: 1, Protocol: "http", Host: "127.0.0.1", Port: upPort, Status: model.StatusHealthy, Score: 90.0, Capabilities: model.ProxyCapabilities{Connect: confirmed}},
		},
	)

	conn, _, _, err := gw.RouteAndDial(context.Background(), "example.com", "443", true)
	if err != nil {
		t.Fatalf("RouteAndDial failed: %v", err)
	}
	defer conn.Close()

	allBytes, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("reading tunnel stream after handshake deadline window failed: %v", err)
	}
	got := string(allBytes)
	if !strings.HasPrefix(got, "EARLY_BANNER\n") || !strings.HasSuffix(got, "LATE_PAYLOAD\n") {
		t.Fatalf("expected both buffered EARLY_BANNER and delayed LATE_PAYLOAD, got %q", got)
	}
}
