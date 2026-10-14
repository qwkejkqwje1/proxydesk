package gateway

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
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
		[]storage.ProxyRecord{}, // Empty/dead pool
	)
	_, _, _, errPool := gw.RouteAndDial(context.Background(), "127.0.0.1", originPort, true)
	if !errors.Is(errPool, ErrNoHealthyProxyAvailable) {
		t.Fatalf("expected ErrNoHealthyProxyAvailable, got %v", errPool)
	}
	if originConns.Load() != 0 {
		t.Fatalf("INV-02 violated: proxy-only mode fell back to direct connection!")
	}
}

func TestGatewayFailoverSwitchesFromDeadPrimaryToBackupBeforeTunnelConfirmation(t *testing.T) {
	t0 := time.Date(2026, 10, 13, 17, 30, 0, 0, time.UTC)
	clk := model.NewFakeClock(t0)
	cfg := config.DefaultConfig()

	// Backup proxy accepts CONNECT and echoes "OK"
	backupLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backupLn.Close()
	go func() {
		for {
			c, err := backupLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 512)
				_, _ = conn.Read(buf)
				_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
			}(c)
		}
	}()
	_, backupPortStr, _ := net.SplitHostPort(backupLn.Addr().String())
	backupPort, _ := strconv.Atoi(backupPortStr)

	confirmed := model.CapabilityRecord{State: model.CapabilityConfirmed, VerifiedAt: &t0}
	var failedProxyID int
	sel := pools.NewSelector(clk, 1)
	gw := NewGateway(&cfg, model.NewCredentialStore(), sel, nil, clk, func(pid int, err error) {
		failedProxyID = pid
	})

	gw.UpdateState(
		nil,
		pools.PoolConfig{ID: 1, Name: "Failover Pool", Kind: "reliable", Strategy: "failover", RequireConnect: true},
		[]storage.ProxyRecord{
			// Primary (ID=10, Score=95) points to closed port 1 -> fails pre-handshake
			{ID: 10, Protocol: "http", Host: "127.0.0.1", Port: 1, Status: model.StatusHealthy, Score: 95.0, Capabilities: model.ProxyCapabilities{Connect: confirmed}},
			// Backup (ID=20, Score=80) points to working backupLn -> succeeds
			{ID: 20, Protocol: "http", Host: "127.0.0.1", Port: backupPort, Status: model.StatusHealthy, Score: 80.0, Capabilities: model.ProxyCapabilities{Connect: confirmed}},
		},
	)

	conn, chosen, traces, err := gw.RouteAndDial(context.Background(), "example.com", "443", true)
	if err != nil {
		t.Fatalf("expected failover to succeed via backup proxy, got err=%v", err)
	}
	defer conn.Close()
	if chosen == nil || chosen.ID != 20 || failedProxyID != 10 {
		t.Fatalf("expected chosen ID=20 and failedProxyID=10, got chosen=%+v failed=%d traces=%+v", chosen, failedProxyID, traces)
	}
}
