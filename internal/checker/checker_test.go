package checker

import (
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/proxydesk/proxydesk/internal/config"
	"github.com/proxydesk/proxydesk/internal/model"
	"github.com/proxydesk/proxydesk/internal/storage"
)

func TestCheckerRejectsTarpitFakeTLSAndRespectsCancellation(t *testing.T) {
	// 1. Start local HTTPS target server with its own self-signed certificate
	targetTLS := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ip=203.0.113.99\n"))
	}))
	defer targetTLS.Close()

	// Build RootCA pool trusting ONLY targetTLS's certificate
	trustedPool := x509.NewCertPool()
	trustedPool.AddCert(targetTLS.Certificate())

	// 2. Start a working HTTP CONNECT proxy forwarding raw TCP to targetTLS
	goodProxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer goodProxyLn.Close()
	go func() {
		for {
			c, err := goodProxyLn.Accept()
			if err != nil {
				return
			}
			go func(clientConn net.Conn) {
				defer clientConn.Close()
				buf := make([]byte, 1024)
				n, err := clientConn.Read(buf)
				if err != nil || n == 0 {
					return
				}
				u, _ := url.Parse(targetTLS.URL)
				upConn, err := net.Dial("tcp", u.Host)
				if err != nil {
					return
				}
				defer upConn.Close()
				_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
				go func() { _, _ = io.Copy(upConn, clientConn) }()
				_, _ = io.Copy(clientConn, upConn)
			}(c)
		}
	}()

	// 3. Start a tarpit proxy that accepts TCP connections and hangs forever (INV-03 test)
	tarpitLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tarpitLn.Close()
	go func() {
		for {
			c, err := tarpitLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				time.Sleep(10 * time.Second)
			}(c)
		}
	}()

	// 4. Start a MITM HTTPS server pretending to be the target with an untrusted certificate
	mitmTLS := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ip=198.51.100.66\n"))
	}))
	defer mitmTLS.Close()
	mitmProxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer mitmProxyLn.Close()
	go func() {
		for {
			c, err := mitmProxyLn.Accept()
			if err != nil {
				return
			}
			go func(clientConn net.Conn) {
				defer clientConn.Close()
				buf := make([]byte, 1024)
				_, _ = clientConn.Read(buf)
				u, _ := url.Parse(mitmTLS.URL)
				upConn, err := net.Dial("tcp", u.Host)
				if err != nil {
					return
				}
				defer upConn.Close()
				_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
				go func() { _, _ = io.Copy(upConn, clientConn) }()
				_, _ = io.Copy(clientConn, upConn)
			}(c)
		}
	}()

	cfg := config.DefaultConfig()
	cfg.Budgets.CheckConnectTimeoutMs = 300
	cfg.Budgets.CheckHandshakeTimeoutMs = 300
	cfg.Budgets.CheckTotalTimeoutMs = 600
	cfg.CheckTargets = []config.CheckTargetConfig{
		{Name: "Local TLS Target", URL: targetTLS.URL, ExpectStatus: 200, ExtractsExitIP: true, Enabled: true},
	}

	chk := NewChecker(&cfg, model.NewCredentialStore(), model.RealClock{}, trustedPool)

	// Test A: Working CONNECT proxy succeeds and extracts exit_ip
	_, goodPortStr, _ := net.SplitHostPort(goodProxyLn.Addr().String())
	goodPort, _ := strconv.Atoi(goodPortStr)
	resGood := chk.CheckProxyCycle(context.Background(), storage.ProxyRecord{
		ID: 1, Protocol: "http", Host: "127.0.0.1", Port: goodPort, Capabilities: model.DefaultCapabilities(),
	})
	if resGood.Outcome != OutcomeSuccess || resGood.ExitIP != "203.0.113.99" {
		t.Fatalf("expected working proxy to succeed with exit_ip=203.0.113.99, got %+v", resGood)
	}

	// Test B: MITM proxy with untrusted TLS certificate is strictly rejected at 'tls' stage
	_, mitmPortStr, _ := net.SplitHostPort(mitmProxyLn.Addr().String())
	mitmPort, _ := strconv.Atoi(mitmPortStr)
	resMITM := chk.CheckProxyCycle(context.Background(), storage.ProxyRecord{
		ID: 2, Protocol: "http", Host: "127.0.0.1", Port: mitmPort, Capabilities: model.DefaultCapabilities(),
	})
	if resMITM.Outcome != OutcomeFailure || resMITM.TargetResults[0].StageFailed != "tls" {
		t.Fatalf("expected MITM TLS proxy to fail at 'tls' stage, got %+v", resMITM)
	}

	// Test C: Tarpit proxy is cancelled mid-flight and frees resources immediately (INV-03)
	_, tarpitPortStr, _ := net.SplitHostPort(tarpitLn.Addr().String())
	tarpitPort, _ := strconv.Atoi(tarpitPortStr)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	tStart := time.Now()
	resCancel := chk.CheckProxyCycle(ctx, storage.ProxyRecord{
		ID: 3, Protocol: "http", Host: "127.0.0.1", Port: tarpitPort, Capabilities: model.DefaultCapabilities(),
	})
	if resCancel.Outcome != OutcomeCancelled {
		t.Fatalf("expected OutcomeCancelled, got %s", resCancel.Outcome)
	}
	if time.Since(tStart) > 250*time.Millisecond {
		t.Fatalf("cancellation took too long: %v", time.Since(tStart))
	}
}
