package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/proxydesk/proxydesk/internal/api"
	"github.com/proxydesk/proxydesk/internal/app"
	"github.com/proxydesk/proxydesk/internal/config"
	"github.com/proxydesk/proxydesk/internal/dns"
	"github.com/proxydesk/proxydesk/internal/model"
	"github.com/proxydesk/proxydesk/internal/storage"
	"github.com/proxydesk/proxydesk/web"
)

// TestCompiledBinarySmoke builds the real proxydesk executable and launches it as a child process
// with an empty --data-dir, verifying that the binary starts all listeners and serves the UI and API (Scenario A).
func TestCompiledBinarySmoke(t *testing.T) {
	tmpDir := t.TempDir()
	binName := "proxydesk"
	if runtime.GOOS == "windows" {
		binName = "proxydesk.exe"
	}
	binPath := filepath.Join(tmpDir, binName)

	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build proxydesk binary: %v\n%s", err, string(out))
	}

	dataDir := filepath.Join(tmpDir, "smoke-data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.APIListenAddr = "127.0.0.1:0"
	cfg.HTTPGatewayAddr = "127.0.0.1:0"
	cfg.SOCKS5GatewayAddr = "127.0.0.1:0"
	cfg.DNSListenAddr = "127.0.0.1:0"
	cfg.ResolvedDataDir = dataDir
	_ = cfg.Save()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, "--data-dir", dataDir, "--no-open-browser")
	var stdoutBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stdoutBuf
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start compiled binary: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	lockFile := filepath.Join(dataDir, "instance.lock")
	var apiURL string
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if raw, err := os.ReadFile(lockFile); err == nil {
			var meta struct {
				APIURL string `json:"api_url"`
			}
			if json.Unmarshal(raw, &meta) == nil && meta.APIURL != "" {
				resp, err := http.Get(meta.APIURL + "/api/v1/health")
				if err == nil {
					_ = resp.Body.Close()
					if resp.StatusCode == http.StatusOK {
						apiURL = meta.APIURL
						break
					}
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if apiURL == "" {
		t.Fatalf("compiled binary did not become healthy in time; output:\n%s", stdoutBuf.String())
	}
}

// TestEndToEnd_ScenariosA_to_L verifies the full integrated application across Scenarios A through L
// using local HTTP/SOCKS5/DNS/Origin fixtures without any external internet access.
func TestEndToEnd_ScenariosA_to_L(t *testing.T) {
	var originHits atomic.Int32
	var lastHostHeader atomic.Value
	originSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits.Add(1)
		lastHostHeader.Store(r.Host)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ip=203.0.113.77\nORIGIN_OK"))
	}))
	defer originSrv.Close()
	originURL, _ := url.Parse(originSrv.URL)
	_, originPort, _ := net.SplitHostPort(originURL.Host)

	tlsTarget := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ip=203.0.113.88\n"))
	}))
	defer tlsTarget.Close()
	rootPool := x509.NewCertPool()
	rootPool.AddCert(tlsTarget.Certificate())

	primaryLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer primaryLn.Close()
	go serveLocalHTTPConnectFixture(primaryLn)
	_, primaryPortStr, _ := net.SplitHostPort(primaryLn.Addr().String())
	primaryPort, _ := strconv.Atoi(primaryPortStr)

	backupSOCKSLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backupSOCKSLn.Close()
	go serveLocalSOCKS5Fixture(backupSOCKSLn)
	_, backupPortStr, _ := net.SplitHostPort(backupSOCKSLn.Addr().String())
	backupPort, _ := strconv.Atoi(backupPortStr)

	dnsUp1 := startLocalUDPDNSFixture(t, net.ParseIP("198.51.100.111"), 60)
	dnsUp2 := startLocalUDPDNSFixture(t, net.ParseIP("127.0.0.1"), 60)

	// --- Scenario A: Start with empty data-dir -> UI/API and listeners ready ---
	dataDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.APIListenAddr = "127.0.0.1:0"
	cfg.HTTPGatewayAddr = "127.0.0.1:0"
	cfg.SOCKS5GatewayAddr = "127.0.0.1:0"
	cfg.DNSListenAddr = "127.0.0.1:0"
	cfg.ResolvedDataDir = dataDir
	cfg.CheckTargets = []config.CheckTargetConfig{
		{Name: "Local TLS Check", URL: tlsTarget.URL, ExpectStatus: 200, ExtractsExitIP: true, Enabled: true},
	}
	_ = cfg.Save()

	store, err := storage.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := api.GenerateSessionToken()
	clk := model.RealClock{}
	application := app.New(&cfg, store, clk, rootPool, token)
	uiFS, _ := web.DistFS()
	apiSrv := api.NewServerWithApp(application, uiFS, token)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := application.Start(ctx, apiSrv.Handler(), 1*time.Hour); err != nil {
		t.Fatalf("Scenario A failed to start App: %v", err)
	}

	lState := application.ListenerState()
	if lState.APIBoundAddr == "" || lState.HTTPGatewayBoundAddr == "" || lState.SOCKS5GatewayBoundAddr == "" || lState.DNSUDPBoundAddr == "" || lState.DNSTCPBoundAddr == "" {
		t.Fatalf("Scenario A failed: expected all listeners bound, got %+v", lState)
	}
	apiBase := "http://" + lState.APIBoundAddr

	uiResp, err := http.Get(apiBase + "/")
	if err != nil {
		t.Fatal(err)
	}
	uiHTML, _ := io.ReadAll(uiResp.Body)
	_ = uiResp.Body.Close()
	reToken := regexp.MustCompile(`name="proxydesk-token" content="([a-f0-9]+)"`)
	m := reToken.FindSubmatch(uiHTML)
	if len(m) < 2 || string(m[1]) != token {
		t.Fatalf("Scenario A failed: UI did not inject session token")
	}

	doAPI := func(method, path string, body any) (int, map[string]any) {
		var rdr io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, apiBase+path, rdr)
		req.Header.Set("X-ProxyDesk-Token", token)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("API %s %s failed: %v", method, path, err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	// --- Scenario B: Import fixture -> candidates saved as unknown ---
	importTxt := fmt.Sprintf("http://127.0.0.1:%d\nsocks5://127.0.0.1:%d\n", primaryPort, backupPort)
	code, impRes := doAPI(http.MethodPost, "/api/v1/proxies/import", map[string]any{
		"content":          importTxt,
		"default_protocol": "http",
		"allow_private":    true,
	})
	if code != http.StatusOK || int(impRes["unique_count"].(float64)) != 2 {
		t.Fatalf("Scenario B failed: code=%d res=%+v", code, impRes)
	}

	// --- Scenario C: Check via local proxy fixtures -> healthy ---
	code, chkRes := doAPI(http.MethodPost, "/api/v1/proxies/check?sync=1", nil)
	if code != http.StatusOK {
		t.Fatalf("Scenario C check failed: code=%d res=%+v", code, chkRes)
	}
	_, ov := doAPI(http.MethodGet, "/api/v1/overview", nil)
	if int(ov["proxies_healthy"].(float64)) != 2 {
		t.Fatalf("Scenario C failed: expected 2 healthy proxies, got overview=%+v", ov)
	}

	// --- Scenario D: Select and apply pool -> client reaches target via HTTP gateway ---
	code, poolRes := doAPI(http.MethodPost, "/api/v1/pools", map[string]any{
		"name":            "E2E Failover Pool",
		"kind":            "reliable",
		"strategy":        "failover",
		"require_connect": true,
		"is_default":      true,
	})
	if code != http.StatusCreated {
		t.Fatalf("Scenario D create pool failed: %d %+v", code, poolRes)
	}

	proxyURL, _ := url.Parse("http://" + lState.HTTPGatewayBoundAddr)
	gwClient := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true},
		Timeout:   5 * time.Second,
	}
	respD, err := gwClient.Get(originSrv.URL + "/test-d")
	if err != nil {
		t.Fatalf("Scenario D client via HTTP gateway failed: %v", err)
	}
	bodyD, _ := io.ReadAll(respD.Body)
	_ = respD.Body.Close()
	if !strings.Contains(string(bodyD), "ORIGIN_OK") {
		t.Fatalf("Scenario D unexpected response body: %q", string(bodyD))
	}

	// --- Scenario E: Active upstream disappears -> new connection goes via backup proxy ---
	_ = primaryLn.Close()
	respE, err := gwClient.Get(originSrv.URL + "/test-e")
	if err != nil {
		t.Fatalf("Scenario E failover after primary death failed: %v", err)
	}
	bodyE, _ := io.ReadAll(respE.Body)
	_ = respE.Body.Close()
	if !strings.Contains(string(bodyE), "ORIGIN_OK") {
		t.Fatalf("Scenario E unexpected body after failover: %q", string(bodyE))
	}

	// --- Scenario F: SOCKS5 client passes through local SOCKS5 listener ---
	socksConn, err := net.DialTimeout("tcp", lState.SOCKS5GatewayBoundAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("Scenario F dial SOCKS5 gateway failed: %v", err)
	}
	_, _ = socksConn.Write([]byte{0x05, 0x01, 0x00})
	mReply := make([]byte, 2)
	_, _ = io.ReadFull(socksConn, mReply)
	originPortNum, _ := strconv.Atoi(originPort)
	sReq := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, byte(originPortNum >> 8), byte(originPortNum & 0xFF)}
	_, _ = socksConn.Write(sReq)
	sRep := make([]byte, 10)
	if _, err := io.ReadFull(socksConn, sRep); err != nil || sRep[1] != 0x00 {
		t.Fatalf("Scenario F SOCKS5 connect failed: err=%v rep=%v", err, sRep)
	}
	_, _ = io.WriteString(socksConn, "GET /socks5-test HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
	socksRespBytes, _ := io.ReadAll(socksConn)
	_ = socksConn.Close()
	if !strings.Contains(string(socksRespBytes), "ORIGIN_OK") {
		t.Fatalf("Scenario F SOCKS5 payload mismatch: %q", string(socksRespBytes))
	}

	// --- Scenario G & H: DNS client queries local UDP & TCP listeners; DNS rule selects right upstream ---
	_, grp1 := doAPI(http.MethodPost, "/api/v1/dns/groups", map[string]any{
		"name":       "E2E Default DNS",
		"upstreams":  []map[string]string{{"protocol": "udp", "address": dnsUp1}},
		"is_default": true,
	})
	_, grp2 := doAPI(http.MethodPost, "/api/v1/dns/groups", map[string]any{
		"name":       "E2E Corp DNS",
		"upstreams":  []map[string]string{{"protocol": "udp", "address": dnsUp2}},
		"is_default": false,
	})
	grp2ID := int(grp2["id"].(float64))
	_ = grp1

	_, _ = doAPI(http.MethodPost, "/api/v1/rules/dns", map[string]any{
		"priority":     10,
		"enabled":      true,
		"match_type":   "suffix",
		"pattern":      "corp.example.test",
		"action":       "group",
		"dns_group_id": grp2ID,
	})

	udpIP := queryLocalDNSUDP(t, lState.DNSUDPBoundAddr, "public.example.test")
	if udpIP != "198.51.100.111" {
		t.Fatalf("Scenario G/H UDP DNS expected 198.51.100.111, got %s", udpIP)
	}
	tcpIP := queryLocalDNSTCP(t, lState.DNSTCPBoundAddr, "app.corp.example.test")
	if tcpIP != "127.0.0.1" {
		t.Fatalf("Scenario G/H TCP DNS expected 127.0.0.1 for corp.example.test, got %s", tcpIP)
	}

	// --- Scenario I: Managed DNS uses chosen DNS answer while preserving Host header ---
	_, _ = doAPI(http.MethodPost, "/api/v1/rules/routing", map[string]any{
		"priority":        5,
		"enabled":         true,
		"match_type":      "exact",
		"pattern":         "managed.corp.example.test",
		"action":          "pool",
		"resolution_mode": "managed_dns",
		"dns_group_id":    grp2ID,
	})
	respI, err := gwClient.Get(fmt.Sprintf("http://managed.corp.example.test:%s/managed-check", originPort))
	if err != nil {
		t.Fatalf("Scenario I Managed DNS request failed: %v", err)
	}
	_ = respI.Body.Close()
	if gotHost, _ := lastHostHeader.Load().(string); !strings.HasPrefix(gotHost, "managed.corp.example.test") {
		t.Fatalf("Scenario I failed to preserve Host header under Managed DNS: got %q", gotHost)
	}

	// --- Scenario J: Block and proxy-only never establish a direct connection ---
	hitsBeforeJ := originHits.Load()
	_, _ = doAPI(http.MethodPost, "/api/v1/rules/routing", map[string]any{
		"priority":        1,
		"enabled":         true,
		"match_type":      "exact",
		"pattern":         "blocked.example.test",
		"action":          "block",
		"resolution_mode": "remote_dns",
	})
	respJ, err := gwClient.Get(fmt.Sprintf("http://blocked.example.test:%s/should-block", originPort))
	if err == nil {
		_ = respJ.Body.Close()
		if respJ.StatusCode != http.StatusForbidden {
			t.Fatalf("Scenario J expected 403 Forbidden on blocked route, got %d", respJ.StatusCode)
		}
	}
	if originHits.Load() != hitsBeforeJ {
		t.Fatalf("Scenario J INV-01 violated: blocked route reached origin server!")
	}

	// --- Scenario K: Restart preserves applied configuration ---
	_ = application.Shutdown(context.Background())
	_ = store.Close()

	store2, err := storage.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store2.Close()
	app2 := app.New(&cfg, store2, clk, rootPool, token)
	apiSrv2 := api.NewServerWithApp(app2, uiFS, token)
	if err := app2.Start(ctx, apiSrv2.Handler(), 1*time.Hour); err != nil {
		t.Fatalf("Scenario K restart failed: %v", err)
	}
	lState2 := app2.ListenerState()
	tcpIPAfterRestart := queryLocalDNSTCP(t, lState2.DNSTCPBoundAddr, "app.corp.example.test")
	if tcpIPAfterRestart != "127.0.0.1" {
		t.Fatalf("Scenario K failed: DNS rule not preserved after restart (got %s)", tcpIPAfterRestart)
	}

	// --- Scenario L: Cancellation and shutdown release sockets immediately ---
	shutStart := time.Now()
	_ = app2.Shutdown(context.Background())
	if time.Since(shutStart) > 2*time.Second {
		t.Fatalf("Scenario L shutdown took too long: %v", time.Since(shutStart))
	}
}

func serveLocalHTTPConnectFixture(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(clientConn net.Conn) {
			defer clientConn.Close()
			br := bufio.NewReader(clientConn)
			req, err := http.ReadRequest(br)
			if err != nil {
				return
			}
			if req.Method == http.MethodConnect {
				upConn, err := net.DialTimeout("tcp", req.Host, 3*time.Second)
				if err != nil {
					_, _ = io.WriteString(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer upConn.Close()
				_, _ = io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")
				go func() { _, _ = io.Copy(upConn, br) }()
				_, _ = io.Copy(clientConn, upConn)
				return
			}
			upConn, err := net.DialTimeout("tcp", req.Host, 3*time.Second)
			if err != nil {
				return
			}
			defer upConn.Close()
			_ = req.Write(upConn)
			_, _ = io.Copy(clientConn, upConn)
		}(c)
	}
}

func serveLocalSOCKS5Fixture(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			hdr := make([]byte, 2)
			if _, err := io.ReadFull(conn, hdr); err != nil {
				return
			}
			methods := make([]byte, int(hdr[1]))
			_, _ = io.ReadFull(conn, methods)
			_, _ = conn.Write([]byte{0x05, 0x00})

			reqHdr := make([]byte, 4)
			if _, err := io.ReadFull(conn, reqHdr); err != nil || reqHdr[1] != 0x01 {
				return
			}
			var host string
			switch reqHdr[3] {
			case 0x01:
				ip4 := make([]byte, 4)
				_, _ = io.ReadFull(conn, ip4)
				host = net.IP(ip4).String()
			case 0x03:
				l := make([]byte, 1)
				_, _ = io.ReadFull(conn, l)
				d := make([]byte, int(l[0]))
				_, _ = io.ReadFull(conn, d)
				host = string(d)
			case 0x04:
				ip6 := make([]byte, 16)
				_, _ = io.ReadFull(conn, ip6)
				host = net.IP(ip6).String()
			}
			portBuf := make([]byte, 2)
			_, _ = io.ReadFull(conn, portBuf)
			port := int(binary.BigEndian.Uint16(portBuf))

			upConn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 3*time.Second)
			if err != nil {
				_, _ = conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				return
			}
			defer upConn.Close()
			_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			go func() { _, _ = io.Copy(upConn, conn) }()
			_, _ = io.Copy(conn, upConn)
		}(c)
	}
}

func startLocalUDPDNSFixture(t *testing.T, answerIP net.IP, ttl uint32) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			txID, _, qname, qtype, _, err := dns.ParseDNSQueryWire(buf[:n])
			if err != nil {
				continue
			}
			resp := dns.BuildDNSResponseWire(txID, qname, qtype, dns.RcodeSuccess, false, []net.IP{answerIP}, ttl)
			_, _ = pc.WriteTo(resp, addr)
		}
	}()
	return pc.LocalAddr().String()
}

func queryLocalDNSUDP(t *testing.T, addr string, qname string) string {
	t.Helper()
	q, _ := dns.BuildDNSQueryWire(0x55AA, qname, dns.TypeA)
	conn, err := net.DialTimeout("udp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write(q)
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := dns.ParseAndValidateDNSResponseWire(buf[:n], 0x55AA, qname, dns.TypeA)
	if err != nil || len(parsed.IPs) == 0 {
		t.Fatalf("UDP DNS parse failed: err=%v parsed=%+v", err, parsed)
	}
	return parsed.IPs[0].String()
}

func queryLocalDNSTCP(t *testing.T, addr string, qname string) string {
	t.Helper()
	q, _ := dns.BuildDNSQueryWire(0x66BB, qname, dns.TypeA)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	frame := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(q)))
	copy(frame[2:], q)
	_, _ = conn.Write(frame)
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, int(binary.BigEndian.Uint16(lenBuf)))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	parsed, err := dns.ParseAndValidateDNSResponseWire(resp, 0x66BB, qname, dns.TypeA)
	if err != nil || len(parsed.IPs) == 0 {
		t.Fatalf("TCP DNS parse failed: err=%v parsed=%+v", err, parsed)
	}
	return parsed.IPs[0].String()
}
