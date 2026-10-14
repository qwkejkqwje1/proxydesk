package checker

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/proxydesk/proxydesk/internal/config"
	"github.com/proxydesk/proxydesk/internal/model"
	"github.com/proxydesk/proxydesk/internal/storage"
)

type CheckOutcome string

const (
	OutcomeSuccess      CheckOutcome = "success"
	OutcomeFailure      CheckOutcome = "failure"
	OutcomeInconclusive CheckOutcome = "inconclusive"
	OutcomeCancelled    CheckOutcome = "cancelled"
)

type TargetCheckResult struct {
	TargetURL   string       `json:"target_url"`
	Outcome     CheckOutcome `json:"outcome"`
	StageFailed string       `json:"stage_failed,omitempty"`
	ConnectMs   int          `json:"connect_ms"`
	HandshakeMs int          `json:"handshake_ms"`
	TTFBMs      int          `json:"ttfb_ms"`
	TotalMs     int          `json:"total_ms"`
	ExitIP      string       `json:"exit_ip,omitempty"`
	ErrorDetail string       `json:"error_detail,omitempty"`
}

type CycleResult struct {
	ProxyID          int                     `json:"proxy_id"`
	CheckedAt        time.Time               `json:"checked_at"`
	Outcome          CheckOutcome            `json:"outcome"`
	TargetsTested    int                     `json:"targets_tested"`
	TargetsSucceeded int                     `json:"targets_succeeded"`
	ConnectMs        *int                    `json:"connect_ms,omitempty"`
	HandshakeMs      *int                    `json:"handshake_ms,omitempty"`
	TTFBMs           *int                    `json:"ttfb_ms,omitempty"`
	TotalMs          *int                    `json:"total_ms,omitempty"`
	ExitIP           string                  `json:"exit_ip,omitempty"`
	Capabilities     model.ProxyCapabilities `json:"capabilities"`
	TargetResults    []TargetCheckResult     `json:"target_results"`
	SummaryError     string                  `json:"summary_error,omitempty"`
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	if b.r != nil && b.r.Buffered() > 0 {
		return b.r.Read(p)
	}
	b.r = nil
	return b.Conn.Read(p)
}

type Checker struct {
	cfg       *config.Config
	credStore *model.CredentialStore
	clock     model.Clock
	rootCAs   *x509.CertPool
	mu        sync.Mutex
	cancelFn  context.CancelFunc
	running   bool
}

func NewChecker(cfg *config.Config, credStore *model.CredentialStore, clock model.Clock, customRootCAs *x509.CertPool) *Checker {
	if clock == nil {
		clock = model.RealClock{}
	}
	return &Checker{
		cfg:       cfg,
		credStore: credStore,
		clock:     clock,
		rootCAs:   customRootCAs,
	}
}

func (c *Checker) CancelBatch() bool {
	c.mu.Lock()
	cancel := c.cancelFn
	running := c.running
	c.mu.Unlock()
	if running && cancel != nil {
		cancel()
		return true
	}
	return false
}

func (c *Checker) CheckProxyCycle(parentCtx context.Context, p storage.ProxyRecord) CycleResult {
	now := c.clock.Now()
	var enabledTargets []config.CheckTargetConfig
	for _, t := range c.cfg.CheckTargets {
		if t.Enabled {
			enabledTargets = append(enabledTargets, t)
		}
	}
	if len(enabledTargets) == 0 {
		return CycleResult{
			ProxyID:      p.ID,
			CheckedAt:    now,
			Outcome:      OutcomeInconclusive,
			Capabilities: p.Capabilities,
			SummaryError: "no enabled check targets configured",
		}
	}

	var creds model.Credentials
	if p.HasAuth && c.credStore != nil {
		creds, _ = c.credStore.Get(p.DedupKey)
	}

	caps := p.Capabilities
	var targetResults []TargetCheckResult
	succeeded := 0
	cancelled := false
	var sumConnect, sumHandshake, sumTTFB, sumTotal int
	var exitIP string

	for _, target := range enabledTargets {
		if parentCtx.Err() != nil {
			cancelled = true
			break
		}
		res, updatedCaps := c.checkSingleTarget(parentCtx, p, creds, target, caps)
		caps = updatedCaps
		targetResults = append(targetResults, res)
		if res.Outcome == OutcomeCancelled {
			cancelled = true
			break
		}
		if res.Outcome == OutcomeSuccess {
			succeeded++
			sumConnect += res.ConnectMs
			sumHandshake += res.HandshakeMs
			sumTTFB += res.TTFBMs
			sumTotal += res.TotalMs
			if res.ExitIP != "" {
				exitIP = res.ExitIP
			}
		}
	}

	if cancelled || errors.Is(parentCtx.Err(), context.Canceled) {
		return CycleResult{
			ProxyID:          p.ID,
			CheckedAt:        now,
			Outcome:          OutcomeCancelled,
			TargetsTested:    len(targetResults),
			TargetsSucceeded: succeeded,
			Capabilities:     p.Capabilities,
			TargetResults:    targetResults,
			SummaryError:     "check cancelled",
		}
	}

	if succeeded > 0 {
		avgConn := sumConnect / succeeded
		avgHs := sumHandshake / succeeded
		avgTTFB := sumTTFB / succeeded
		avgTot := sumTotal / succeeded
		return CycleResult{
			ProxyID:          p.ID,
			CheckedAt:        now,
			Outcome:          OutcomeSuccess,
			TargetsTested:    len(targetResults),
			TargetsSucceeded: succeeded,
			ConnectMs:        &avgConn,
			HandshakeMs:      &avgHs,
			TTFBMs:           &avgTTFB,
			TotalMs:          &avgTot,
			ExitIP:           exitIP,
			Capabilities:     caps,
			TargetResults:    targetResults,
		}
	}

	if c.cfg.EnableDirectDiag && !c.anyTargetReachableDirect(parentCtx, enabledTargets) {
		return CycleResult{
			ProxyID:          p.ID,
			CheckedAt:        now,
			Outcome:          OutcomeInconclusive,
			TargetsTested:    len(targetResults),
			TargetsSucceeded: 0,
			Capabilities:     p.Capabilities,
			TargetResults:    targetResults,
			SummaryError:     "all control targets unreachable directly (network or target outage)",
		}
	}

	summaryErr := "all targets failed"
	if len(targetResults) > 0 {
		summaryErr = targetResults[0].StageFailed + ": " + targetResults[0].ErrorDetail
	}
	return CycleResult{
		ProxyID:          p.ID,
		CheckedAt:        now,
		Outcome:          OutcomeFailure,
		TargetsTested:    len(targetResults),
		TargetsSucceeded: 0,
		Capabilities:     caps,
		TargetResults:    targetResults,
		SummaryError:     summaryErr,
	}
}

func (c *Checker) checkSingleTarget(parentCtx context.Context, p storage.ProxyRecord, creds model.Credentials, target config.CheckTargetConfig, caps model.ProxyCapabilities) (TargetCheckResult, model.ProxyCapabilities) {
	totalTimeout := time.Duration(c.cfg.Budgets.CheckTotalTimeoutMs) * time.Millisecond
	if totalTimeout <= 0 {
		totalTimeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(parentCtx, totalTimeout)
	defer cancel()

	targetURL, err := url.Parse(target.URL)
	if err != nil {
		return TargetCheckResult{TargetURL: target.URL, Outcome: OutcomeInconclusive, ErrorDetail: "invalid target URL"}, caps
	}
	targetHost := targetURL.Hostname()
	targetPort := targetURL.Port()
	if targetPort == "" {
		if targetURL.Scheme == "https" {
			targetPort = "443"
		} else {
			targetPort = "80"
		}
	}
	targetAddr := net.JoinHostPort(targetHost, targetPort)

	connTimeout := time.Duration(c.cfg.Budgets.CheckConnectTimeoutMs) * time.Millisecond
	if connTimeout <= 0 {
		connTimeout = 4 * time.Second
	}
	t0 := time.Now()
	dialer := &net.Dialer{Timeout: connTimeout}
	proxyAddr := net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
	rawConn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		if errors.Is(parentCtx.Err(), context.Canceled) {
			return TargetCheckResult{TargetURL: target.URL, Outcome: OutcomeCancelled}, caps
		}
		return TargetCheckResult{
			TargetURL:   target.URL,
			Outcome:     OutcomeFailure,
			StageFailed: "connect",
			ErrorDetail: err.Error(),
		}, caps
	}
	defer rawConn.Close()
	connectMs := int(time.Since(t0).Milliseconds())

	var doneFlag atomic.Bool
	stopCancelWatch := make(chan struct{})
	defer func() {
		doneFlag.Store(true)
		close(stopCancelWatch)
	}()
	go func() {
		select {
		case <-ctx.Done():
			if !doneFlag.Load() {
				_ = rawConn.SetDeadline(time.Now())
			}
		case <-stopCancelWatch:
		}
	}()

	hsTimeout := time.Duration(c.cfg.Budgets.CheckHandshakeTimeoutMs) * time.Millisecond
	if hsTimeout <= 0 {
		hsTimeout = 4 * time.Second
	}
	_ = rawConn.SetDeadline(time.Now().Add(hsTimeout))
	tHsStart := time.Now()
	now := c.clock.Now()

	var tunnelConn net.Conn = rawConn

	switch p.Protocol {
	case "socks5":
		stage, err := performSOCKS5Handshake(rawConn, creds, targetHost, targetPort)
		if err != nil {
			if errors.Is(parentCtx.Err(), context.Canceled) {
				return TargetCheckResult{TargetURL: target.URL, Outcome: OutcomeCancelled}, caps
			}
			if stage == "auth" {
				caps.Auth = model.CapabilityRecord{State: model.CapabilityUnsupported, Detail: err.Error()}
			} else if stage == "remote_dns" {
				caps.RemoteDNS = model.CapabilityRecord{State: model.CapabilityUnsupported, Detail: err.Error()}
			} else {
				caps.Connect = model.CapabilityRecord{State: model.CapabilityTransientError, Detail: err.Error()}
			}
			return TargetCheckResult{
				TargetURL:   target.URL,
				Outcome:     OutcomeFailure,
				StageFailed: "handshake",
				ConnectMs:   connectMs,
				ErrorDetail: err.Error(),
			}, caps
		}
		caps.Connect = model.CapabilityRecord{State: model.CapabilityConfirmed, VerifiedAt: &now}
		caps.RemoteDNS = model.CapabilityRecord{State: model.CapabilityConfirmed, VerifiedAt: &now}
		if p.HasAuth {
			caps.Auth = model.CapabilityRecord{State: model.CapabilityConfirmed, VerifiedAt: &now}
		}

	case "http":
		if targetURL.Scheme == "https" {
			wrapped, statusCode, err := performHTTPConnectHandshake(rawConn, creds, targetAddr)
			if err != nil {
				if errors.Is(parentCtx.Err(), context.Canceled) {
					return TargetCheckResult{TargetURL: target.URL, Outcome: OutcomeCancelled}, caps
				}
				if statusCode == http.StatusProxyAuthRequired || statusCode == http.StatusForbidden {
					caps.Auth = model.CapabilityRecord{State: model.CapabilityUnsupported, Detail: err.Error()}
				} else if statusCode == http.StatusMethodNotAllowed || statusCode == http.StatusNotImplemented {
					caps.Connect = model.CapabilityRecord{State: model.CapabilityUnsupported, Detail: err.Error()}
				} else {
					caps.Connect = model.CapabilityRecord{State: model.CapabilityTransientError, Detail: err.Error()}
				}
				return TargetCheckResult{
					TargetURL:   target.URL,
					Outcome:     OutcomeFailure,
					StageFailed: "handshake",
					ConnectMs:   connectMs,
					ErrorDetail: err.Error(),
				}, caps
			}
			tunnelConn = wrapped
			caps.Connect = model.CapabilityRecord{State: model.CapabilityConfirmed, VerifiedAt: &now}
			caps.RemoteDNS = model.CapabilityRecord{State: model.CapabilityConfirmed, VerifiedAt: &now}
			if p.HasAuth {
				caps.Auth = model.CapabilityRecord{State: model.CapabilityConfirmed, VerifiedAt: &now}
			}
		}
	}

	var activeConn net.Conn = tunnelConn
	if targetURL.Scheme == "https" {
		tlsCfg := &tls.Config{
			ServerName:         targetHost,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: false,
			RootCAs:            c.rootCAs,
		}
		tlsConn := tls.Client(tunnelConn, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			if errors.Is(parentCtx.Err(), context.Canceled) {
				return TargetCheckResult{TargetURL: target.URL, Outcome: OutcomeCancelled}, caps
			}
			return TargetCheckResult{
				TargetURL:   target.URL,
				Outcome:     OutcomeFailure,
				StageFailed: "tls",
				ConnectMs:   connectMs,
				ErrorDetail: "TLS verification failed: " + err.Error(),
			}, caps
		}
		activeConn = tlsConn
	}
	handshakeMs := int(time.Since(tHsStart).Milliseconds())

	// Clear handshake deadline and set request/response deadline for the remaining total budget
	_ = rawConn.SetDeadline(time.Now().Add(totalTimeout))

	reqURI := targetURL.RequestURI()
	if p.Protocol == "http" && targetURL.Scheme == "http" {
		reqURI = target.URL
	}
	var reqBuilder strings.Builder
	fmt.Fprintf(&reqBuilder, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: ProxyDesk-Checker/1.0\r\nConnection: close\r\n", reqURI, targetHost)
	if p.Protocol == "http" && targetURL.Scheme == "http" && (creds.Username != "" || creds.Password != "") {
		authB64 := base64.StdEncoding.EncodeToString([]byte(creds.Username + ":" + creds.Password))
		fmt.Fprintf(&reqBuilder, "Proxy-Authorization: Basic %s\r\n", authB64)
	}
	reqBuilder.WriteString("\r\n")

	tReqStart := time.Now()
	if _, err := io.WriteString(activeConn, reqBuilder.String()); err != nil {
		return TargetCheckResult{
			TargetURL:   target.URL,
			Outcome:     OutcomeFailure,
			StageFailed: "request",
			ConnectMs:   connectMs,
			HandshakeMs: handshakeMs,
			ErrorDetail: err.Error(),
		}, caps
	}

	br := bufio.NewReader(activeConn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		if errors.Is(parentCtx.Err(), context.Canceled) {
			return TargetCheckResult{TargetURL: target.URL, Outcome: OutcomeCancelled}, caps
		}
		return TargetCheckResult{
			TargetURL:   target.URL,
			Outcome:     OutcomeFailure,
			StageFailed: "response",
			ConnectMs:   connectMs,
			HandshakeMs: handshakeMs,
			ErrorDetail: err.Error(),
		}, caps
	}
	defer resp.Body.Close()
	ttfbMs := int(time.Since(tReqStart).Milliseconds())

	expectStatus := target.ExpectStatus
	if expectStatus == 0 {
		expectStatus = http.StatusOK
	}
	if resp.StatusCode != expectStatus {
		return TargetCheckResult{
			TargetURL:   target.URL,
			Outcome:     OutcomeFailure,
			StageFailed: "response",
			ConnectMs:   connectMs,
			HandshakeMs: handshakeMs,
			TTFBMs:      ttfbMs,
			ErrorDetail: fmt.Sprintf("unexpected HTTP status %d (expected %d)", resp.StatusCode, expectStatus),
		}, caps
	}

	maxBody := c.cfg.Budgets.MaxCheckBodyBytes
	if maxBody <= 0 {
		maxBody = 64 * 1024
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		if errors.Is(parentCtx.Err(), context.Canceled) {
			return TargetCheckResult{TargetURL: target.URL, Outcome: OutcomeCancelled}, caps
		}
		return TargetCheckResult{
			TargetURL:   target.URL,
			Outcome:     OutcomeFailure,
			StageFailed: "response",
			ConnectMs:   connectMs,
			HandshakeMs: handshakeMs,
			TTFBMs:      ttfbMs,
			ErrorDetail: "body read failed: " + err.Error(),
		}, caps
	}
	if int64(len(bodyBytes)) > maxBody {
		return TargetCheckResult{
			TargetURL:   target.URL,
			Outcome:     OutcomeFailure,
			StageFailed: "response",
			ConnectMs:   connectMs,
			HandshakeMs: handshakeMs,
			TTFBMs:      ttfbMs,
			ErrorDetail: "response body exceeded max_check_body_bytes",
		}, caps
	}
	if len(strings.TrimSpace(string(bodyBytes))) == 0 {
		return TargetCheckResult{
			TargetURL:   target.URL,
			Outcome:     OutcomeFailure,
			StageFailed: "response",
			ConnectMs:   connectMs,
			HandshakeMs: handshakeMs,
			TTFBMs:      ttfbMs,
			ErrorDetail: "empty response body",
		}, caps
	}

	totalMs := int(time.Since(t0).Milliseconds())
	var extractedIP string
	if target.ExtractsExitIP {
		extractedIP = parseExitIP(string(bodyBytes))
	}

	return TargetCheckResult{
		TargetURL:   target.URL,
		Outcome:     OutcomeSuccess,
		ConnectMs:   connectMs,
		HandshakeMs: handshakeMs,
		TTFBMs:      ttfbMs,
		TotalMs:     totalMs,
		ExitIP:      extractedIP,
	}, caps
}

func performHTTPConnectHandshake(conn net.Conn, creds model.Credentials, targetAddr string) (net.Conn, int, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: ProxyDesk-Checker/1.0\r\n", targetAddr, targetAddr)
	if creds.Username != "" || creds.Password != "" {
		authB64 := base64.StdEncoding.EncodeToString([]byte(creds.Username + ":" + creds.Password))
		fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n", authB64)
	}
	b.WriteString("\r\n")

	if _, err := io.WriteString(conn, b.String()); err != nil {
		return nil, 0, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("CONNECT rejected with HTTP %d", resp.StatusCode)
	}
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, http.StatusOK, nil
	}
	return conn, http.StatusOK, nil
}

func performSOCKS5Handshake(conn net.Conn, creds model.Credentials, targetHost, targetPortStr string) (string, error) {
	hasAuth := creds.Username != "" || creds.Password != ""
	var greeting []byte
	if hasAuth {
		greeting = []byte{0x05, 0x02, 0x00, 0x02}
	} else {
		greeting = []byte{0x05, 0x01, 0x00}
	}
	if _, err := conn.Write(greeting); err != nil {
		return "handshake", err
	}
	methodResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, methodResp); err != nil {
		return "handshake", err
	}
	if methodResp[0] != 0x05 {
		return "handshake", fmt.Errorf("invalid SOCKS5 version %d", methodResp[0])
	}
	if methodResp[1] == 0xFF {
		return "auth", errors.New("SOCKS5 server rejected authentication methods")
	}
	if methodResp[1] == 0x02 {
		if len(creds.Username) > 255 || len(creds.Password) > 255 {
			return "auth", errors.New("SOCKS5 credentials exceed 255 bytes")
		}
		authBuf := make([]byte, 0, 3+len(creds.Username)+len(creds.Password))
		authBuf = append(authBuf, 0x01, byte(len(creds.Username)))
		authBuf = append(authBuf, []byte(creds.Username)...)
		authBuf = append(authBuf, byte(len(creds.Password)))
		authBuf = append(authBuf, []byte(creds.Password)...)
		if _, err := conn.Write(authBuf); err != nil {
			return "auth", err
		}
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			return "auth", err
		}
		if authResp[0] != 0x01 || authResp[1] != 0x00 {
			return "auth", errors.New("SOCKS5 username/password authentication failed")
		}
	} else if methodResp[1] != 0x00 {
		return "auth", fmt.Errorf("unsupported SOCKS5 auth method 0x%02x", methodResp[1])
	}

	portNum, err := strconv.Atoi(targetPortStr)
	if err != nil || portNum < 1 || portNum > 65535 {
		return "handshake", errors.New("invalid target port")
	}

	req := []byte{0x05, 0x01, 0x00}
	ip := net.ParseIP(targetHost)
	if ip4 := ip.To4(); ip4 != nil {
		req = append(req, 0x01)
		req = append(req, ip4...)
	} else if ip6 := ip.To16(); ip6 != nil {
		req = append(req, 0x04)
		req = append(req, ip6...)
	} else {
		if len(targetHost) == 0 || len(targetHost) > 255 {
			return "remote_dns", errors.New("domain name length invalid")
		}
		req = append(req, 0x03, byte(len(targetHost)))
		req = append(req, []byte(targetHost)...)
	}
	req = append(req, byte(portNum>>8), byte(portNum&0xFF))

	if _, err := conn.Write(req); err != nil {
		return "handshake", err
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return "handshake", err
	}
	if hdr[0] != 0x05 {
		return "handshake", fmt.Errorf("invalid SOCKS5 connect reply version %d", hdr[0])
	}
	if hdr[1] != 0x00 {
		if hdr[1] == 0x04 || hdr[1] == 0x08 {
			return "remote_dns", fmt.Errorf("SOCKS5 remote host/ATYP error code %d", hdr[1])
		}
		return "handshake", fmt.Errorf("SOCKS5 connect failed with reply code %d", hdr[1])
	}
	var discardLen int
	switch hdr[3] {
	case 0x01:
		discardLen = 4 + 2
	case 0x04:
		discardLen = 16 + 2
	case 0x03:
		domLen := make([]byte, 1)
		if _, err := io.ReadFull(conn, domLen); err != nil {
			return "handshake", err
		}
		discardLen = int(domLen[0]) + 2
	default:
		return "handshake", fmt.Errorf("unknown SOCKS5 ATYP %d", hdr[3])
	}
	discard := make([]byte, discardLen)
	_, err = io.ReadFull(conn, discard)
	return "handshake", err
}

func parseExitIP(body string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ip=") {
			candidate := strings.TrimSpace(strings.TrimPrefix(line, "ip="))
			if net.ParseIP(candidate) != nil {
				return candidate
			}
		}
		if net.ParseIP(line) != nil {
			return line
		}
	}
	return ""
}

func (c *Checker) anyTargetReachableDirect(ctx context.Context, targets []config.CheckTargetConfig) bool {
	tr := &http.Transport{
		Proxy:             nil,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: c.rootCAs},
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	for _, t := range targets {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.URL, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == t.ExpectStatus || (t.ExpectStatus == 0 && resp.StatusCode == http.StatusOK) {
				return true
			}
		}
	}
	return false
}

func (c *Checker) RunBatch(parentCtx context.Context, proxies []storage.ProxyRecord, onProgress func(done, total int, res CycleResult)) []CycleResult {
	c.mu.Lock()
	ctx, cancel := context.WithCancel(parentCtx)
	c.cancelFn = cancel
	c.running = true
	c.mu.Unlock()

	defer func() {
		cancel()
		c.mu.Lock()
		c.running = false
		c.cancelFn = nil
		c.mu.Unlock()
	}()

	workers := c.cfg.Budgets.MaxConcurrentChecks
	if workers <= 0 {
		workers = 16
	}
	if workers > len(proxies) && len(proxies) > 0 {
		workers = len(proxies)
	}
	if workers == 0 {
		return nil
	}

	jobs := make(chan storage.ProxyRecord, len(proxies))
	for _, p := range proxies {
		jobs <- p
	}
	close(jobs)

	var wg sync.WaitGroup
	var resMu sync.Mutex
	results := make([]CycleResult, 0, len(proxies))
	doneCount := 0

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				res := c.CheckProxyCycle(ctx, p)
				resMu.Lock()
				results = append(results, res)
				doneCount++
				if onProgress != nil {
					onProgress(doneCount, len(proxies), res)
				}
				resMu.Unlock()
			}
		}()
	}
	wg.Wait()
	return results
}
