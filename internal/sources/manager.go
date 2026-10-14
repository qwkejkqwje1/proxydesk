package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/proxydesk/proxydesk/internal/diagnostics"
	"github.com/proxydesk/proxydesk/internal/model"
	"github.com/proxydesk/proxydesk/internal/parsers"
	"github.com/proxydesk/proxydesk/internal/storage"
)

var (
	ErrSourceAlreadyRunning   = errors.New("source refresh is already running")
	ErrSourceResponseTooLarge = errors.New("source response exceeds max_source_body_bytes limit")
	ErrTooManyRedirects       = errors.New("source exceeded maximum redirect limit (3)")
	ErrSSRFBlockedAddress     = errors.New("connection to private, loopback, or link-local address blocked by SSRF policy")
)

type RefreshProgress struct {
	SourceID    int64  `json:"source_id"`
	Status      string `json:"status"` // "running", "ok", "not_modified", "error", "cancelled"
	TotalParsed int    `json:"total_parsed"`
	TotalUnique int    `json:"total_unique"`
	TotalErrors int    `json:"total_errors"`
	Error       string `json:"error,omitempty"`
}

type Manager struct {
	store          *storage.Store
	credStore      *model.CredentialStore
	logger         *diagnostics.RotatingLogger
	clock          model.Clock
	rng            *rand.Rand
	maxBodyBytes   int64
	mu             sync.Mutex
	runningSources map[int64]context.CancelFunc
}

func NewManager(store *storage.Store, credStore *model.CredentialStore, logger *diagnostics.RotatingLogger, clock model.Clock, seed int64, maxBodyBytes int64) *Manager {
	if clock == nil {
		clock = model.RealClock{}
	}
	if maxBodyBytes <= 0 {
		maxBodyBytes = 10 * 1024 * 1024
	}
	return &Manager{
		store:          store,
		credStore:      credStore,
		logger:         logger,
		clock:          clock,
		rng:            rand.New(rand.NewSource(seed)),
		maxBodyBytes:   maxBodyBytes,
		runningSources: make(map[int64]context.CancelFunc),
	}
}

// CancelSource cancels an in-flight refresh for sourceID and releases resources (INV-03).
func (m *Manager) CancelSource(sourceID int64) bool {
	m.mu.Lock()
	cancel, ok := m.runningSources[sourceID]
	m.mu.Unlock()
	if ok && cancel != nil {
		cancel()
		return true
	}
	return false
}

func (m *Manager) CancelAll() {
	m.mu.Lock()
	cancels := make([]context.CancelFunc, 0, len(m.runningSources))
	for _, c := range m.runningSources {
		cancels = append(cancels, c)
	}
	m.mu.Unlock()
	for _, c := range cancels {
		c()
	}
}

func (m *Manager) IsRunning(sourceID int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.runningSources[sourceID]
	return ok
}

// ComputeBackoff calculates exponential backoff with deterministic jitter (Increment B & Section 4).
func (m *Manager) ComputeBackoff(consecutiveFailures int) time.Duration {
	if consecutiveFailures <= 0 {
		return 0
	}
	shift := consecutiveFailures - 1
	if shift > 6 {
		shift = 6
	}
	base := time.Duration(30*(1<<shift)) * time.Second
	if base > 30*time.Minute {
		base = 30 * time.Minute
	}
	m.mu.Lock()
	jitterSec := m.rng.Intn(11) // 0..10s deterministic jitter
	m.mu.Unlock()
	return base + time.Duration(jitterSec)*time.Second
}

// RefreshSource runs a single source fetch, parse, and deduplicated upsert.
// Concurrent runs of the same sourceID are strictly prevented.
func (m *Manager) RefreshSource(parentCtx context.Context, src storage.SourceRecord) (RefreshProgress, error) {
	id := int64(src.ID)
	m.mu.Lock()
	if _, exists := m.runningSources[id]; exists {
		m.mu.Unlock()
		return RefreshProgress{SourceID: id, Status: "running"}, ErrSourceAlreadyRunning
	}
	timeout := time.Duration(src.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	m.runningSources[id] = cancel
	m.mu.Unlock()

	defer func() {
		cancel()
		m.mu.Lock()
		delete(m.runningSources, id)
		m.mu.Unlock()
	}()

	now := m.clock.Now()
	rawContent, newETag, newLastMod, notModified, err := m.loadSourceContent(ctx, src)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(parentCtx.Err(), context.Canceled) {
			_ = m.recordSourceOutcome(id, now, "cancelled", "cancelled by user", src.ETag, src.LastModified, src.ConsecutiveFailures, "", 0, 0, 0)
			return RefreshProgress{SourceID: id, Status: "cancelled", Error: "cancelled"}, context.Canceled
		}
		failures := src.ConsecutiveFailures + 1
		backoffUntil := now.Add(m.ComputeBackoff(failures)).Format(time.RFC3339)
		safeErr := diagnostics.RedactString(err.Error())
		_ = m.recordSourceOutcome(id, now, "error", safeErr, src.ETag, src.LastModified, failures, backoffUntil, 0, 0, 0)
		return RefreshProgress{SourceID: id, Status: "error", Error: safeErr}, err
	}

	if notModified {
		_ = m.recordSourceOutcome(id, now, "not_modified", "", src.ETag, src.LastModified, 0, "", src.TotalParsed, src.TotalUnique, src.TotalErrors)
		return RefreshProgress{
			SourceID:    id,
			Status:      "not_modified",
			TotalParsed: src.TotalParsed,
			TotalUnique: src.TotalUnique,
			TotalErrors: src.TotalErrors,
		}, nil
	}

	stats, parseErr := m.parseByFormat(rawContent, src.Format, src.DefaultProtocol, src.AllowPrivate)
	if parseErr != nil {
		failures := src.ConsecutiveFailures + 1
		backoffUntil := now.Add(m.ComputeBackoff(failures)).Format(time.RFC3339)
		safeErr := diagnostics.RedactString(parseErr.Error())
		_ = m.recordSourceOutcome(id, now, "error", safeErr, src.ETag, src.LastModified, failures, backoffUntil, 0, 0, 0)
		return RefreshProgress{SourceID: id, Status: "error", Error: safeErr}, parseErr
	}

	if _, err := m.store.UpsertCandidates(ctx, id, stats.Candidates, m.credStore, now); err != nil {
		if errors.Is(err, context.Canceled) {
			_ = m.recordSourceOutcome(id, now, "cancelled", "cancelled during upsert", src.ETag, src.LastModified, src.ConsecutiveFailures, "", 0, 0, 0)
			return RefreshProgress{SourceID: id, Status: "cancelled"}, context.Canceled
		}
		return RefreshProgress{SourceID: id, Status: "error", Error: err.Error()}, err
	}

	etagToSave := src.ETag
	if newETag != "" {
		etagToSave = newETag
	}
	lastModToSave := src.LastModified
	if newLastMod != "" {
		lastModToSave = newLastMod
	}
	_ = m.recordSourceOutcome(id, now, "ok", "", etagToSave, lastModToSave, 0, "", stats.ValidCount, stats.UniqueCount, stats.ErrorCount)
	return RefreshProgress{
		SourceID:    id,
		Status:      "ok",
		TotalParsed: stats.ValidCount,
		TotalUnique: stats.UniqueCount,
		TotalErrors: stats.ErrorCount,
	}, nil
}

// DueSources returns enabled sources whose schedule interval and backoff window have elapsed at clock.Now().
func (m *Manager) DueSources() ([]storage.SourceRecord, error) {
	all, err := m.store.ListSources()
	if err != nil {
		return nil, err
	}
	now := m.clock.Now()
	var due []storage.SourceRecord
	for _, s := range all {
		if !s.Enabled {
			continue
		}
		if m.IsRunning(int64(s.ID)) {
			continue
		}
		if s.BackoffUntil != "" {
			if t, err := time.Parse(time.RFC3339, s.BackoffUntil); err == nil && now.Before(t) {
				continue
			}
		}
		if s.LastRunAt == "" {
			// Remember: first automatic bulk scrape does NOT run immediately on install unless LastRunAt was set or user triggered
			continue
		}
		lastRun, err := time.Parse(time.RFC3339, s.LastRunAt)
		if err != nil {
			continue
		}
		if now.Sub(lastRun) >= time.Duration(s.UpdateIntervalSec)*time.Second {
			due = append(due, s)
		}
	}
	return due, nil
}

func (m *Manager) loadSourceContent(ctx context.Context, src storage.SourceRecord) (content, etag, lastMod string, notModified bool, err error) {
	switch src.Kind {
	case "manual":
		return src.Location, "", "", false, nil
	case "file":
		info, err := os.Stat(src.Location)
		if err != nil {
			return "", "", "", false, err
		}
		if info.Size() > m.maxBodyBytes {
			return "", "", "", false, ErrSourceResponseTooLarge
		}
		b, err := os.ReadFile(src.Location)
		if err != nil {
			return "", "", "", false, err
		}
		return string(b), "", "", false, nil
	case "url", "html":
		return m.fetchURLSafe(ctx, src)
	default:
		return "", "", "", false, fmt.Errorf("unsupported source kind %q", src.Kind)
	}
}

// fetchURLSafe downloads a source over HTTP/HTTPS verifying the actual destination IP at dial time
// via net.Dialer.Control (preventing DNS rebinding and redirect SSRF), enforcing max 3 redirects
// and reading at most m.maxBodyBytes + 1 bytes.
func (m *Manager) fetchURLSafe(ctx context.Context, src storage.SourceRecord) (content, etag, lastMod string, notModified bool, err error) {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, splitErr := net.SplitHostPort(address)
			if splitErr != nil {
				return splitErr
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return ErrSSRFBlockedAddress
			}
			if !src.AllowPrivate && parsers.IsRestrictedIP(ip) {
				return fmt.Errorf("%w: %s", ErrSSRFBlockedAddress, ip.String())
			}
			return nil
		},
	}

	transport := &http.Transport{
		Proxy:                 nil, // Never inherit system HTTP_PROXY
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		DisableKeepAlives:     true,
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return ErrTooManyRedirects
			}
			scheme := strings.ToLower(req.URL.Scheme)
			if scheme != "http" && scheme != "https" {
				return fmt.Errorf("unsupported redirect scheme %q", scheme)
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.Location, nil)
	if err != nil {
		return "", "", "", false, err
	}
	req.Header.Set("User-Agent", "ProxyDesk/1.0")
	if src.ETag != "" {
		req.Header.Set("If-None-Match", src.ETag)
	}
	if src.LastModified != "" {
		req.Header.Set("If-Modified-Since", src.LastModified)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return "", resp.Header.Get("ETag"), resp.Header.Get("Last-Modified"), true, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", "", false, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}

	limited := io.LimitReader(resp.Body, m.maxBodyBytes+1)
	bodyBytes, err := io.ReadAll(limited)
	if err != nil {
		return "", "", "", false, err
	}
	if int64(len(bodyBytes)) > m.maxBodyBytes {
		return "", "", "", false, ErrSourceResponseTooLarge
	}

	return string(bodyBytes), resp.Header.Get("ETag"), resp.Header.Get("Last-Modified"), false, nil
}

func (m *Manager) parseByFormat(raw, format, defaultProto string, allowPrivate bool) (parsers.ParseStats, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "csv":
		return parsers.ParseCSV(raw, defaultProto, allowPrivate)
	case "json":
		return parsers.ParseJSON(raw, defaultProto, allowPrivate)
	case "html":
		return parsers.ParseStaticHTML(raw, defaultProto, allowPrivate), nil
	default:
		return parsers.ParseTXT(raw, defaultProto, allowPrivate), nil
	}
}

func (m *Manager) recordSourceOutcome(id int64, now time.Time, status, lastErr, etag, lastMod string, failures int, backoffUntil string, parsed, unique, errs int) error {
	_, err := m.store.DB().Exec(`
		UPDATE sources SET
			last_run_at = ?,
			last_status = ?,
			last_error = ?,
			etag = ?,
			last_modified = ?,
			consecutive_failures = ?,
			backoff_until = ?,
			total_parsed = ?,
			total_unique = ?,
			total_errors = ?
		WHERE id = ?`,
		now.UTC().Format(time.RFC3339), status, lastErr, etag, lastMod,
		failures, backoffUntil, parsed, unique, errs, id,
	)
	return err
}

func (m *Manager) ExportSourcesJSON() ([]byte, error) {
	list, err := m.store.ListSources()
	if err != nil {
		return nil, err
	}
	for i := range list {
		list[i].Location = diagnostics.RedactString(list[i].Location)
	}
	return json.MarshalIndent(list, "", "  ")
}
