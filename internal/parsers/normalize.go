package parsers

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/proxydesk/proxydesk/internal/diagnostics"
	"github.com/proxydesk/proxydesk/internal/model"
)

var (
	ErrUnsupportedProtocol = errors.New("unsupported proxy protocol (only http and socks5 supported)")
	ErrInvalidHostPort     = errors.New("invalid proxy host or port")
	ErrPrivateIPForbidden  = errors.New("private, loopback, or link-local proxy address rejected")
	ErrSchemaMismatch      = errors.New("input schema mismatch")
)

var htmlCandidateRegex = regexp.MustCompile(`(?i)(?:(http|socks5)://)?(?:([^\s:@<>"']+):([^\s@<>"']+)@)?([a-zA-Z0-9.-]+|\[\:[a-fA-F0-9:]+\]):(\d{1,5})`)

type NormalizedCandidate struct {
	DedupKey     string
	Protocol     string // "http" or "socks5"
	Host         string
	Port         int
	HasAuth      bool
	Username     string // kept in memory only, never persisted to SQLite
	Password     string // kept in memory only, never persisted to SQLite
	SanitizedRaw string // safe for SQLite proxy_sources.raw_line (no secrets)
	Status       model.ProxyStatus
	Capabilities model.ProxyCapabilities
}

// IsRestrictedIP returns true if ip is loopback, private, link-local, multicast, or unspecified.
func IsRestrictedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() ||
		ip.Equal(net.ParseIP("169.254.169.254"))
}

// ComputeDedupKey generates a collision-resistant deduplication key that distinguishes
// proxies with different credentials WITHOUT storing plaintext credentials in the key (INV-05, ADR-003).
func ComputeDedupKey(protocol, host string, port int, username, password string) string {
	base := fmt.Sprintf("%s://%s:%d", strings.ToLower(protocol), strings.ToLower(host), port)
	if username == "" && password == "" {
		return base + "#anon"
	}
	sum := sha256.Sum256([]byte(username + "\x00" + password))
	return base + "#auth-" + hex.EncodeToString(sum[:16])
}

// NormalizeProxyLine parses a single proxy line (scheme://user:pass@host:port, user:pass@host:port, or host:port).
// Newly imported proxies always receive StatusUnknown and unknown capabilities.
func NormalizeProxyLine(rawLine string, defaultProtocol string, allowPrivate bool) (*NormalizedCandidate, error) {
	trimmed := strings.TrimSpace(rawLine)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
		return nil, nil
	}

	proto := strings.ToLower(strings.TrimSpace(defaultProtocol))
	if proto == "" {
		proto = "http"
	}
	target := trimmed
	if !strings.Contains(target, "://") {
		target = proto + "://" + target
	}

	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidHostPort, err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme == "socks5h" {
		scheme = "socks5"
	}
	if scheme != "http" && scheme != "socks5" {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedProtocol, u.Scheme)
	}

	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	portStr := u.Port()
	if host == "" || portStr == "" {
		return nil, ErrInvalidHostPort
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, ErrInvalidHostPort
	}

	if ip := net.ParseIP(host); ip != nil {
		if !allowPrivate && IsRestrictedIP(ip) {
			return nil, fmt.Errorf("%w: %s", ErrPrivateIPForbidden, ip.String())
		}
	} else {
		if !allowPrivate && (host == "localhost" || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal")) {
			return nil, fmt.Errorf("%w: %s", ErrPrivateIPForbidden, host)
		}
	}

	var username, password string
	hasAuth := false
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
		hasAuth = username != "" || password != ""
	}

	dedupKey := ComputeDedupKey(scheme, host, port, username, password)
	sanitizedRaw := diagnostics.RedactString(trimmed)
	if hasAuth && password != "" {
		sanitizedRaw = diagnostics.RedactString(sanitizedRaw, password)
	}

	return &NormalizedCandidate{
		DedupKey:     dedupKey,
		Protocol:     scheme,
		Host:         host,
		Port:         port,
		HasAuth:      hasAuth,
		Username:     username,
		Password:     password,
		SanitizedRaw: sanitizedRaw,
		Status:       model.StatusUnknown,
		Capabilities: model.DefaultCapabilities(),
	}, nil
}

type ParseStats struct {
	TotalLines  int                   `json:"total_lines"`
	ValidCount  int                   `json:"valid_count"`
	UniqueCount int                   `json:"unique_count"`
	ErrorCount  int                   `json:"error_count"`
	Candidates  []NormalizedCandidate `json:"-"`
}

func ParseTXT(content string, defaultProtocol string, allowPrivate bool) ParseStats {
	lines := strings.Split(content, "\n")
	seen := make(map[string]struct{})
	stats := ParseStats{}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		stats.TotalLines++
		cand, err := NormalizeProxyLine(trimmed, defaultProtocol, allowPrivate)
		if err != nil {
			stats.ErrorCount++
			continue
		}
		if cand == nil {
			continue
		}
		stats.ValidCount++
		if _, exists := seen[cand.DedupKey]; !exists {
			seen[cand.DedupKey] = struct{}{}
			stats.Candidates = append(stats.Candidates, *cand)
		}
	}
	stats.UniqueCount = len(stats.Candidates)
	return stats
}

// ParseCSV parses a CSV proxy list with an explicit header schema requiring at least "host" and "port"
// (or "proxy") columns.
func ParseCSV(content string, defaultProtocol string, allowPrivate bool) (ParseStats, error) {
	r := csv.NewReader(strings.NewReader(content))
	r.FieldsPerRecord = -1
	headers, err := r.Read()
	if err != nil {
		return ParseStats{}, fmt.Errorf("%w: cannot read CSV header: %v", ErrSchemaMismatch, err)
	}
	colIdx := make(map[string]int)
	for i, h := range headers {
		colIdx[strings.ToLower(strings.TrimSpace(h))] = i
	}
	_, hasProxyCol := colIdx["proxy"]
	_, hasHostCol := colIdx["host"]
	_, hasPortCol := colIdx["port"]
	if !hasProxyCol && (!hasHostCol || !hasPortCol) {
		return ParseStats{}, fmt.Errorf("%w: CSV header must contain 'proxy' or both 'host' and 'port' columns", ErrSchemaMismatch)
	}

	seen := make(map[string]struct{})
	stats := ParseStats{}
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		stats.TotalLines++
		if err != nil {
			stats.ErrorCount++
			continue
		}
		var line string
		if idx, ok := colIdx["proxy"]; ok && idx < len(rec) {
			line = rec[idx]
		} else {
			h := rec[colIdx["host"]]
			p := rec[colIdx["port"]]
			proto := defaultProtocol
			if pIdx, ok := colIdx["protocol"]; ok && pIdx < len(rec) && strings.TrimSpace(rec[pIdx]) != "" {
				proto = strings.TrimSpace(rec[pIdx])
			}
			u := ""
			if uIdx, ok := colIdx["username"]; ok && uIdx < len(rec) {
				u = strings.TrimSpace(rec[uIdx])
			}
			pw := ""
			if pwIdx, ok := colIdx["password"]; ok && pwIdx < len(rec) {
				pw = strings.TrimSpace(rec[pwIdx])
			}
			if u != "" || pw != "" {
				line = fmt.Sprintf("%s://%s:%s@%s:%s", proto, u, pw, h, p)
			} else {
				line = fmt.Sprintf("%s://%s:%s", proto, h, p)
			}
		}
		cand, err := NormalizeProxyLine(line, defaultProtocol, allowPrivate)
		if err != nil || cand == nil {
			stats.ErrorCount++
			continue
		}
		stats.ValidCount++
		if _, exists := seen[cand.DedupKey]; !exists {
			seen[cand.DedupKey] = struct{}{}
			stats.Candidates = append(stats.Candidates, *cand)
		}
	}
	stats.UniqueCount = len(stats.Candidates)
	return stats, nil
}

type jsonProxyEntry struct {
	Proxy    string  `json:"proxy"`
	Protocol string  `json:"protocol"`
	Host     string  `json:"host"`
	Port     int     `json:"port"`
	Username *string `json:"username"`
	Password *string `json:"password"`
}

// ParseJSON parses either a JSON array of proxy objects (like monosans/proxy-list proxies.json)
// or an object {"proxies": [...]}.
func ParseJSON(content string, defaultProtocol string, allowPrivate bool) (ParseStats, error) {
	trimmed := bytes.TrimSpace([]byte(content))
	if len(trimmed) == 0 {
		return ParseStats{}, fmt.Errorf("%w: empty JSON input", ErrSchemaMismatch)
	}
	var entries []jsonProxyEntry
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &entries); err != nil {
			return ParseStats{}, fmt.Errorf("%w: invalid JSON array: %v", ErrSchemaMismatch, err)
		}
	} else {
		var wrapper struct {
			Proxies []jsonProxyEntry `json:"proxies"`
		}
		if err := json.Unmarshal(trimmed, &wrapper); err != nil || wrapper.Proxies == nil {
			return ParseStats{}, fmt.Errorf("%w: JSON object must contain 'proxies' array", ErrSchemaMismatch)
		}
		entries = wrapper.Proxies
	}

	seen := make(map[string]struct{})
	stats := ParseStats{TotalLines: len(entries)}
	for _, item := range entries {
		var line string
		if item.Proxy != "" {
			line = item.Proxy
		} else {
			if item.Host == "" || item.Port <= 0 {
				stats.ErrorCount++
				continue
			}
			proto := item.Protocol
			if proto == "" {
				proto = defaultProtocol
			}
			u, pw := "", ""
			if item.Username != nil {
				u = *item.Username
			}
			if item.Password != nil {
				pw = *item.Password
			}
			if u != "" || pw != "" {
				line = fmt.Sprintf("%s://%s:%s@%s:%d", proto, u, pw, item.Host, item.Port)
			} else {
				line = fmt.Sprintf("%s://%s:%d", proto, item.Host, item.Port)
			}
		}
		cand, err := NormalizeProxyLine(line, defaultProtocol, allowPrivate)
		if err != nil || cand == nil {
			stats.ErrorCount++
			continue
		}
		stats.ValidCount++
		if _, exists := seen[cand.DedupKey]; !exists {
			seen[cand.DedupKey] = struct{}{}
			stats.Candidates = append(stats.Candidates, *cand)
		}
	}
	stats.UniqueCount = len(stats.Candidates)
	return stats, nil
}

// ParseStaticHTML extracts proxy candidates from static HTML without executing any JavaScript.
func ParseStaticHTML(content string, defaultProtocol string, allowPrivate bool) ParseStats {
	matches := htmlCandidateRegex.FindAllString(content, -1)
	return ParseTXT(strings.Join(matches, "\n"), defaultProtocol, allowPrivate)
}
