package diagnostics

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	urlUserInfoRegex = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)([^/@\s]+):([^/@\s]+)@`)
	inlineCredRegex  = regexp.MustCompile(`([^\s:@/]+):([^\s@/]+)@([a-zA-Z0-9.-]+:\d{1,5})`)
	tokenHeaderRegex = regexp.MustCompile(`(?i)(X-ProxyDesk-Token|Proxy-Authorization|Authorization)\s*[:=]\s*([^\s,;"]+)`)
)

// RedactString strips credentials from URLs, host:port@user:pass strings, and auth headers (INV-05).
func RedactString(input string, extraSecrets ...string) string {
	out := urlUserInfoRegex.ReplaceAllString(input, "${1}***:***@")
	out = inlineCredRegex.ReplaceAllString(out, "***:***@$3")
	out = tokenHeaderRegex.ReplaceAllString(out, "${1}: [REDACTED]")
	for _, secret := range extraSecrets {
		if len(secret) >= 3 {
			out = strings.ReplaceAll(out, secret, "[REDACTED]")
		}
	}
	return out
}

func RedactURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return RedactString(rawURL)
	}
	if u.User != nil {
		u.User = url.UserPassword("***", "***")
		return strings.ReplaceAll(u.String(), "%2A%2A%2A:%2A%2A%2A@", "***:***@")
	}
	return RedactString(rawURL)
}

type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Component string    `json:"component"`
	Message   string    `json:"message"`
}

type RotatingLogger struct {
	mu           sync.Mutex
	logPath      string
	maxFileBytes int64
	maxFiles     int
	ring         []LogEntry
	maxRing      int
	secrets      []string
}

func NewRotatingLogger(dataDir string, maxFileBytes int64, maxFiles int, secrets ...string) *RotatingLogger {
	if maxFileBytes <= 0 {
		maxFileBytes = 5 * 1024 * 1024
	}
	if maxFiles <= 0 {
		maxFiles = 3
	}
	return &RotatingLogger{
		logPath:      filepath.Join(dataDir, "proxydesk.log"),
		maxFileBytes: maxFileBytes,
		maxFiles:     maxFiles,
		ring:         make([]LogEntry, 0, 256),
		maxRing:      500,
		secrets:      secrets,
	}
}

func (l *RotatingLogger) Log(level, component, msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	safeMsg := RedactString(msg, l.secrets...)
	entry := LogEntry{
		Timestamp: time.Now().UTC(),
		Level:     level,
		Component: component,
		Message:   safeMsg,
	}
	if len(l.ring) >= l.maxRing {
		copy(l.ring, l.ring[1:])
		l.ring[len(l.ring)-1] = entry
	} else {
		l.ring = append(l.ring, entry)
	}

	if l.logPath == "" {
		return
	}
	l.rotateIfNeeded()
	line := fmt.Sprintf("%s [%s] (%s) %s\n", entry.Timestamp.Format(time.RFC3339), level, component, safeMsg)
	f, err := os.OpenFile(l.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err == nil {
		_, _ = f.WriteString(line)
		_ = f.Close()
	}
}

func (l *RotatingLogger) Recent(limit int) []LogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	if limit <= 0 || limit > len(l.ring) {
		limit = len(l.ring)
	}
	out := make([]LogEntry, limit)
	copy(out, l.ring[len(l.ring)-limit:])
	return out
}

func (l *RotatingLogger) rotateIfNeeded() {
	info, err := os.Stat(l.logPath)
	if err != nil || info.Size() < l.maxFileBytes {
		return
	}
	for i := l.maxFiles - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", l.logPath, i)
		dst := fmt.Sprintf("%s.%d", l.logPath, i+1)
		if i == 1 {
			src = l.logPath
			dst = fmt.Sprintf("%s.1", l.logPath)
		}
		_ = os.Rename(src, dst)
	}
}
