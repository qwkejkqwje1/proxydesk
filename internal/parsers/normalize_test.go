package parsers

import (
	"errors"
	"strings"
	"testing"

	"github.com/proxydesk/proxydesk/internal/model"
)

func TestInvariant_NoCredentialsInDedupKeyOrRawLine(t *testing.T) {
	cand1, err := NormalizeProxyLine("socks5://userA:TopSecretPass1@203.0.113.10:1080", "http", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cand2, err := NormalizeProxyLine("socks5://userA:DifferentPass2@203.0.113.10:1080", "http", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 1. Different passwords must produce distinct dedup_keys
	if cand1.DedupKey == cand2.DedupKey {
		t.Fatalf("proxies with different passwords must not share dedup_key: %s", cand1.DedupKey)
	}

	// 2. Neither dedup_key nor SanitizedRaw may contain the plaintext password or username
	if strings.Contains(cand1.DedupKey, "TopSecretPass1") || strings.Contains(cand1.DedupKey, "userA") {
		t.Fatalf("credentials leaked in dedup_key: %s", cand1.DedupKey)
	}
	if strings.Contains(cand1.SanitizedRaw, "TopSecretPass1") || strings.Contains(cand1.SanitizedRaw, "userA") {
		t.Fatalf("credentials leaked in SanitizedRaw: %s", cand1.SanitizedRaw)
	}

	// 3. Imported proxy status must strictly be unknown
	if cand1.Status != model.StatusUnknown {
		t.Fatalf("expected StatusUnknown, got %s", cand1.Status)
	}
}

func TestPrivateIPRejectedByDefaultAndAllowedExplicitly(t *testing.T) {
	_, err := NormalizeProxyLine("http://127.0.0.1:8080", "http", false)
	if !errors.Is(err, ErrPrivateIPForbidden) {
		t.Fatalf("expected ErrPrivateIPForbidden for 127.0.0.1, got %v", err)
	}
	_, err = NormalizeProxyLine("socks5://192.168.1.50:1080", "socks5", false)
	if !errors.Is(err, ErrPrivateIPForbidden) {
		t.Fatalf("expected ErrPrivateIPForbidden for 192.168.1.50, got %v", err)
	}

	cand, err := NormalizeProxyLine("http://127.0.0.1:8080", "http", true)
	if err != nil || cand == nil {
		t.Fatalf("expected private IP to succeed when allowPrivate=true, got %v", err)
	}
}

func TestParseCSVAndJSONSchemas(t *testing.T) {
	csvInput := "protocol,host,port\nsocks5,198.51.100.1,1080\nhttp,198.51.100.2,8080\n"
	stats, err := ParseCSV(csvInput, "http", false)
	if err != nil || stats.UniqueCount != 2 {
		t.Fatalf("CSV parse failed: err=%v stats=%+v", err, stats)
	}

	_, errBadCSV := ParseCSV("foo,bar\n1,2\n", "http", false)
	if !errors.Is(errBadCSV, ErrSchemaMismatch) {
		t.Fatalf("expected ErrSchemaMismatch for invalid CSV headers, got %v", errBadCSV)
	}

	jsonInput := `[{"protocol":"socks5","host":"203.0.113.7","port":1080},{"protocol":"http","host":"203.0.113.8","port":3128}]`
	jStats, err := ParseJSON(jsonInput, "http", false)
	if err != nil || jStats.UniqueCount != 2 {
		t.Fatalf("JSON parse failed: err=%v stats=%+v", err, jStats)
	}
}

func FuzzNormalizeProxyLine(f *testing.F) {
	seeds := []string{
		"http://198.51.100.10:8080",
		"socks5://user:pass@203.0.113.15:1080",
		"127.0.0.1:9050",
		"invalid://[::1]:999999",
		"<script>alert(1)</script>@1.2.3.4:80",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		cand, err := NormalizeProxyLine(input, "http", false)
		if err == nil && cand != nil {
			if cand.Port < 1 || cand.Port > 65535 {
				t.Fatalf("invalid port accepted: %d", cand.Port)
			}
			if cand.Status != model.StatusUnknown {
				t.Fatalf("unexpected status: %s", cand.Status)
			}
		}
	})
}
