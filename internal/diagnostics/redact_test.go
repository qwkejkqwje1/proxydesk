package diagnostics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInvariant_SecretsNeverLeakInLogsOrExport(t *testing.T) {
	dir := t.TempDir()
	apiToken := "secret-session-token-987654321"
	logger := NewRotatingLogger(dir, 1024, 3, apiToken)

	logger.Log("INFO", "sources", "Imported socks5://alice:SuperSecretPass123@198.51.100.10:1080 with X-ProxyDesk-Token: "+apiToken)
	logger.Log("WARN", "gateway", "Upstream auth failed for user1:MyPass99@203.0.113.5:8080 Proxy-Authorization: Basic dXNlcjE6TXlQYXNzOTk=")

	entries := logger.Recent(10)
	for _, e := range entries {
		if strings.Contains(e.Message, "SuperSecretPass123") ||
			strings.Contains(e.Message, "MyPass99") ||
			strings.Contains(e.Message, apiToken) ||
			strings.Contains(e.Message, "dXNlcjE6TXlQYXNzOTk=") {
			t.Fatalf("secret leaked in memory log ring: %s", e.Message)
		}
	}

	diskBytes, err := os.ReadFile(filepath.Join(dir, "proxydesk.log"))
	if err != nil {
		t.Fatal(err)
	}
	diskStr := string(diskBytes)
	if strings.Contains(diskStr, "SuperSecretPass123") || strings.Contains(diskStr, apiToken) {
		t.Fatalf("secret leaked to disk log: %s", diskStr)
	}
}
