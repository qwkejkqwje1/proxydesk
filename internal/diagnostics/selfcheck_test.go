package diagnostics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInvariant_NoSystemMutationCallsInCodebase verifies INV-09:
// The application must not modify OS-level DNS, WinINET registry, WFP, routes, or services.
func TestInvariant_NoSystemMutationCallsInCodebase(t *testing.T) {
	forbiddenTokens := []string{
		"InternetSetOption",
		"CurrentVersion\\Internet Settings",
		"FwpmEngineOpen",
		"FwpmFilterAdd",
		"WinDivertOpen",
		"netsh ",
		"Set-DnsClientServerAddress",
		"sc.exe",
		"CreateServiceW",
	}

	root := filepath.Join("..", "..")
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == "docs" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "selfcheck_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		content := string(data)
		for _, tok := range forbiddenTokens {
			if strings.Contains(content, tok) {
				t.Errorf("INV-09 violation: forbidden system mutation API %q found in %s", tok, path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk codebase: %v", err)
	}
}
