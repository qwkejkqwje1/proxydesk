package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveDataDirPriority(t *testing.T) {
	fakeExec := filepath.Join(t.TempDir(), "bin", "proxydesk.exe")

	// 1. --portable uses executable directory, not cwd
	flagsPortable := CLIFlags{Portable: true}
	gotPortable, err := ResolveDataDir(flagsPortable, fakeExec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantPortable := filepath.Join(filepath.Dir(fakeExec), "data")
	if gotPortable != wantPortable {
		t.Fatalf("got %q, want %q", gotPortable, wantPortable)
	}

	// 2. --data-dir overrides --portable
	explicitDir := filepath.Join(t.TempDir(), "custom-data")
	flagsExplicit := CLIFlags{Portable: true, DataDir: explicitDir}
	gotExplicit, err := ResolveDataDir(flagsExplicit, fakeExec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotExplicit != explicitDir {
		t.Fatalf("got %q, want %q", gotExplicit, explicitDir)
	}
}

func TestValidateRejectsNonLoopbackAndIncompatibleVersion(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIListenAddr = "0.0.0.0:18443"
	if err := cfg.Validate(); !errors.Is(err, ErrNonLoopbackAddress) {
		t.Fatalf("expected ErrNonLoopbackAddress, got %v", err)
	}

	cfg2 := DefaultConfig()
	cfg2.Version = 999
	if err := cfg2.Validate(); !errors.Is(err, ErrUnsupportedConfigVersion) {
		t.Fatalf("expected ErrUnsupportedConfigVersion, got %v", err)
	}
}

func TestLoadOrInitDetectsIncompatibleVersionOnDisk(t *testing.T) {
	dir := t.TempDir()
	badCfg := `{"version": 42, "api_listen_addr": "127.0.0.1:18443"}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(badCfg), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadOrInit(dir, CLIFlags{})
	if !errors.Is(err, ErrUnsupportedConfigVersion) {
		t.Fatalf("expected ErrUnsupportedConfigVersion, got %v", err)
	}
}
