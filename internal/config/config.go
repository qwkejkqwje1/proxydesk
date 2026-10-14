package config

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const CurrentConfigVersion = 1

var (
	ErrUnsupportedConfigVersion = errors.New("unsupported configuration version")
	ErrDataDirNotWritable       = errors.New("data directory is not writable")
	ErrNonLoopbackAddress       = errors.New("listener address must be loopback (127.0.0.1 or ::1)")
	ErrInvalidBudget            = errors.New("invalid resource budget parameter")
)

type CLIFlags struct {
	Portable      bool
	DataDir       string
	NoOpenBrowser bool
	ListenAddr    string
}

type CheckTargetConfig struct {
	Name           string `json:"name"`
	URL            string `json:"url"`
	ExpectStatus   int    `json:"expect_status"`
	ExtractsExitIP bool   `json:"extracts_exit_ip"`
	Enabled        bool   `json:"enabled"`
}

type ScoringWeights struct {
	Reliability float64 `json:"reliability"`
	Latency     float64 `json:"latency"`
	Stability   float64 `json:"stability"`
	Freshness   float64 `json:"freshness"`
}

type ResourceBudgets struct {
	MaxSourceBodyBytes      int64 `json:"max_source_body_bytes"`
	MaxCheckBodyBytes       int64 `json:"max_check_body_bytes"`
	MaxConcurrentChecks     int   `json:"max_concurrent_checks"`
	MaxCheckQueue           int   `json:"max_check_queue"`
	MaxHistoryPerProxy      int   `json:"max_history_per_proxy"`
	HistoryRetentionDays    int   `json:"history_retention_days"`
	MaxDNSCacheEntries      int   `json:"max_dns_cache_entries"`
	MaxGatewayConns         int   `json:"max_gateway_conns"`
	MaxActiveConnRing       int   `json:"max_active_conn_ring"`
	MaxSSEClients           int   `json:"max_sse_clients"`
	MaxLogFileBytes         int64 `json:"max_log_file_bytes"`
	MaxLogFiles             int   `json:"max_log_files"`
	CheckConnectTimeoutMs   int   `json:"check_connect_timeout_ms"`
	CheckHandshakeTimeoutMs int   `json:"check_handshake_timeout_ms"`
	CheckTotalTimeoutMs     int   `json:"check_total_timeout_ms"`
}

type Config struct {
	Version              int                 `json:"version"`
	APIListenAddr        string              `json:"api_listen_addr"`
	HTTPGatewayAddr      string              `json:"http_gateway_addr"`
	SOCKS5GatewayAddr    string              `json:"socks5_gateway_addr"`
	DNSListenAddr        string              `json:"dns_listen_addr"`
	DNSResolutionMode    string              `json:"dns_resolution_mode"` // "remote_dns" or "managed_dns"
	IPv6Policy           string              `json:"ipv6_policy"`         // "ipv4_only", "prefer_ipv4", "dual_stack"
	StrictProxyOnly      bool                `json:"strict_proxy_only"`
	AllowDirectFallback  bool                `json:"allow_direct_fallback"`
	EnableDirectDiag     bool                `json:"enable_direct_diag"`
	LogDomains           bool                `json:"log_domains"`
	EnableDNSQueryLog    bool                `json:"enable_dns_query_log"`
	CapabilityTTLMinutes int                 `json:"capability_ttl_minutes"`
	HysteresisDelta      float64             `json:"hysteresis_delta"`
	Weights              ScoringWeights      `json:"weights"`
	Budgets              ResourceBudgets     `json:"budgets"`
	CheckTargets         []CheckTargetConfig `json:"check_targets"`

	// Runtime-resolved fields (not persisted in config.json)
	ResolvedDataDir string `json:"-"`
	PortableMode    bool   `json:"-"`
	NoOpenBrowser   bool   `json:"-"`
}

func DefaultConfig() Config {
	return Config{
		Version:              CurrentConfigVersion,
		APIListenAddr:        "127.0.0.1:18443",
		HTTPGatewayAddr:      "127.0.0.1:18080",
		SOCKS5GatewayAddr:    "127.0.0.1:18081",
		DNSListenAddr:        "127.0.0.1:15353",
		DNSResolutionMode:    "remote_dns",
		IPv6Policy:           "prefer_ipv4",
		StrictProxyOnly:      true,
		AllowDirectFallback:  false,
		EnableDirectDiag:     false,
		LogDomains:           false,
		EnableDNSQueryLog:    false,
		CapabilityTTLMinutes: 30,
		HysteresisDelta:      5.0,
		Weights: ScoringWeights{
			Reliability: 0.45,
			Latency:     0.25,
			Stability:   0.15,
			Freshness:   0.15,
		},
		Budgets: ResourceBudgets{
			MaxSourceBodyBytes:      10 * 1024 * 1024, // 10 MiB
			MaxCheckBodyBytes:       64 * 1024,        // 64 KiB
			MaxConcurrentChecks:     64,
			MaxCheckQueue:           10000,
			MaxHistoryPerProxy:      50,
			HistoryRetentionDays:    14,
			MaxDNSCacheEntries:      4096,
			MaxGatewayConns:         512,
			MaxActiveConnRing:       200,
			MaxSSEClients:           8,
			MaxLogFileBytes:         5 * 1024 * 1024, // 5 MiB
			MaxLogFiles:             3,
			CheckConnectTimeoutMs:   4000,
			CheckHandshakeTimeoutMs: 4000,
			CheckTotalTimeoutMs:     10000,
		},
		CheckTargets: []CheckTargetConfig{
			{
				Name:           "Cloudflare Trace",
				URL:            "https://1.1.1.1/cdn-cgi/trace",
				ExpectStatus:   200,
				ExtractsExitIP: true,
				Enabled:        true,
			},
			{
				Name:           "AWS CheckIP",
				URL:            "https://checkip.amazonaws.com",
				ExpectStatus:   200,
				ExtractsExitIP: true,
				Enabled:        true,
			},
			{
				Name:           "Icanhazip IPv4",
				URL:            "https://ipv4.icanhazip.com",
				ExpectStatus:   200,
				ExtractsExitIP: true,
				Enabled:        true,
			},
		},
	}
}

func ParseFlags(args []string) (CLIFlags, error) {
	var flags CLIFlags
	fs := flag.NewFlagSet("proxydesk", flag.ContinueOnError)
	fs.BoolVar(&flags.Portable, "portable", false, "Хранить данные в папке data рядом с исполняемым файлом")
	fs.StringVar(&flags.DataDir, "data-dir", "", "Явный путь к каталогу данных (имеет приоритет над --portable)")
	fs.BoolVar(&flags.NoOpenBrowser, "no-open-browser", false, "Не открывать браузер автоматически при запуске")
	fs.StringVar(&flags.ListenAddr, "listen", "", "Адрес локального API/UI (по умолчанию 127.0.0.1:18443)")
	if err := fs.Parse(args); err != nil {
		return flags, err
	}
	return flags, nil
}

// ResolveDataDir determines the data directory strictly following ADR-002:
// 1. Explicit --data-dir takes highest priority.
// 2. --portable resolves relative to the executable's directory (never os.Getwd()).
// 3. Otherwise uses OS user local app data directory.
func ResolveDataDir(flags CLIFlags, executablePath string) (string, error) {
	if strings.TrimSpace(flags.DataDir) != "" {
		abs, err := filepath.Abs(flags.DataDir)
		if err != nil {
			return "", fmt.Errorf("resolve --data-dir: %w", err)
		}
		return abs, nil
	}
	if flags.Portable {
		if executablePath == "" {
			var err error
			executablePath, err = os.Executable()
			if err != nil {
				return "", fmt.Errorf("locate executable for --portable: %w", err)
			}
		}
		execDir := filepath.Dir(executablePath)
		return filepath.Join(execDir, "data"), nil
	}
	if runtime.GOOS == "windows" {
		if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
			return filepath.Join(localAppData, "ProxyDesk"), nil
		}
	}
	userCfgDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate user config dir: %w", err)
	}
	return filepath.Join(userCfgDir, "ProxyDesk"), nil
}

// EnsureWritableDataDir creates the directory if needed and verifies write access
// without silently falling back to another folder.
func EnsureWritableDataDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("%w: cannot create directory %s: %v", ErrDataDirNotWritable, dir, err)
	}
	probeFile := filepath.Join(dir, ".proxydesk_write_probe")
	f, err := os.OpenFile(probeFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("%w: cannot write to directory %s: %v", ErrDataDirNotWritable, dir, err)
	}
	_, writeErr := f.Write([]byte("ok"))
	closeErr := f.Close()
	_ = os.Remove(probeFile)
	if writeErr != nil || closeErr != nil {
		return fmt.Errorf("%w: probe write failed in %s", ErrDataDirNotWritable, dir)
	}
	return nil
}

func ValidateLoopbackAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%w: invalid host:port %q", ErrNonLoopbackAddress, addr)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%w: %q is not loopback", ErrNonLoopbackAddress, addr)
	}
	return nil
}

func (c *Config) Validate() error {
	if c.Version != CurrentConfigVersion {
		return fmt.Errorf("%w: got version %d, expected %d", ErrUnsupportedConfigVersion, c.Version, CurrentConfigVersion)
	}
	for _, addr := range []string{c.APIListenAddr, c.HTTPGatewayAddr, c.SOCKS5GatewayAddr, c.DNSListenAddr} {
		if err := ValidateLoopbackAddr(addr); err != nil {
			return err
		}
	}
	if c.DNSResolutionMode != "remote_dns" && c.DNSResolutionMode != "managed_dns" {
		return errors.New("dns_resolution_mode must be 'remote_dns' or 'managed_dns'")
	}
	if c.IPv6Policy != "ipv4_only" && c.IPv6Policy != "prefer_ipv4" && c.IPv6Policy != "dual_stack" {
		return errors.New("ipv6_policy must be 'ipv4_only', 'prefer_ipv4', or 'dual_stack'")
	}
	if c.Budgets.MaxSourceBodyBytes < 1024 || c.Budgets.MaxSourceBodyBytes > 100*1024*1024 {
		return fmt.Errorf("%w: max_source_body_bytes out of bounds", ErrInvalidBudget)
	}
	if c.Budgets.MaxCheckBodyBytes < 512 || c.Budgets.MaxCheckBodyBytes > 10*1024*1024 {
		return fmt.Errorf("%w: max_check_body_bytes out of bounds", ErrInvalidBudget)
	}
	if c.Budgets.MaxConcurrentChecks < 1 || c.Budgets.MaxConcurrentChecks > 512 {
		return fmt.Errorf("%w: max_concurrent_checks must be 1..512", ErrInvalidBudget)
	}
	if c.Budgets.MaxGatewayConns < 1 || c.Budgets.MaxGatewayConns > 4096 {
		return fmt.Errorf("%w: max_gateway_conns must be 1..4096", ErrInvalidBudget)
	}
	if c.Budgets.MaxSSEClients < 1 || c.Budgets.MaxSSEClients > 64 {
		return fmt.Errorf("%w: max_sse_clients must be 1..64", ErrInvalidBudget)
	}
	return nil
}

func LoadOrInit(dataDir string, flags CLIFlags) (*Config, error) {
	if err := EnsureWritableDataDir(dataDir); err != nil {
		return nil, err
	}
	cfgPath := filepath.Join(dataDir, "config.json")
	cfg := DefaultConfig()

	if raw, err := os.ReadFile(cfgPath); err == nil {
		var versionProbe struct {
			Version int `json:"version"`
		}
		if err := json.Unmarshal(raw, &versionProbe); err != nil {
			return nil, fmt.Errorf("invalid config.json syntax: %w", err)
		}
		if versionProbe.Version != CurrentConfigVersion {
			return nil, fmt.Errorf("%w: found version %d in %s (expected %d)", ErrUnsupportedConfigVersion, versionProbe.Version, cfgPath, CurrentConfigVersion)
		}
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, fmt.Errorf("parse config.json: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read config.json: %w", err)
	}

	if flags.ListenAddr != "" {
		cfg.APIListenAddr = flags.ListenAddr
	}
	cfg.ResolvedDataDir = dataDir
	cfg.PortableMode = flags.Portable
	cfg.NoOpenBrowser = flags.NoOpenBrowser

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := cfg.Save(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) Save() error {
	if c.ResolvedDataDir == "" {
		return errors.New("resolved data dir is empty")
	}
	cfgPath := filepath.Join(c.ResolvedDataDir, "config.json")
	tmpPath := cfgPath + ".tmp"
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpPath, cfgPath)
}
