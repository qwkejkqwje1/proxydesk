package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/proxydesk/proxydesk/internal/api"
	"github.com/proxydesk/proxydesk/internal/checker"
	"github.com/proxydesk/proxydesk/internal/config"
	"github.com/proxydesk/proxydesk/internal/diagnostics"
	"github.com/proxydesk/proxydesk/internal/dns"
	"github.com/proxydesk/proxydesk/internal/gateway"
	"github.com/proxydesk/proxydesk/internal/lock"
	"github.com/proxydesk/proxydesk/internal/model"
	"github.com/proxydesk/proxydesk/internal/pools"
	"github.com/proxydesk/proxydesk/internal/scoring"
	"github.com/proxydesk/proxydesk/internal/sources"
	"github.com/proxydesk/proxydesk/internal/storage"
	"github.com/proxydesk/proxydesk/web"
)

func main() {
	flags, err := config.ParseFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка разбора аргументов: %v\n", err)
		os.Exit(2)
	}

	dataDir, err := config.ResolveDataDir(flags, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка определения каталога данных: %v\n", err)
		os.Exit(1)
	}

	cfg, err := config.LoadOrInit(dataDir, flags)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка инициализации конфигурации в %s: %v\n", dataDir, err)
		os.Exit(1)
	}

	// Single-instance check: if another instance is already running on the same data directory,
	// report its URL (and open browser if interactive) and exit cleanly without killing processes.
	instLock, existing, err := lock.Acquire(dataDir, cfg.APIListenAddr)
	if err != nil {
		if errors.Is(err, lock.ErrInstanceAlreadyRunning) && existing != nil {
			fmt.Fprintf(os.Stdout, "ProxyDesk уже запущен (PID %d): %s\n", existing.PID, existing.APIURL)
			if !cfg.NoOpenBrowser {
				_ = openBrowserNonFatal(existing.APIURL)
			}
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "Ошибка блокировки экземпляра: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = instLock.Release() }()

	token, err := api.GenerateSessionToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка генерации токена безопасности: %v\n", err)
		os.Exit(1)
	}

	logger := diagnostics.NewRotatingLogger(dataDir, cfg.Budgets.MaxLogFileBytes, cfg.Budgets.MaxLogFiles, token)
	logger.Log("INFO", "main", fmt.Sprintf("Starting ProxyDesk (portable=%v, data_dir=%s)", cfg.PortableMode, dataDir))

	store, err := storage.Open(dataDir)
	if err != nil {
		logger.Log("ERROR", "storage", fmt.Sprintf("Failed to open SQLite: %v", err))
		fmt.Fprintf(os.Stderr, "Ошибка открытия базы данных SQLite: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = store.Close() }()

	clk := model.RealClock{}
	credStore := model.NewCredentialStore()
	srcMgr := sources.NewManager(store, credStore, logger, clk, time.Now().UnixNano(), cfg.Budgets.MaxSourceBodyBytes)
	chk := checker.NewChecker(cfg, credStore, clk, nil)
	scr := scoring.NewScorer(cfg, store, clk)
	poolSel := pools.NewSelector(clk, time.Now().UnixNano())
	dnsSrv := dns.NewServer(clk, cfg.Budgets.MaxDNSCacheEntries, cfg.EnableDNSQueryLog, nil)
	gw := gateway.NewGateway(cfg, credStore, poolSel, dnsSrv, clk, func(proxyID int, dialErr error) {
		logger.Log("WARN", "gateway", fmt.Sprintf("Upstream proxy id=%d failed during dial: %v", proxyID, dialErr))
	})

	uiFS, err := web.DistFS()
	if err != nil {
		logger.Log("WARN", "ui", fmt.Sprintf("Embedded UI FS error: %v", err))
	}

	apiSrv := api.NewServer(cfg, store, credStore, srcMgr, chk, scr, poolSel, gw, dnsSrv, logger, uiFS, token)

	httpServer := &http.Server{
		Addr:              cfg.APIListenAddr,
		Handler:           apiSrv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	gwHTTPServer := &http.Server{
		Addr:              cfg.HTTPGatewayAddr,
		Handler:           http.HandlerFunc(gw.ServeHTTPProxy),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Log("INFO", "gateway", "Local HTTP CONNECT gateway listening on "+cfg.HTTPGatewayAddr)
		if err := gwHTTPServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Log("ERROR", "gateway", fmt.Sprintf("HTTP gateway error: %v", err))
		}
	}()

	go func() {
		uiURL := "http://" + cfg.APIListenAddr
		fmt.Fprintf(os.Stdout, "ProxyDesk запущен: %s\n", uiURL)
		if !cfg.NoOpenBrowser {
			if err := openBrowserNonFatal(uiURL); err != nil {
				logger.Log("WARN", "browser", fmt.Sprintf("Auto-open browser skipped: %v", err))
			}
		}
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Log("ERROR", "api", fmt.Sprintf("API server error: %v", err))
			stop()
		}
	}()

	<-ctx.Done()
	logger.Log("INFO", "main", "Shutting down gracefully: cancelling active tasks and closing listeners...")
	srcMgr.CancelAll()
	chk.CancelBatch()

	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutCtx)
	_ = gwHTTPServer.Shutdown(shutCtx)
}

// openBrowserNonFatal launches the system default browser on interactive startup.
// Failure to open the browser never crashes or breaks the application.
func openBrowserNonFatal(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
