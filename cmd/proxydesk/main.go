package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/proxydesk/proxydesk/internal/api"
	"github.com/proxydesk/proxydesk/internal/app"
	"github.com/proxydesk/proxydesk/internal/config"
	"github.com/proxydesk/proxydesk/internal/lock"
	"github.com/proxydesk/proxydesk/internal/model"
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

	store, err := storage.Open(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка открытия базы данных SQLite: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = store.Close() }()

	application := app.New(cfg, store, model.RealClock{}, nil, token)
	uiFS, err := web.DistFS()
	if err != nil {
		application.Logger.Log("WARN", "ui", fmt.Sprintf("Embedded UI FS error: %v", err))
	}

	apiSrv := api.NewServerWithApp(application, uiFS, token)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := application.Start(ctx, apiSrv.Handler(), 15*time.Second); err != nil {
		application.Logger.Log("ERROR", "main", fmt.Sprintf("Startup failed: %v", err))
		fmt.Fprintf(os.Stderr, "Ошибка запуска ProxyDesk: %v\n", err)
		os.Exit(1)
	}

	lState := application.ListenerState()
	uiURL := "http://" + lState.APIBoundAddr
	fmt.Fprintf(os.Stdout, "ProxyDesk запущен: %s (HTTP GW: %s, SOCKS5 GW: %s, DNS UDP: %s)\n",
		uiURL, lState.HTTPGatewayBoundAddr, lState.SOCKS5GatewayBoundAddr, lState.DNSUDPBoundAddr)
	for comp, bErr := range lState.BindErrors {
		fmt.Fprintf(os.Stderr, "Предупреждение: не удалось занять порт для %s: %s\n", comp, bErr)
	}

	if !cfg.NoOpenBrowser {
		if err := openBrowserNonFatal(uiURL); err != nil {
			application.Logger.Log("WARN", "browser", fmt.Sprintf("Auto-open browser skipped: %v", err))
		}
	}

	<-ctx.Done()
	application.Logger.Log("INFO", "main", "Shutting down gracefully...")
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = application.Shutdown(shutCtx)
}

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
