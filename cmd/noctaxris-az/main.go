package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/audit"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/server"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "noctaxris-az: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 0 && args[0] == "healthcheck" {
		return runHealthcheck()
	}

	cfg, err := config.LoadFromEnv()
	if err != nil {
		return err
	}
	if cfg.RootClientID == "" || cfg.RootAccessToken == "" {
		return fmt.Errorf("set NOCTAXRIS_AZ_ROOT_CLIENT_ID and NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN")
	}
	if config.ExampleRootCredentials(cfg.RootClientID, cfg.RootAccessToken) && !config.ListenIsLoopback(cfg.ListenAddr) {
		return fmt.Errorf("example root credentials refused on non-loopback listen %q; set unique NOCTAXRIS_AZ_ROOT_CLIENT_ID and NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN (Compose binds 0.0.0.0 inside the container while host publish stays 127.0.0.1)", cfg.ListenAddr)
	}

	if err := os.MkdirAll(cfg.DataRoot, 0o700); err != nil {
		return fmt.Errorf("create data root: %w", err)
	}

	masterKeyPath, err := store.ResolveMasterKeyPath(cfg.MasterKeyPath, cfg.DataRoot)
	if err != nil {
		return fmt.Errorf("master key path: %w", err)
	}
	master, err := store.LoadOrCreateMasterKey(masterKeyPath)
	if err != nil {
		return fmt.Errorf("load master key: %w", err)
	}

	st, err := store.Open(cfg.DataRoot, master)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	if err := st.EnsureRoot(cfg.TenantID, cfg.SubscriptionID, cfg.RootClientID); err != nil {
		return fmt.Errorf("ensure root: %w", err)
	}

	aud, err := audit.NewWriter(filepath.Join(cfg.DataRoot, "audit"))
	if err != nil {
		return fmt.Errorf("open audit writer: %w", err)
	}
	defer aud.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := server.New(cfg, st, aud)
	if err := srv.StartAMQP(ctx); err != nil {
		return fmt.Errorf("start amqp: %w", err)
	}
	return srv.ListenAndServeContext(ctx)
}

func runHealthcheck() error {
	addr := strings.TrimSpace(os.Getenv("NOCTAXRIS_AZ_LISTEN"))
	if addr == "" {
		addr = config.DefaultListenAddr
	}
	if strings.HasPrefix(addr, "0.0.0.0:") {
		addr = "127.0.0.1:" + strings.TrimPrefix(addr, "0.0.0.0:")
	}
	url := "http://" + addr + "/_noctaxris-az/ready"
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck: status %d", resp.StatusCode)
	}
	return nil
}
