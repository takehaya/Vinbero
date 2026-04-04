package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/config"
	"github.com/takehaya/vinbero/pkg/logger"
	"github.com/takehaya/vinbero/pkg/server"
	"github.com/takehaya/vinbero/pkg/vinbero"
	"github.com/urfave/cli/v2"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

func main() {
	app := newApp()
	if err := app.Run(os.Args); err != nil {
		log.Fatalf("%+v", err)
	}
}

func newApp() *cli.App {
	return &cli.App{
		Name:    "vinberod",
		Version: fmt.Sprintf("%s, %s, %s, %s", version, commit, date, builtBy),
		Usage:   "High Performance SRv6 Function Subset",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Value:   "/etc/vinbero/vinbero.yaml",
				Usage:   "config file path",
			},
		},
		Action:                 run,
		EnableBashCompletion:   true,
		UseShortOptionHandling: true,
	}
}

func run(cliCtx *cli.Context) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := loadConfig(cliCtx.String("config"))
	if err != nil {
		return err
	}

	lg, cleanup, err := logger.NewLogger(cfg.InternalConfig.Logger)
	if err != nil {
		return fmt.Errorf("initialize logger: %w", err)
	}
	defer func() {
		if err := cleanup(context.Background()); err != nil {
			lg.Warn("failed to cleanup logger", zap.Error(err))
		}
	}()

	vin, err := vinbero.NewVinbero(cfg, lg)
	if err != nil {
		return fmt.Errorf("initialize vinbero: %w", err)
	}
	defer func() { _ = vin.Close() }()

	if err := vin.LoadXDPProgram(); err != nil {
		return fmt.Errorf("load XDP program: %w", err)
	}
	lg.Info("Vinbero XDP program loaded successfully")

	if err := vin.LoadTCProgram(); err != nil {
		return fmt.Errorf("load TC program: %w", err)
	}
	lg.Info("Vinbero TC BUM program loaded successfully")

	// Initialize resource manager (reconcile state before FDB watcher)
	if err := vin.InitResourceManager(); err != nil {
		return fmt.Errorf("init resource manager: %w", err)
	}

	// Start FDB watcher
	if err := vin.StartFDBWatcher(ctx); err != nil {
		return fmt.Errorf("start FDB watcher: %w", err)
	}

	srv := server.NewServer(cfg, vin.GetMapOperations(), vin.GetResourceManager(), vin.GetFDBWatcher(), lg)
	if err := srv.StartAsync(); err != nil {
		return fmt.Errorf("start server: %w", err)
	}

	lg.Info("Vinbero started successfully")

	// Wait for shutdown signal
	<-ctx.Done()
	lg.Info("Received shutdown signal, cleaning up...")

	return shutdown(srv, lg)
}

func loadConfig(path string) (*config.Config, error) {
	if !config.FileExists(path) {
		return nil, fmt.Errorf("config file not found: %s", path)
	}
	cfg, err := config.LoadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	return cfg, nil
}

func shutdown(srv *server.Server, lg *zap.Logger) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		lg.Error("Shutdown error", zap.Error(err))
		return err
	}
	lg.Info("Shutdown completed")
	return nil
}
