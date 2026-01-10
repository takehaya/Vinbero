package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/takehaya/vinbero/pkg/config"
	"github.com/takehaya/vinbero/pkg/logger"
	"github.com/takehaya/vinbero/pkg/vinbero"
	"github.com/urfave/cli"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

func main() {
	app := newApp(version)
	if err := app.Run(os.Args); err != nil {
		log.Fatalf("%+v", err)
	}
}

func newApp(version string) *cli.App {
	app := cli.NewApp()
	app.Name = "vinbero"
	app.Version = fmt.Sprintf("%s, %s, %s, %s", version, commit, date, builtBy)

	app.Usage = "High Perfomance SRv6 Function Subset"

	app.EnableBashCompletion = true

	// Common flags for the main run command
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "config, cfg",
			Value: "/etc/vinbero/vinbero.yaml",
			Usage: "config path, default is /etc/vinbero/vinbero.yaml",
		},
	}
	app.Action = run
	return app
}

func run(ctx *cli.Context) error {
	configPath := ctx.String("config")

	if !config.FileExists(configPath) {
		return fmt.Errorf("config file not found: %s", configPath)
	}
	c, err := config.LoadFile(configPath)
	if err != nil {
		return fmt.Errorf("load config error: %w", err)
	}

	lg, cleanup, err := logger.NewLogger(c.InternalConfig.Logger)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}

	vin, err := vinbero.NewVinbero(c, lg)
	if err != nil {
		cleanup(context.Background())
		return fmt.Errorf("failed to initialize vinbero: %w", err)
	}
	if err := vin.LoadXDPProgram(); err != nil {
		vin.Close()
		cleanup(context.Background())
		return fmt.Errorf("failed to load XDP program: %w", err)
	}

	lg.Info("Vinbero started successfully")

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	lg.Info("Received shutdown signal, cleaning up...")

	// Create context with 10 second timeout for graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		vin.Close()
		cleanup(shutdownCtx)
		close(done)
	}()

	// Wait for cleanup or timeout
	select {
	case <-done:
		lg.Info("Shutdown completed")
		return nil
	case <-shutdownCtx.Done():
		lg.Error("Shutdown timed out after 10 seconds")
		os.Exit(1)
		return nil
	}
}
