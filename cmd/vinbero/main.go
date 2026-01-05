package main

import (
	"fmt"
	"log"
	"os"

	"github.com/takehaya/vinbero/pkg/config"
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

	_ = c // Use c or remove if not needed

	return nil
}
