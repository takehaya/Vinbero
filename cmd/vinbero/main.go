package main

import (
	"fmt"
	"os"

	vinberocli "github.com/takehaya/vinbero/pkg/cli"
)

// goreleaser injects these via the default ldflags
// (-X main.version / main.commit / main.date / main.builtBy). They mirror the
// vinberod daemon so `vinbero --version` reports the real release version
// instead of "dev".
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

func main() {
	vinberocli.SetVersion(fmt.Sprintf("%s, %s, %s, %s", version, commit, date, builtBy))
	app := vinberocli.NewApp()
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
