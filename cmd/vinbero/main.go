package main

import (
	"fmt"
	"os"

	vinberocli "github.com/takehaya/vinbero/pkg/cli"
)

func main() {
	app := vinberocli.NewApp()
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
