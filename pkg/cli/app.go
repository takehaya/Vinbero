package cli

import (
	"fmt"
	"os"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/completion"
	"github.com/urfave/cli/v2"
)

const clientsKey = "vinbero-clients"

func NewApp() *cli.App {
	return &cli.App{
		Name:                 "vinbero",
		Usage:                "Vinbero CLI - SRv6 control plane client",
		EnableBashCompletion: true,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "server",
				Aliases: []string{"s"},
				Value:   "http://localhost:8080",
				Usage:   "Vinbero server address",
				EnvVars: []string{"VINBERO_SERVER"},
			},
			&cli.BoolFlag{
				Name:  "json",
				Usage: "Output in JSON format",
			},
		},
		Before: func(c *cli.Context) error {
			clients := NewClients(c.String("server"))
			c.App.Metadata[clientsKey] = clients
			return nil
		},
		Commands: []*cli.Command{
			sidFunctionCommand(),
			headendV4Command(),
			headendV6Command(),
			headendL2Command(),
			bdPeerCommand(),
			bridgeCommand(),
			vrfCommand(),
			dmacCommand(),
			completion.Command(),
		},
	}
}

func clientsFromContext(c *cli.Context) *Clients {
	v, ok := c.App.Metadata[clientsKey]
	if !ok {
		panic("vinbero: clients not initialized (Before hook missing?)")
	}
	return v.(*Clients)
}

func printOperationResult[T any](created []T, errors []*v1.OperationError, resourceName string) error {
	if len(created) > 0 {
		fmt.Printf("%s created: %d\n", resourceName, len(created))
	}
	for _, e := range errors {
		fmt.Fprintf(os.Stderr, "Error [%s]: %s\n", e.TriggerPrefix, e.Reason)
	}
	if len(errors) > 0 {
		return fmt.Errorf("%d error(s) occurred", len(errors))
	}
	return nil
}
