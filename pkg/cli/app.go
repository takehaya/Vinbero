package cli

import (
	"fmt"
	"os"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/completion"
	"github.com/urfave/cli/v2"
)

const clientsKey = "vinbero-clients"

var (
	version = "dev"
)

func SetVersion(v string) {
	version = v
}

func NewApp() *cli.App {
	return &cli.App{
		Name:                 "vinbero",
		Version:              version,
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
			esCommand(),
			vrfCommand(),
			locatorCommand(),
			vrfBgpCommand(),
			bgpCommand(),
			srPolicyCommand(),
			mupCommand(),
			fdbCommand(),
			vlanTableCommand(),
			statsCommand(),
			pluginCommand(),
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

// printOperationResult reports a batch RPC result. verb names the action
// for the success line and defaults to "created"; advertise / withdraw
// style commands pass their own ("advertised", "withdrawn", ...).
func printOperationResult[T any](created []T, errors []*v1.OperationError, resourceName string, verb ...string) error {
	action := "created"
	if len(verb) > 0 {
		action = verb[0]
	}
	if len(created) > 0 {
		fmt.Printf("%s %s: %d\n", resourceName, action, len(created))
	}
	for _, e := range errors {
		fmt.Fprintf(os.Stderr, "Error [%s]: %s\n", e.TriggerPrefix, e.Reason)
	}
	if len(errors) > 0 {
		return fmt.Errorf("%d error(s) occurred", len(errors))
	}
	return nil
}

// reportSingle prints the result of a single-item create/update/delete: success
// iff no per-item error came back. Each such CLI mutation submits exactly one
// item, so a 0- or 1-element ok slice drives printOperationResult's count.
func reportSingle(errs []*v1.OperationError, resourceName, verb string) error {
	var ok []struct{}
	if len(errs) == 0 {
		ok = []struct{}{{}}
	}
	return printOperationResult(ok, errs, resourceName, verb)
}
