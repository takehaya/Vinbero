package cli

import (
	"context"
	"fmt"
	"os"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/urfave/cli/v2"
)

func pluginCommand() *cli.Command {
	return &cli.Command{
		Name:  "plugin",
		Usage: "Manage BPF plugins",
		Subcommands: []*cli.Command{
			{
				Name:  "register",
				Usage: "Register a BPF plugin into a tail call slot",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "type", Required: true, Usage: "PROG_ARRAY target: endpoint, headend_v4, headend_v6"},
					&cli.UintFlag{Name: "index", Required: true, Usage: "Plugin slot index (endpoint: 32-63, headend: 16-31)"},
					&cli.StringFlag{Name: "prog", Required: true, Usage: "Path to compiled BPF ELF object file"},
					&cli.StringFlag{Name: "section", Value: "xdp", Usage: "BPF program section name in the ELF"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)

					elfPath := c.String("prog")
					elfBytes, err := os.ReadFile(elfPath)
					if err != nil {
						return fmt.Errorf("failed to read BPF ELF file %s: %w", elfPath, err)
					}

					req := &v1.PluginRegisterRequest{
						MapType: c.String("type"),
						Index:   uint32(c.Uint("index")),
						BpfElf:  elfBytes,
						Section: c.String("section"),
					}

					_, err = clients.Plugin.PluginRegister(context.Background(), connect.NewRequest(req))
					if err != nil {
						return err
					}

					fmt.Printf("Plugin registered: type=%s index=%d prog=%s section=%s\n",
						req.MapType, req.Index, elfPath, req.Section)
					return nil
				},
			},
			{
				Name:  "unregister",
				Usage: "Unregister a BPF plugin from a tail call slot",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "type", Required: true, Usage: "PROG_ARRAY target: endpoint, headend_v4, headend_v6"},
					&cli.UintFlag{Name: "index", Required: true, Usage: "Plugin slot index to clear"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)

					req := &v1.PluginUnregisterRequest{
						MapType: c.String("type"),
						Index:   uint32(c.Uint("index")),
					}

					_, err := clients.Plugin.PluginUnregister(context.Background(), connect.NewRequest(req))
					if err != nil {
						return err
					}

					fmt.Printf("Plugin unregistered: type=%s index=%d\n", req.MapType, req.Index)
					return nil
				},
			},
		},
	}
}
