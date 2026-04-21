package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"connectrpc.com/connect"
	"github.com/cilium/ebpf"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/urfave/cli/v2"
)

func pluginCommand() *cli.Command {
	return &cli.Command{
		Name:  "plugin",
		Usage: "Manage BPF plugins",
		Subcommands: []*cli.Command{
			{
				Name:  "validate",
				Usage: "Validate a plugin ELF locally (no server contact)",
				Description: "Exit codes: 0=OK, 1=validation failure, 2=file/parse error.\n" +
					"Use in CI to catch contract violations before upload.",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "prog", Required: true, Usage: "Path to compiled BPF ELF object file"},
					&cli.StringFlag{Name: "program", Required: true, Usage: "BPF program function name in the ELF"},
				},
				Action: func(c *cli.Context) error {
					elfPath := c.String("prog")
					programName := c.String("program")

					spec, err := ebpf.LoadCollectionSpec(elfPath)
					if err != nil {
						return cli.Exit(fmt.Errorf("failed to parse BPF ELF %s: %w", elfPath, err), 2)
					}
					if _, err := bpf.ValidatePluginCollection(spec, programName); err != nil {
						return cli.Exit(err, 1)
					}
					fmt.Printf("OK: %s (program=%s) passes plugin contract\n", elfPath, programName)
					return nil
				},
			},
			{
				Name:  "register",
				Usage: "Register a BPF plugin into a tail call slot",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "type", Required: true, Usage: "PROG_ARRAY target: endpoint, headend_v4, headend_v6"},
					&cli.UintFlag{Name: "index", Required: true, Usage: "Plugin slot index (endpoint: 32-63, headend: 16-31)"},
					&cli.StringFlag{Name: "prog", Required: true, Usage: "Path to compiled BPF ELF object file"},
					&cli.StringFlag{Name: "program", Required: true, Usage: "BPF program function name in the ELF (e.g., plugin_counter)"},
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
						Program: c.String("program"),
					}

					_, err = clients.Plugin.PluginRegister(context.Background(), connect.NewRequest(req))
					if err != nil {
						return err
					}

					fmt.Printf("Plugin registered: type=%s index=%d prog=%s program=%s\n",
						req.MapType, req.Index, elfPath, req.Program)
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
			{
				Name:  "list",
				Usage: "List registered plugins",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "type", Usage: "Filter by map type: endpoint, headend_v4, headend_v6"},
					&cli.BoolFlag{Name: "verbose", Aliases: []string{"v"}, Usage: "Show map linkage (shared/owned)"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					req := &v1.PluginListRequest{MapTypeFilter: c.String("type")}
					resp, err := clients.Plugin.PluginList(context.Background(), connect.NewRequest(req))
					if err != nil {
						return err
					}
					tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
					if _, err := fmt.Fprintln(tw, "MAP_TYPE\tSLOT\tPROGRAM\tAUX_TYPE\tREGISTERED"); err != nil {
						return err
					}
					for _, p := range resp.Msg.Plugins {
						aux := "-"
						if p.HasAuxType {
							aux = p.AuxTypeName
							if aux == "" {
								aux = "(anonymous)"
							}
						}
						ts := ""
						if p.RegisteredAt != nil {
							ts = p.RegisteredAt.AsTime().UTC().Format("2006-01-02T15:04:05Z")
						}
						if _, err := fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\n", p.MapType, p.Slot, p.Program, aux, ts); err != nil {
							return err
						}
					}
					if err := tw.Flush(); err != nil {
						return err
					}
					if c.Bool("verbose") {
						for _, p := range resp.Msg.Plugins {
							fmt.Printf("  %s/%d:\n", p.MapType, p.Slot)
							fmt.Printf("    shared_ro: [%s]\n", strings.Join(p.SharedRoNames, ", "))
							fmt.Printf("    shared_rw: [%s]\n", strings.Join(p.SharedRwNames, ", "))
							fmt.Printf("    owned:     [%s]\n", strings.Join(p.OwnedMapNames, ", "))
						}
					}
					return nil
				},
			},
		},
	}
}
