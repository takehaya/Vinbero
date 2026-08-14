package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"connectrpc.com/connect"
	"github.com/urfave/cli/v2"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

// cplaneSubcommand builds `vbctl plugin cplane`, which manages the
// WebAssembly control-plane half of a plugin.
//
// It is a sibling of the data-plane commands rather than an extension of
// them: the two halves are different artifacts with different lifecycles,
// and an operator upgrading a module should not have to restate the eBPF
// slot it has nothing to do with.
func cplaneSubcommand() *cli.Command {
	return &cli.Command{
		Name:  "cplane",
		Usage: "Manage control-plane (WebAssembly) plugins",
		Subcommands: []*cli.Command{
			{
				Name:  "register",
				Usage: "Register or upgrade a control-plane plugin",
				Description: "Registering a name that is already running upgrades it in place: the\n" +
					"state the running instance wrote is kept and the new module reconciles\n" +
					"over it, so the data plane is not emptied between the two.",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Required: true, Usage: "Plugin name; becomes the owner tag its writes carry"},
					&cli.StringFlag{Name: "wasm", Required: true, Usage: "Path to the WebAssembly module"},
					&cli.StringFlag{Name: "config", Usage: "Path to the operator config blob handed to the module (optional)"},
					&cli.StringSliceFlag{Name: "family", Usage: "BGP family to deliver (repeatable); omit for every family"},
					&cli.UintFlag{
						Name: "tick-ms",
						Usage: "Drive the plugin's periodic callback every N milliseconds; " +
							"omit to leave it undriven, which suits a purely event-driven plugin",
					},
					&cli.StringSliceFlag{
						Name: "behavior",
						Usage: "SRv6 endpoint behavior codepoint this plugin claims (repeatable, decimal or 0x-prefixed). " +
							"Routes naming one are withheld from vinbero's own appliers",
					},
				},
				Action: func(c *cli.Context) error {
					wasm, err := os.ReadFile(c.String("wasm"))
					if err != nil {
						return fmt.Errorf("read module: %w", err)
					}
					var config []byte
					if path := c.String("config"); path != "" {
						config, err = os.ReadFile(path)
						if err != nil {
							return fmt.Errorf("read config: %w", err)
						}
					}
					behaviors, err := parseBehaviorFlags(c.StringSlice("behavior"))
					if err != nil {
						return err
					}
					clients := clientsFromContext(c)
					resp, err := clients.Plugin.CplanePluginRegister(c.Context,
						connect.NewRequest(&v1.CplanePluginRegisterRequest{
							Name:              c.String("name"),
							Wasm:              wasm,
							Config:            config,
							Families:          c.StringSlice("family"),
							EndpointBehaviors: behaviors,
							TickIntervalMs:    uint32(c.Uint("tick-ms")),
						}))
					if err != nil {
						return err
					}
					verb := "Registered"
					if resp.Msg.GetReplaced() {
						verb = "Upgraded"
					}
					fmt.Printf("%s control-plane plugin %q\n", verb, c.String("name"))
					return nil
				},
			},
			{
				Name:  "unregister",
				Usage: "Stop a control-plane plugin and remove the state it owns",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Required: true, Usage: "Plugin name"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					_, err := clients.Plugin.CplanePluginUnregister(c.Context,
						connect.NewRequest(&v1.CplanePluginUnregisterRequest{Name: c.String("name")}))
					if err != nil {
						return err
					}
					fmt.Printf("Unregistered control-plane plugin %q\n", c.String("name"))
					return nil
				},
			},
			{
				Name:  "list",
				Usage: "List running control-plane plugins",
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Plugin.CplanePluginList(c.Context,
						connect.NewRequest(&v1.CplanePluginListRequest{}))
					if err != nil {
						return err
					}
					plugins := resp.Msg.GetPlugins()
					if len(plugins) == 0 {
						fmt.Println("No control-plane plugins registered")
						return nil
					}
					w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
					if _, err := fmt.Fprintln(w, "NAME"); err != nil {
						return err
					}
					for _, p := range plugins {
						if _, err := fmt.Fprintf(w, "%s\n", p.GetName()); err != nil {
							return err
						}
					}
					return w.Flush()
				},
			},
		},
	}
}

// parseBehaviorFlags accepts decimal or 0x-prefixed codepoints. A behavior
// is conventionally written in hex (RFC 8986 numbers them that way), and
// silently reading 0x0013 as decimal 13 would claim the wrong one.
func parseBehaviorFlags(values []string) ([]uint32, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make([]uint32, 0, len(values))
	for _, v := range values {
		text := strings.TrimSpace(v)
		base := 10
		if lower := strings.ToLower(text); strings.HasPrefix(lower, "0x") {
			text = text[2:]
			base = 16
		}
		n, err := strconv.ParseUint(text, base, 16)
		if err != nil {
			return nil, fmt.Errorf("endpoint behavior %q: %w", v, err)
		}
		out = append(out, uint32(n))
	}
	return out, nil
}
