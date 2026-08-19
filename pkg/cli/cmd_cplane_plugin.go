package cli

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

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
					&cli.StringSliceFlag{
						Name: "capability",
						Usage: "What the plugin may do (repeatable): headend, advertise, local_sid. " +
							"Omit to run it able only to observe and to log",
					},
					&cli.StringSliceFlag{
						Name: "locator",
						Usage: "Locator the plugin may allocate local SIDs from (repeatable). " +
							"It also bounds the IPv6 unicast prefixes it may advertise",
					},
					&cli.StringSliceFlag{
						Name: "vrf",
						Usage: "VRF the plugin may originate VPN routes into (repeatable). " +
							"The route distinguisher and route targets come from that VRF's binding",
					},
					&cli.StringSliceFlag{
						Name: "headend-prefix",
						Usage: "Prefix the plugin may install headend entries inside (repeatable, CIDR). " +
							"The headend maps are keyed on the destination alone, so this is the only " +
							"thing holding a plugin off another writer's traffic",
					},
					&cli.UintSliceFlag{
						Name:  "headend-slot",
						Usage: "Headend PROG_ARRAY slot this plugin's data-plane half occupies (repeatable, 16-31)",
					},
					&cli.UintSliceFlag{
						Name:  "endpoint-slot",
						Usage: "Endpoint PROG_ARRAY slot this plugin's data-plane half occupies (repeatable, 32-63)",
					},
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
					headendSlots, err := uintSliceToUint32("headend-slot", c.UintSlice("headend-slot"))
					if err != nil {
						return err
					}
					endpointSlots, err := uintSliceToUint32("endpoint-slot", c.UintSlice("endpoint-slot"))
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
							Capabilities:      c.StringSlice("capability"),
							TickIntervalMs:    uint32(c.Uint("tick-ms")),
							Scope: &v1.CplanePluginScope{
								Locators:        c.StringSlice("locator"),
								Vrfs:            c.StringSlice("vrf"),
								HeadendPrefixes: c.StringSlice("headend-prefix"),
								HeadendSlots:    headendSlots,
								EndpointSlots:   endpointSlots,
							},
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
				Name:  "stats",
				Usage: "Report what each plugin is doing and holding",
				Description: "A sandboxed plugin is otherwise unobservable: one that has fallen\n" +
					"behind, one restarting in a loop and one with nothing to do all look\n" +
					"the same from outside. DROPPED, RESTARTS and QUARANTINED are what tell\n" +
					"them apart; PENDING counts declarations stuck on something that does\n" +
					"not exist yet, and SINCE is when the running instance started -- a\n" +
					"plugin restarting in a loop is one whose SINCE keeps moving. The last\n" +
					"columns show what it owns against its quota.\n\n" +
					"Plugins the store held that would not start are listed separately:\n" +
					"they are not running, but the daemon still holds their state and the\n" +
					"behaviors claimed on their behalf, so routes carrying those reach\n" +
					"nothing. Use 'forget' once you have decided one is not coming back.",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Usage: "Report one plugin instead of all of them"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Plugin.CplanePluginStats(c.Context,
						connect.NewRequest(&v1.CplanePluginStatsRequest{Name: c.String("name")}))
					if err != nil {
						return err
					}
					plugins := resp.Msg.GetPlugins()
					unrestored := resp.Msg.GetUnrestored()
					if len(plugins) == 0 && len(unrestored) == 0 {
						fmt.Println("No control-plane plugins registered")
						return nil
					}
					w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
					if len(plugins) > 0 {
						if _, err := fmt.Fprintln(w,
							"NAME\tCAPABILITIES\tBEHAVIORS\tSTATE\tSINCE\tDROPPED\tRESTARTS\tQUARANTINED\tSNAPSHOTS\tPENDING\tHEADEND\tADVERTISED\tSIDS"); err != nil {
							return err
						}
					}
					for _, p := range plugins {
						state := "running"
						if p.GetDead() {
							// Its state is still installed; it is simply
							// no longer being fed.
							state = "stopped"
						}
						caps := strings.Join(p.GetCapabilities(), ",")
						if caps == "" {
							caps = "-"
						}
						if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d/%d\t%d/%d\t%d/%d\n",
							p.GetName(), caps, formatBehaviors(p.GetEndpointBehaviors()), state,
							formatSince(p.GetSince().AsTime(), p.GetSince() != nil),
							p.GetDroppedEvents(), p.GetRestarts(), p.GetQuarantinedEvents(), p.GetSnapshots(),
							p.GetPendingDeclarations(),
							p.GetHeadendEntries(), p.GetMaxHeadendEntries(),
							p.GetAdvertisedRoutes(), p.GetMaxAdvertisedRoutes(),
							p.GetLocalSids(), p.GetMaxLocalSids()); err != nil {
							return err
						}
					}
					if err := w.Flush(); err != nil {
						return err
					}
					// The scope is reported in its own block rather than as
					// more columns. It is what a capability may be
					// exercised on, so it is read when checking a grant
					// rather than when watching a plugin run, and four more
					// list-valued columns would push the table past a
					// terminal.
					if err := printCplaneScopes(plugins); err != nil {
						return err
					}
					if len(unrestored) == 0 {
						return nil
					}
					fmt.Println()
					fmt.Println("Plugins that could not be restored (state and claims still held):")
					u := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
					if _, err := fmt.Fprintln(u, "NAME\tBEHAVIORS\tSINCE\tREASON"); err != nil {
						return err
					}
					for _, p := range unrestored {
						if _, err := fmt.Fprintf(u, "%s\t%s\t%s\t%s\n",
							p.GetName(), formatBehaviors(p.GetEndpointBehaviors()),
							formatSince(p.GetSince().AsTime(), p.GetSince() != nil),
							p.GetReason()); err != nil {
							return err
						}
					}
					return u.Flush()
				},
			},
			{
				Name:      "forget",
				Usage:     "Drop a plugin that could not be restored",
				ArgsUsage: "--name <plugin>",
				Description: "Releases the endpoint behaviors still claimed on its behalf and\n" +
					"removes it from the store, so a plugin that will not start stops\n" +
					"withholding routes from everything else.\n\n" +
					"The state it left in the maps is not touched: nothing here knows\n" +
					"what that state was for. Register a working version of the plugin if\n" +
					"you want it reconciled, or remove the entries by hand.",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Required: true, Usage: "Plugin to forget"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					if _, err := clients.Plugin.CplanePluginForget(c.Context,
						connect.NewRequest(&v1.CplanePluginForgetRequest{Name: c.String("name")})); err != nil {
						return err
					}
					fmt.Printf("Forgot control-plane plugin %q\n", c.String("name"))
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

// printCplaneScopes reports what each plugin may name, for the plugins
// that may name anything.
func printCplaneScopes(plugins []*v1.CplanePluginStat) error {
	var scoped []*v1.CplanePluginStat
	for _, p := range plugins {
		s := p.GetScope()
		if len(s.GetLocators()) > 0 || len(s.GetVrfs()) > 0 || len(s.GetHeadendPrefixes()) > 0 ||
			len(s.GetHeadendSlots()) > 0 || len(s.GetEndpointSlots()) > 0 {
			scoped = append(scoped, p)
		}
	}
	if len(scoped) == 0 {
		return nil
	}
	fmt.Println()
	fmt.Println("Scopes:")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "NAME\tLOCATORS\tVRFS\tHEADEND PREFIXES\tHEADEND SLOTS\tENDPOINT SLOTS"); err != nil {
		return err
	}
	for _, p := range scoped {
		s := p.GetScope()
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			p.GetName(),
			joinOrDash(s.GetLocators()),
			joinOrDash(s.GetVrfs()),
			joinOrDash(s.GetHeadendPrefixes()),
			joinOrDash(formatSlots(s.GetHeadendSlots())),
			joinOrDash(formatSlots(s.GetEndpointSlots()))); err != nil {
			return err
		}
	}
	return w.Flush()
}

// formatSlots renders slot numbers for the scope table.
func formatSlots(slots []uint32) []string {
	out := make([]string, 0, len(slots))
	for _, s := range slots {
		out = append(out, strconv.FormatUint(uint64(s), 10))
	}
	return out
}

// uintSliceToUint32 narrows the slot flags to what the request carries.
//
// Which slots a plugin may occupy is the daemon's to decide, so the ranges
// are not repeated here. What is checked is that the number survives the
// narrowing: uint is 64 bits on the platforms this runs on, so
// --endpoint-slot 4294967328 would wrap to 32 and be granted as a slot the
// operator never named.
func uintSliceToUint32(flag string, in []uint) ([]uint32, error) {
	out := make([]uint32, 0, len(in))
	for _, v := range in {
		if uint64(v) > math.MaxUint32 {
			return nil, fmt.Errorf("--%s %d does not fit a slot number", flag, v)
		}
		out = append(out, uint32(v))
	}
	return out, nil
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

// formatBehaviors renders claimed codepoints the way an operator writes
// them, which is hex: they are SID TLV values, and the private range an
// operator picks from is only recognizable in that base.
func formatBehaviors(behaviors []uint32) string {
	if len(behaviors) == 0 {
		return "-"
	}
	out := make([]string, 0, len(behaviors))
	for _, b := range behaviors {
		out = append(out, fmt.Sprintf("0x%04X", b))
	}
	return strings.Join(out, ",")
}

// formatSince renders how long the current instance has been up.
//
// The age matters more than the timestamp: a plugin restarting in a loop
// is one whose age keeps resetting, and that is visible at a glance in a
// column of durations where it is not in a column of clock times.
func formatSince(t time.Time, ok bool) string {
	if !ok || t.IsZero() {
		return "-"
	}
	d := time.Since(t).Round(time.Second)
	if d < 0 {
		d = 0
	}
	return d.String()
}
