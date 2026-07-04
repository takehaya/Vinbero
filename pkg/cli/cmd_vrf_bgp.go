package cli

import (
	"context"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"
)

func vrfBgpCommand() *cli.Command {
	return &cli.Command{
		Name:    "vrf-bgp",
		Aliases: []string{"vbgp"},
		Usage:   "Manage VRF <-> BGP route-target bindings",
		Subcommands: []*cli.Command{
			vrfBgpBindCommand(),
			vrfBgpUnbindCommand(),
			vrfBgpListCommand(),
			vrfBgpUpdateCommand(),
			vrfBgpRTCommand(),
			vrfBgpFamilyCommand(),
		},
	}
}

// vrfBgpBindFlags is the flag set bind and update share: they take the same
// inputs because update is the atomic full-replace form of bind.
func vrfBgpBindFlags(requireVRF bool) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "vrf", Required: requireVRF, Usage: "VRF device name"},
		&cli.StringFlag{Name: "import-rts", Usage: "Import route targets (comma-separated, legacy L3VPN shorthand)"},
		&cli.StringFlag{Name: "export-rts", Usage: "Export route targets (comma-separated, legacy L3VPN shorthand)"},
		&cli.StringSliceFlag{Name: "rt", Usage: "Repeatable: FAMILY:RT[:DIRECTION] (e.g. vpnv4:65000:200:both, mup_ipv4:100:6000:import)"},
		&cli.StringFlag{Name: "default-locator", Usage: "Locator name for this VRF's local SIDs"},
		&cli.StringFlag{Name: "rd", Usage: "Route distinguisher for auto-advertised local prefixes (e.g. 65100:200)"},
		&cli.StringFlag{Name: "redistribute", Usage: "Auto-advertise protocols (comma-separated: connected,static)"},
		&cli.UintFlag{Name: "max-prefixes", Usage: "Cap on auto-advertised prefixes for this VRF (0 = unlimited)"},
		&cli.StringFlag{Name: "mup-gtp4-source-prefix", Usage: "RFC 9433 6.6 GTP4 downlink source-embed prefix for this VRF's RD (IPv6, /96 or shorter; empty = off, requires --rd)"},
	}
}

// buildBindingFromFlags assembles a VrfBgpBinding from the bind/update flags
// shared via vrfBgpBindFlags. --rt entries are merged into families; legacy
// --import-rts / --export-rts are passed through unchanged so the server's
// Normalize step expands them.
func buildBindingFromFlags(c *cli.Context) (*v1.VrfBgpBinding, error) {
	maxPfx := c.Uint("max-prefixes")
	if maxPfx > math.MaxUint32 {
		return nil, fmt.Errorf("max-prefixes %d out of range (max %d)", maxPfx, uint32(math.MaxUint32))
	}
	families, err := parseRTFlags(c.StringSlice("rt"))
	if err != nil {
		return nil, err
	}
	return &v1.VrfBgpBinding{
		VrfName:             c.String("vrf"),
		ImportRts:           csvFlag(c.String("import-rts")),
		ExportRts:           csvFlag(c.String("export-rts")),
		DefaultLocator:      c.String("default-locator"),
		Rd:                  c.String("rd"),
		Redistribute:        csvFlag(c.String("redistribute")),
		MaxPrefixes:         uint32(maxPfx),
		Families:            families,
		MupGtp4SourcePrefix: c.String("mup-gtp4-source-prefix"),
	}, nil
}

func vrfBgpBindCommand() *cli.Command {
	return &cli.Command{
		Name:  "bind",
		Usage: "Bind a VRF to its BGP route-target policy",
		Flags: vrfBgpBindFlags(true),
		Action: func(c *cli.Context) error {
			b, err := buildBindingFromFlags(c)
			if err != nil {
				return err
			}
			clients := clientsFromContext(c)
			resp, err := clients.VrfBgp.VrfBgpBind(context.Background(),
				connect.NewRequest(&v1.VrfBgpBindRequest{Bindings: []*v1.VrfBgpBinding{b}}))
			if err != nil {
				return err
			}
			return printOperationResult(resp.Msg.Bound, resp.Msg.Errors, "VrfBgpBinding", "bound")
		},
	}
}

func vrfBgpUnbindCommand() *cli.Command {
	return &cli.Command{
		Name:  "unbind",
		Usage: "Remove a VRF's BGP binding",
		Flags: []cli.Flag{&cli.StringFlag{Name: "vrf", Required: true}},
		Action: func(c *cli.Context) error {
			clients := clientsFromContext(c)
			resp, err := clients.VrfBgp.VrfBgpUnbind(context.Background(),
				connect.NewRequest(&v1.VrfBgpUnbindRequest{VrfNames: []string{c.String("vrf")}}))
			if err != nil {
				return err
			}
			for _, e := range resp.Msg.Errors {
				fmt.Printf("error: %s: %s\n", e.TriggerPrefix, e.Reason)
			}
			if len(resp.Msg.UnboundVrfNames) > 0 {
				fmt.Printf("Unbound: %s\n", strings.Join(resp.Msg.UnboundVrfNames, ", "))
			}
			if len(resp.Msg.Errors) > 0 {
				return fmt.Errorf("%d unbind operation(s) failed", len(resp.Msg.Errors))
			}
			return nil
		},
	}
}

func vrfBgpListCommand() *cli.Command {
	return &cli.Command{
		Name:  "list",
		Usage: "List VRF BGP bindings",
		Action: func(c *cli.Context) error {
			clients := clientsFromContext(c)
			resp, err := clients.VrfBgp.VrfBgpList(context.Background(),
				connect.NewRequest(&v1.VrfBgpListRequest{}))
			if err != nil {
				return err
			}
			if useJSON(c) {
				return printJSON(resp.Msg.Bindings)
			}
			headers := []string{"VRF", "RD", "FAMILIES", "REDISTRIBUTE", "MAX_PFX", "DEFAULT_LOCATOR"}
			var rows [][]string
			for _, b := range resp.Msg.Bindings {
				rows = append(rows, []string{
					b.VrfName,
					b.Rd,
					renderFamilies(b.GetFamilies()),
					strings.Join(b.Redistribute, ","),
					fmt.Sprintf("%d", b.MaxPrefixes),
					b.DefaultLocator,
				})
			}
			printTable(headers, rows)
			return nil
		},
	}
}

func vrfBgpUpdateCommand() *cli.Command {
	return &cli.Command{
		Name:  "update",
		Usage: "Atomically replace a VRF binding (omitted flags preserve prior values)",
		Flags: vrfBgpBindFlags(true),
		Action: func(c *cli.Context) error {
			b, err := buildBindingFromFlags(c)
			if err != nil {
				return err
			}
			clients := clientsFromContext(c)
			// UpdateBinding is full-replace at the proto level, but proto3
			// scalars cannot distinguish "set to zero" from "not provided",
			// so a CLI user who omits --rd on a binding would silently clear
			// it. Fetch prev and fill every flag the user did NOT explicitly
			// set from prev, so the CLI's semantic is "patch what I passed".
			if err := preservePriorBindingFields(c, b, clients); err != nil {
				return err
			}
			resp, err := clients.VrfBgp.UpdateBinding(context.Background(),
				connect.NewRequest(&v1.UpdateBindingRequest{Binding: b}))
			if err != nil {
				return err
			}
			if useJSON(c) {
				return printJSON(resp.Msg.GetBinding())
			}
			fmt.Printf("Updated: %s\n", resp.Msg.GetBinding().GetVrfName())
			return nil
		},
	}
}

// preservePriorBindingFields reads the binding currently stored under
// b.VrfName and copies, for every flag the caller did NOT pass, the prior
// value into b. The list of "patchable" fields matches vrfBgpBindFlags so
// every scalar zero a user did not type is restored. RT inputs (--rt,
// --import-rts, --export-rts) are treated as a single group: if the caller
// touched any of them, the new wire value (including an explicit clear) is
// kept verbatim; if none was touched, prev's Families and legacy lists are
// restored so a `vrf-bgp update --rd X` does not wipe every RT.
func preservePriorBindingFields(c *cli.Context, b *v1.VrfBgpBinding, clients *Clients) error {
	listResp, err := clients.VrfBgp.VrfBgpList(c.Context, connect.NewRequest(&v1.VrfBgpListRequest{}))
	if err != nil {
		return fmt.Errorf("fetch prior binding state: %w", err)
	}
	var prev *v1.VrfBgpBinding
	for _, p := range listResp.Msg.GetBindings() {
		if p.GetVrfName() == b.GetVrfName() {
			prev = p
			break
		}
	}
	if prev == nil {
		// No prior binding: nothing to preserve. The server returns NotFound
		// in this case anyway (UpdateBinding requires existing).
		return nil
	}
	if !c.IsSet("rd") {
		b.Rd = prev.GetRd()
	}
	if !c.IsSet("default-locator") {
		b.DefaultLocator = prev.GetDefaultLocator()
	}
	if !c.IsSet("redistribute") {
		b.Redistribute = prev.GetRedistribute()
	}
	if !c.IsSet("max-prefixes") {
		b.MaxPrefixes = prev.GetMaxPrefixes()
	}
	if !c.IsSet("mup-gtp4-source-prefix") {
		// Explicit clear stays possible: --mup-gtp4-source-prefix "" is IsSet.
		b.MupGtp4SourcePrefix = prev.GetMupGtp4SourcePrefix()
	}
	if !c.IsSet("rt") && !c.IsSet("import-rts") && !c.IsSet("export-rts") {
		b.Families = prev.GetFamilies()
		b.ImportRts = prev.GetImportRts()
		b.ExportRts = prev.GetExportRts()
	}
	return nil
}

func vrfBgpRTCommand() *cli.Command {
	return &cli.Command{
		Name:  "rt",
		Usage: "Manage route targets on a VRF binding",
		Subcommands: []*cli.Command{
			{
				Name:  "add",
				Usage: "Add (or extend the direction bitmask of) one RT under one family",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "vrf", Required: true},
					&cli.StringFlag{Name: "family", Required: true, Usage: "vpnv4 / vpnv6 / evpn / mup_ipv4 / mup_ipv6"},
					&cli.StringFlag{Name: "rt", Required: true, Usage: "Route target (e.g. 65000:200, 10.0.0.1:200)"},
					&cli.StringFlag{Name: "direction", Value: "both", Usage: "import / export / both"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.VrfBgp.AddRouteTarget(context.Background(),
						connect.NewRequest(&v1.AddRouteTargetRequest{
							VrfName: c.String("vrf"),
							Family:  c.String("family"),
							RouteTarget: &v1.VrfBgpRouteTarget{
								Rt:        c.String("rt"),
								Direction: c.String("direction"),
							},
						}))
					if err != nil {
						return err
					}
					return printBindingResult(c, resp.Msg.GetBinding(), "Added")
				},
			},
			{
				Name:  "remove",
				Usage: "Remove one RT (or one direction bit of it) from a family",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "vrf", Required: true},
					&cli.StringFlag{Name: "family", Required: true},
					&cli.StringFlag{Name: "rt", Required: true},
					&cli.StringFlag{Name: "direction", Usage: "Empty strips the whole RT; import/export strips only that bit"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.VrfBgp.RemoveRouteTarget(context.Background(),
						connect.NewRequest(&v1.RemoveRouteTargetRequest{
							VrfName:   c.String("vrf"),
							Family:    c.String("family"),
							Rt:        c.String("rt"),
							Direction: c.String("direction"),
						}))
					if err != nil {
						return err
					}
					return printBindingResult(c, resp.Msg.GetBinding(), "Removed")
				},
			},
			{
				Name:  "list",
				Usage: "List the route targets on a binding (with optional family/direction filter)",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "vrf", Required: true},
					&cli.StringFlag{Name: "family", Usage: "Filter by family"},
					&cli.StringFlag{Name: "direction", Usage: "Filter by import / export"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.VrfBgp.ListRouteTargets(context.Background(),
						connect.NewRequest(&v1.ListRouteTargetsRequest{
							VrfName:   c.String("vrf"),
							Family:    c.String("family"),
							Direction: c.String("direction"),
						}))
					if err != nil {
						return err
					}
					if useJSON(c) {
						return printJSON(resp.Msg.GetFamilies())
					}
					headers := []string{"FAMILY", "RT", "DIRECTION"}
					var rows [][]string
					for _, fam := range resp.Msg.GetFamilies() {
						for _, rt := range fam.GetRouteTargets() {
							rows = append(rows, []string{fam.GetFamily(), rt.GetRt(), rt.GetDirection()})
						}
					}
					printTable(headers, rows)
					return nil
				},
			},
			{
				Name:  "batch",
				Usage: "Apply a sequence of RT add/remove ops atomically (rollback on failure)",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "vrf", Required: true},
					&cli.StringFlag{Name: "from-file", Required: true, Usage: "YAML/JSON file listing ops (see docs/dev/cli_vrf_bgp.md)"},
				},
				Action: func(c *cli.Context) error {
					ops, err := loadBatchOpsFile(c.String("from-file"))
					if err != nil {
						return err
					}
					clients := clientsFromContext(c)
					resp, err := clients.VrfBgp.BatchModifyRouteTargets(context.Background(),
						connect.NewRequest(&v1.BatchModifyRouteTargetsRequest{
							VrfName: c.String("vrf"),
							Ops:     ops,
						}))
					if err != nil {
						return err
					}
					return printBindingResult(c, resp.Msg.GetBinding(), "Batched")
				},
			},
		},
	}
}

func vrfBgpFamilyCommand() *cli.Command {
	return &cli.Command{
		Name:  "family",
		Usage: "Manage address-family entries on a VRF binding",
		Subcommands: []*cli.Command{
			{
				Name:  "add",
				Usage: "Add a new family entry (empty RT set OK)",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "vrf", Required: true},
					&cli.StringFlag{Name: "family", Required: true},
					&cli.StringSliceFlag{Name: "rt", Usage: "Initial RTs: RT[:DIRECTION] (repeatable, family inferred from --family)"},
				},
				Action: func(c *cli.Context) error {
					cfg, err := parseFamilyRTs(c.String("family"), c.StringSlice("rt"))
					if err != nil {
						return err
					}
					clients := clientsFromContext(c)
					resp, err := clients.VrfBgp.AddFamily(context.Background(),
						connect.NewRequest(&v1.AddFamilyRequest{
							VrfName: c.String("vrf"),
							Family:  c.String("family"),
							Config:  cfg,
						}))
					if err != nil {
						return err
					}
					return printBindingResult(c, resp.Msg.GetBinding(), "AddedFamily")
				},
			},
			{
				Name:  "remove",
				Usage: "Remove a family entry from a binding",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "vrf", Required: true},
					&cli.StringFlag{Name: "family", Required: true},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.VrfBgp.RemoveFamily(context.Background(),
						connect.NewRequest(&v1.RemoveFamilyRequest{
							VrfName: c.String("vrf"),
							Family:  c.String("family"),
						}))
					if err != nil {
						return err
					}
					return printBindingResult(c, resp.Msg.GetBinding(), "RemovedFamily")
				},
			},
		},
	}
}

// parseRTFlags expands repeated --rt FAMILY:RT[:DIRECTION] flags into the
// proto families map. The last colon-separated token is treated as direction
// only when it matches a known direction word; otherwise the entire tail is
// the RT itself, so IP-form RTs like "10.0.0.1:200" round-trip correctly.
func parseRTFlags(rts []string) (map[string]*v1.VrfBgpFamily, error) {
	if len(rts) == 0 {
		return nil, nil
	}
	out := make(map[string]*v1.VrfBgpFamily)
	for _, raw := range rts {
		fam, rt, dir, err := parseOneRTFlag(raw)
		if err != nil {
			return nil, err
		}
		entry, ok := out[fam]
		if !ok {
			entry = &v1.VrfBgpFamily{}
			out[fam] = entry
		}
		entry.RouteTargets = append(entry.RouteTargets, &v1.VrfBgpRouteTarget{Rt: rt, Direction: dir})
	}
	return out, nil
}

// parseFamilyRTs is the family-scoped variant: --rt entries on `family add`
// omit the leading FAMILY: token because the family comes from --family.
// So --rt 65000:200:import expands to {rt:65000:200, dir:import}.
func parseFamilyRTs(fam string, rts []string) (*v1.VrfBgpFamily, error) {
	out := &v1.VrfBgpFamily{}
	for _, raw := range rts {
		rt, dir, err := splitRTAndDirection(raw)
		if err != nil {
			return nil, fmt.Errorf("family %q --rt %q: %w", fam, raw, err)
		}
		out.RouteTargets = append(out.RouteTargets, &v1.VrfBgpRouteTarget{Rt: rt, Direction: dir})
	}
	return out, nil
}

func parseOneRTFlag(raw string) (family, rt, direction string, err error) {
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("--rt %q: want FAMILY:RT (RT is ASN:value or IP:value)", raw)
	}
	rt, direction, err = splitRTAndDirection(parts[1])
	if err != nil {
		return "", "", "", fmt.Errorf("--rt %q: %w", raw, err)
	}
	return parts[0], rt, direction, nil
}

// splitRTAndDirection peels an optional trailing direction word ("import",
// "export", "both") off the colon-separated input; the rest is the RT.
// An RT needs at least one colon (ASN:value or IP:value).
func splitRTAndDirection(s string) (rt, direction string, err error) {
	parts := strings.Split(s, ":")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("RT %q: want ASN:value or IP:value", s)
	}
	switch last := strings.ToLower(parts[len(parts)-1]); last {
	case "import", "export", "both":
		if len(parts) < 3 {
			return "", "", fmt.Errorf("RT %q: direction without an RT", s)
		}
		return strings.Join(parts[:len(parts)-1], ":"), last, nil
	default:
		return s, "", nil
	}
}

// renderFamilies returns a one-line summary "fam=[rt(dir),rt(dir);...]"
// for `vrf-bgp list`. Families are sorted alphabetically; RTs keep their
// server-supplied registration order.
func renderFamilies(in map[string]*v1.VrfBgpFamily) string {
	if len(in) == 0 {
		return "-"
	}
	famKeys := make([]string, 0, len(in))
	for k := range in {
		famKeys = append(famKeys, k)
	}
	sort.Strings(famKeys)
	parts := make([]string, 0, len(famKeys))
	for _, fam := range famKeys {
		rts := in[fam].GetRouteTargets()
		entries := make([]string, 0, len(rts))
		for _, rt := range rts {
			dir := rt.GetDirection()
			if dir == "" {
				dir = "both"
			}
			entries = append(entries, fmt.Sprintf("%s(%s)", rt.GetRt(), dir))
		}
		parts = append(parts, fmt.Sprintf("%s=[%s]", fam, strings.Join(entries, ",")))
	}
	return strings.Join(parts, "; ")
}

// batchOpsFile is the YAML/JSON shape for `vbctl vrf-bgp rt batch --from-file`.
// Ops are applied in array order; a single invalid op rolls back the batch.
type batchOpsFile struct {
	Ops []batchOp `yaml:"ops" json:"ops"`
}

type batchOp struct {
	Kind      string `yaml:"kind" json:"kind"` // add / remove
	Family    string `yaml:"family" json:"family"`
	RT        string `yaml:"rt" json:"rt"`
	Direction string `yaml:"direction,omitempty" json:"direction,omitempty"`
}

func loadBatchOpsFile(path string) ([]*v1.RouteTargetOp, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var doc batchOpsFile
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	out := make([]*v1.RouteTargetOp, 0, len(doc.Ops))
	for i, op := range doc.Ops {
		kind, err := batchKind(op.Kind)
		if err != nil {
			return nil, fmt.Errorf("ops[%d]: %w", i, err)
		}
		out = append(out, &v1.RouteTargetOp{
			Kind:        kind,
			Family:      op.Family,
			RouteTarget: &v1.VrfBgpRouteTarget{Rt: op.RT, Direction: op.Direction},
		})
	}
	return out, nil
}

func batchKind(s string) (v1.RouteTargetOp_Kind, error) {
	switch strings.ToLower(s) {
	case "add":
		return v1.RouteTargetOp_KIND_ADD, nil
	case "remove":
		return v1.RouteTargetOp_KIND_REMOVE, nil
	default:
		return v1.RouteTargetOp_KIND_UNSPECIFIED, fmt.Errorf("kind %q: want add/remove", s)
	}
}

// printBindingResult emits either JSON of the updated binding (so scripts
// can re-read state) or a one-line tag + vrf_name for terminal use.
func printBindingResult(c *cli.Context, b *v1.VrfBgpBinding, tag string) error {
	if useJSON(c) {
		return printJSON(b)
	}
	fmt.Printf("%s: %s\n", tag, b.GetVrfName())
	return nil
}

// csvFlag splits a comma-separated CLI flag into a slice, trimming each
// element and dropping empties, returning nil for an empty flag.
func csvFlag(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
