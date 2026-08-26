package cli

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/urfave/cli/v2"
)

func sidFunctionCommand() *cli.Command {
	return &cli.Command{
		Name:    "sid-function",
		Aliases: []string{"sid"},
		Usage:   "Manage SRv6 SID endpoint functions",
		Subcommands: []*cli.Command{
			{
				Name:  "create",
				Usage: "Create a SID function",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "trigger-prefix", Required: true, Usage: "IPv6 CIDR (e.g., fc00:1::1/128)"},
					&cli.StringFlag{Name: "action", Required: true, Usage: "Endpoint action (e.g., END_DT4, END_DT2)"},
					&cli.StringFlag{Name: "vrf-name", Usage: "VRF device name (for End.DT4/DT6/DT46 and uT)"},
					&cli.UintFlag{Name: "bd-id", Usage: "Bridge Domain ID (for End.DT2)"},
					&cli.StringFlag{Name: "bridge-name", Usage: "Bridge device name (for End.DT2)"},
					&cli.StringFlag{Name: "src-addr", Usage: "Source IPv6 address"},
					&cli.StringFlag{Name: "dst-addr", Usage: "Destination IPv6 address"},
					&cli.StringFlag{Name: "nexthop", Usage: "Next-hop IPv6 address (for End.X)"},
					&cli.UintFlag{Name: "oif", Usage: "Output interface index (for End.DX2)"},
					&cli.StringFlag{Name: "flavor", Usage: "SRv6 flavor (PSP, USP, USD)"},
					&cli.StringFlag{Name: "segments", Usage: "Policy segment list, comma-separated (for End.B6)"},
					&cli.StringFlag{Name: "headend-mode", Usage: "Policy mode: H_INSERT, H_INSERT_RED, H_ENCAPS, H_ENCAPS_RED (for End.B6)"},
					&cli.UintFlag{Name: "args-offset", Usage: "Args.Mob.Session byte offset in SID (for GTP functions)"},
					&cli.StringFlag{Name: "gtp-v4-src-addr", Usage: "GTP4 outer IPv4 source address (for End.M.GTP4.E)"},
					&cli.UintFlag{Name: "gtp-v4-src-position", Usage: "Extract the GTP4 outer IPv4 source from the outer IPv6 SA at this bit position 0..96 (RFC 9433 6.6, for End.M.GTP4.E; mutually exclusive with --gtp-v4-src-addr)"},
					&cli.UintFlag{Name: "table-id", Usage: "VLAN table ID (for End.DX2V)"},
					&cli.UintFlag{Name: "iface-in", Usage: "Return circuit ifindex (IFACE-IN; required for END_AS/END_AD/END_AM)"},
					&cli.UintFlag{Name: "vlan-in", Usage: "Return circuit VLAN, 0 = untagged (for END_AS/END_AD/END_AM)"},
					&cli.StringFlag{Name: "inner-type", Usage: "Proxy INNER-TYPE: ipv4, ipv6, or l2 (required for END_AS/END_AD/END_AM; END_AM requires ipv6)"},
					&cli.StringFlag{Name: "service-mac", Usage: "Service MAC for static rewrite towards IFACE-OUT; omit to resolve the inner destination via FIB (END_AS/END_AD L3 inner; required for END_AM)"},
					&cli.UintFlag{Name: "hop-limit-margin", Usage: "Tolerated outer hop-limit drift before the dynamic cache refreshes (END_AD only)"},
					&cli.StringFlag{Name: "service-name", Usage: "NF-catalog name of the SR-aware service behind this SID (END_AN only)"},
					&cli.UintFlag{Name: "usid-block-len", Usage: "NEXT-C-SID locator block length in bits (END_UN/END_UA/END_UT; F3216 = 32, the default)"},
					&cli.StringFlag{Name: "plugin-aux-hex", Usage: "Plugin-defined aux payload as hex (<= 256 bytes after decode)"},
					&cli.StringFlag{Name: "plugin-aux-json", Usage: "Plugin-defined aux payload as JSON (server encodes via plugin BTF)"},
					&cli.StringFlag{Name: "plugin-aux-json-file", Usage: "Path to a file containing plugin aux JSON"},
					&cli.UintFlag{Name: "plugin-aux-index", Usage: "Reference an aux index previously returned by `plugin aux alloc` (mutually exclusive with --plugin-aux-hex/--plugin-aux-json*)"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					action, err := resolveAction(c.String("action"))
					if err != nil {
						return err
					}

					var flavor v1.Srv6LocalFlavor
					if f := c.String("flavor"); f != "" {
						var err error
						flavor, err = resolveFlavor(f)
						if err != nil {
							return err
						}
					}

					var headendMode v1.Srv6HeadendBehavior
					if m := c.String("headend-mode"); m != "" {
						var err error
						headendMode, err = resolveMode(m)
						if err != nil {
							return err
						}
					}

					var segments []string
					if s := c.String("segments"); s != "" {
						segments = strings.Split(s, ",")
						for i := range segments {
							segments[i] = strings.TrimSpace(segments[i])
						}
					}

					var pluginAuxRaw []byte
					if hx := c.String("plugin-aux-hex"); hx != "" {
						decoded, err := hex.DecodeString(hx)
						if err != nil {
							return fmt.Errorf("invalid plugin-aux-hex: %w", err)
						}
						if len(decoded) > bpf.SidAuxPluginRawMax {
							return fmt.Errorf("plugin-aux-hex decodes to %d bytes, max %d",
								len(decoded), bpf.SidAuxPluginRawMax)
						}
						pluginAuxRaw = decoded
					}

					pluginAuxJSON := c.String("plugin-aux-json")
					if jsonPath := c.String("plugin-aux-json-file"); jsonPath != "" {
						if pluginAuxJSON != "" {
							return fmt.Errorf("--plugin-aux-json and --plugin-aux-json-file are mutually exclusive")
						}
						body, err := os.ReadFile(jsonPath)
						if err != nil {
							return fmt.Errorf("read %s: %w", jsonPath, err)
						}
						pluginAuxJSON = string(body)
					}
					if pluginAuxJSON != "" && pluginAuxRaw != nil {
						return fmt.Errorf("--plugin-aux-hex and --plugin-aux-json* are mutually exclusive")
					}
					pluginAuxIndex := uint32(c.Uint("plugin-aux-index"))
					if pluginAuxIndex != 0 && (pluginAuxRaw != nil || pluginAuxJSON != "") {
						return fmt.Errorf("--plugin-aux-index is mutually exclusive with --plugin-aux-hex and --plugin-aux-json*")
					}

					sid := &v1.SidFunction{
						Action:         action,
						TriggerPrefix:  c.String("trigger-prefix"),
						SrcAddr:        c.String("src-addr"),
						DstAddr:        c.String("dst-addr"),
						Nexthop:        c.String("nexthop"),
						Flavor:         flavor,
						VrfName:        c.String("vrf-name"),
						BdId:           uint32(c.Uint("bd-id")),
						BridgeName:     c.String("bridge-name"),
						Oif:            uint32(c.Uint("oif")),
						Segments:       segments,
						HeadendMode:    headendMode,
						ArgsOffset:     uint32(c.Uint("args-offset")),
						GtpV4SrcAddr:   c.String("gtp-v4-src-addr"),
						TableId:        uint32(c.Uint("table-id")),
						PluginAuxRaw:   pluginAuxRaw,
						PluginAuxJson:  pluginAuxJSON,
						PluginAuxIndex: pluginAuxIndex,
					}
					// IsSet, not a zero check: position 0 is a valid setting
					// (extract from the very start of the outer IPv6 SA).
					if c.IsSet("usid-block-len") {
						blockLen := uint32(c.Uint("usid-block-len"))
						sid.UsidBlockLen = &blockLen
					}
					if c.IsSet("gtp-v4-src-position") {
						pos := uint32(c.Uint("gtp-v4-src-position"))
						sid.GtpV4SrcPosition = &pos
					}
					if c.IsSet("iface-in") {
						ifaceIn := uint32(c.Uint("iface-in"))
						sid.IfaceIn = &ifaceIn
					}
					if c.IsSet("vlan-in") {
						vlanIn := uint32(c.Uint("vlan-in"))
						sid.VlanIn = &vlanIn
					}
					if it := c.String("inner-type"); it != "" {
						innerType, err := resolveProxyInnerType(it)
						if err != nil {
							return err
						}
						sid.InnerType = innerType
					}
					if mac := c.String("service-mac"); mac != "" {
						sid.ServiceMac = &mac
					}
					if c.IsSet("hop-limit-margin") {
						margin := uint32(c.Uint("hop-limit-margin"))
						sid.HopLimitMargin = &margin
					}
					if name := c.String("service-name"); name != "" {
						sid.ServiceName = &name
					}

					resp, err := clients.Sid.SidFunctionCreate(context.Background(),
						connect.NewRequest(&v1.SidFunctionCreateRequest{SidFunctions: []*v1.SidFunction{sid}}))
					if err != nil {
						return err
					}
					return printOperationResult(resp.Msg.Created, resp.Msg.Errors, "SID function")
				},
			},
			{
				Name:  "delete",
				Usage: "Delete a SID function",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "trigger-prefix", Required: true},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Sid.SidFunctionDelete(context.Background(),
						connect.NewRequest(&v1.SidFunctionDeleteRequest{TriggerPrefixes: []string{c.String("trigger-prefix")}}))
					if err != nil {
						return err
					}
					fmt.Printf("Deleted: %s\n", strings.Join(resp.Msg.DeletedTriggerPrefixes, ", "))
					return nil
				},
			},
			{
				Name:  "flush",
				Usage: "Delete every SID function entry (requires --yes)",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "yes", Usage: "Confirm the destructive operation", Required: true},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Sid.SidFunctionFlush(context.Background(),
						connect.NewRequest(&v1.SidFunctionFlushRequest{}))
					if err != nil {
						return err
					}
					fmt.Printf("Flushed %d SID functions\n", resp.Msg.DeletedCount)
					fmt.Println("Note: plugin-owned aux entries are NOT freed by flush.")
					fmt.Println("      Use `vbctl plugin aux free --map-type ... --slot ... --index ...`")
					fmt.Println("      per index to release them, or `vbctl plugin list -v` to inspect.")
					return nil
				},
			},
			{
				Name:  "list",
				Usage: "List all SID functions",
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Sid.SidFunctionList(context.Background(),
						connect.NewRequest(&v1.SidFunctionListRequest{}))
					if err != nil {
						return err
					}
					if useJSON(c) {
						return printJSON(resp.Msg.SidFunctions)
					}
					headers := []string{"TRIGGER PREFIX", "ACTION", "FLAVOR", "VRF", "BD_ID", "BRIDGE", "OIF", "TABLE_ID", "IFACE_IN", "INNER"}
					var rows [][]string
					for _, s := range resp.Msg.SidFunctions {
						ifaceIn := ""
						if s.IfaceIn != nil {
							ifaceIn = fmt.Sprintf("%d", s.GetIfaceIn())
						}
						rows = append(rows, []string{
							s.TriggerPrefix,
							formatAction(s.Action),
							formatFlavor(s.Flavor),
							s.VrfName,
							fmt.Sprintf("%d", s.BdId),
							s.BridgeName,
							fmt.Sprintf("%d", s.Oif),
							fmt.Sprintf("%d", s.TableId),
							ifaceIn,
							formatProxyInnerType(s.InnerType),
						})
					}
					printTable(headers, rows)
					return nil
				},
			},
			{
				Name:  "get",
				Usage: "Get a SID function",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "trigger-prefix", Required: true},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Sid.SidFunctionGet(context.Background(),
						connect.NewRequest(&v1.SidFunctionGetRequest{TriggerPrefix: c.String("trigger-prefix")}))
					if err != nil {
						return err
					}
					return printJSON(resp.Msg.SidFunction)
				},
			},
		},
	}
}
