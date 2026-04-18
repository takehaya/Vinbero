package cli

import (
	"context"
	"encoding/hex"
	"fmt"
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
					&cli.StringFlag{Name: "vrf-name", Usage: "VRF device name (for End.DT4/DT6/DT46)"},
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
					&cli.UintFlag{Name: "table-id", Usage: "VLAN table ID (for End.DX2V)"},
					&cli.StringFlag{Name: "plugin-aux-hex", Usage: "Plugin-defined aux payload as hex (<= 196 bytes after decode)"},
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

					sid := &v1.SidFunction{
						Action:        action,
						TriggerPrefix: c.String("trigger-prefix"),
						SrcAddr:       c.String("src-addr"),
						DstAddr:       c.String("dst-addr"),
						Nexthop:       c.String("nexthop"),
						Flavor:        flavor,
						VrfName:       c.String("vrf-name"),
						BdId:          uint32(c.Uint("bd-id")),
						BridgeName:    c.String("bridge-name"),
						Oif:           uint32(c.Uint("oif")),
						Segments:      segments,
						HeadendMode:   headendMode,
						ArgsOffset:   uint32(c.Uint("args-offset")),
						GtpV4SrcAddr: c.String("gtp-v4-src-addr"),
						TableId:      uint32(c.Uint("table-id")),
						PluginAuxRaw: pluginAuxRaw,
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
					headers := []string{"TRIGGER PREFIX", "ACTION", "FLAVOR", "VRF", "BD_ID", "BRIDGE", "OIF", "TABLE_ID"}
					var rows [][]string
					for _, s := range resp.Msg.SidFunctions {
						rows = append(rows, []string{
							s.TriggerPrefix,
							formatAction(s.Action),
							formatFlavor(s.Flavor),
							s.VrfName,
							fmt.Sprintf("%d", s.BdId),
							s.BridgeName,
							fmt.Sprintf("%d", s.Oif),
							fmt.Sprintf("%d", s.TableId),
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
