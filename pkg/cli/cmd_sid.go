package cli

import (
	"context"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
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
					headers := []string{"TRIGGER PREFIX", "ACTION", "FLAVOR", "VRF", "BD_ID", "BRIDGE", "OIF"}
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
