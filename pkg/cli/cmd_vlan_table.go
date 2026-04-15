package cli

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/urfave/cli/v2"
)

func vlanTableCommand() *cli.Command {
	return &cli.Command{
		Name:    "vlan-table",
		Aliases: []string{"vt"},
		Usage:   "Manage VLAN cross-connect table entries (End.DX2V)",
		Subcommands: []*cli.Command{
			{
				Name:  "create",
				Usage: "Create a VLAN cross-connect entry",
				Flags: []cli.Flag{
					&cli.UintFlag{Name: "table-id", Required: true, Usage: "VLAN table ID"},
					&cli.UintFlag{Name: "vlan-id", Required: true, Usage: "VLAN ID (0-4095)"},
					&cli.StringFlag{Name: "interface", Required: true, Usage: "Output interface name"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.VlanTbl.VlanTableCreate(context.Background(),
						connect.NewRequest(&v1.VlanTableCreateRequest{
							Entries: []*v1.VlanTableEntry{{
								TableId:       uint32(c.Uint("table-id")),
								VlanId:        uint32(c.Uint("vlan-id")),
								InterfaceName: c.String("interface"),
							}},
						}))
					if err != nil {
						return err
					}
					return printOperationResult(resp.Msg.Created, resp.Msg.Errors, "VLAN table entry")
				},
			},
			{
				Name:  "delete",
				Usage: "Delete a VLAN cross-connect entry",
				Flags: []cli.Flag{
					&cli.UintFlag{Name: "table-id", Required: true, Usage: "VLAN table ID"},
					&cli.UintFlag{Name: "vlan-id", Required: true, Usage: "VLAN ID"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.VlanTbl.VlanTableDelete(context.Background(),
						connect.NewRequest(&v1.VlanTableDeleteRequest{
							Entries: []*v1.VlanTableEntry{{
								TableId: uint32(c.Uint("table-id")),
								VlanId:  uint32(c.Uint("vlan-id")),
							}},
						}))
					if err != nil {
						return err
					}
					return printOperationResult(resp.Msg.Deleted, resp.Msg.Errors, "VLAN table entry")
				},
			},
			{
				Name:  "list",
				Usage: "List VLAN cross-connect entries",
				Flags: []cli.Flag{
					&cli.UintFlag{Name: "table-id", Usage: "Filter by table ID (0 = all)"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.VlanTbl.VlanTableList(context.Background(),
						connect.NewRequest(&v1.VlanTableListRequest{
							TableId: uint32(c.Uint("table-id")),
						}))
					if err != nil {
						return err
					}
					if useJSON(c) {
						return printJSON(resp.Msg.Entries)
					}
					headers := []string{"TABLE_ID", "VLAN_ID", "INTERFACE"}
					var rows [][]string
					for _, e := range resp.Msg.Entries {
						rows = append(rows, []string{
							fmt.Sprintf("%d", e.TableId),
							fmt.Sprintf("%d", e.VlanId),
							e.InterfaceName,
						})
					}
					printTable(headers, rows)
					return nil
				},
			},
		},
	}
}
