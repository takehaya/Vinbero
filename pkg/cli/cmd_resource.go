package cli

import (
	"context"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/urfave/cli/v2"
)

func bridgeCommand() *cli.Command {
	return &cli.Command{
		Name:    "bridge",
		Aliases: []string{"br"},
		Usage:   "Manage Linux bridge devices",
		Subcommands: []*cli.Command{
			{
				Name:  "create",
				Usage: "Create a bridge device",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Required: true, Usage: "Bridge device name"},
					&cli.UintFlag{Name: "bd-id", Required: true, Usage: "Bridge Domain ID"},
					&cli.StringFlag{Name: "members", Usage: "Member interfaces (comma-separated)"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					var members []string
					if m := c.String("members"); m != "" {
						members = strings.Split(m, ",")
					}
					br := &v1.Bridge{
						Name:    c.String("name"),
						BdId:    uint32(c.Uint("bd-id")),
						Members: members,
					}
					resp, err := clients.Resource.BridgeCreate(context.Background(),
						connect.NewRequest(&v1.BridgeCreateRequest{Bridges: []*v1.Bridge{br}}))
					if err != nil {
						return err
					}
					return printOperationResult(resp.Msg.Created, resp.Msg.Errors, "Bridge")
				},
			},
			{
				Name:  "delete",
				Usage: "Delete a bridge device",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Required: true},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Resource.BridgeDelete(context.Background(),
						connect.NewRequest(&v1.BridgeDeleteRequest{Names: []string{c.String("name")}}))
					if err != nil {
						return err
					}
					fmt.Printf("Deleted: %s\n", strings.Join(resp.Msg.DeletedNames, ", "))
					return nil
				},
			},
			{
				Name:  "list",
				Usage: "List managed bridges",
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Resource.BridgeList(context.Background(),
						connect.NewRequest(&v1.BridgeListRequest{}))
					if err != nil {
						return err
					}
					if useJSON(c) {
						return printJSON(resp.Msg.Bridges)
					}
					headers := []string{"NAME", "BD_ID", "MEMBERS"}
					var rows [][]string
					for _, b := range resp.Msg.Bridges {
						rows = append(rows, []string{
							b.Name, fmt.Sprintf("%d", b.BdId), strings.Join(b.Members, ","),
						})
					}
					printTable(headers, rows)
					return nil
				},
			},
		},
	}
}
