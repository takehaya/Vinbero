package cli

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/urfave/cli/v2"
)

func dmacCommand() *cli.Command {
	return &cli.Command{
		Name:  "fdb",
		Usage: "Show FDB (MAC address table) entries",
		Subcommands: []*cli.Command{
			{
				Name:  "list",
				Usage: "List all FDB entries",
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Dmac.DmacList(context.Background(),
						connect.NewRequest(&v1.DmacListRequest{}))
					if err != nil {
						return err
					}
					if useJSON(c) {
						return printJSON(resp.Msg.Entries)
					}
					headers := []string{"BD_ID", "MAC", "OIF"}
					var rows [][]string
					for _, e := range resp.Msg.Entries {
						rows = append(rows, []string{
							fmt.Sprintf("%d", e.BdId), e.Mac, fmt.Sprintf("%d", e.Oif),
						})
					}
					printTable(headers, rows)
					return nil
				},
			},
		},
	}
}
