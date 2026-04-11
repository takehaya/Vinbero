package cli

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/urfave/cli/v2"
)

func statsCommand() *cli.Command {
	return &cli.Command{
		Name:  "stats",
		Usage: "Show XDP packet statistics",
		Subcommands: []*cli.Command{
			{
				Name:  "show",
				Usage: "Display per-counter packet and byte statistics",
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Stats.StatsShow(context.Background(),
						connect.NewRequest(&v1.StatsShowRequest{}))
					if err != nil {
						return err
					}
					if useJSON(c) {
						return printJSON(resp.Msg.Counters)
					}
					headers := []string{"COUNTER", "PACKETS", "BYTES"}
					var rows [][]string
					for _, counter := range resp.Msg.Counters {
						rows = append(rows, []string{
							counter.Name,
							fmt.Sprintf("%d", counter.Packets),
							fmt.Sprintf("%d", counter.Bytes),
						})
					}
					printTable(headers, rows)
					return nil
				},
			},
			{
				Name:  "reset",
				Usage: "Reset all counters to zero",
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					_, err := clients.Stats.StatsReset(context.Background(),
						connect.NewRequest(&v1.StatsResetRequest{}))
					if err != nil {
						return err
					}
					fmt.Println("Stats counters reset.")
					return nil
				},
			},
		},
	}
}
