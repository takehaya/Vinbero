package cli

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"connectrpc.com/connect"
	"github.com/urfave/cli/v2"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

func proberCommand() *cli.Command {
	return &cli.Command{
		Name:  "prober",
		Usage: "Inspect the SRv6 liveness prober",
		Subcommands: []*cli.Command{
			{
				Name:  "status",
				Usage: "Show per-path probe state for every ECMP group",
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Prober.ProberStatus(context.Background(),
						connect.NewRequest(&v1.ProberStatusRequest{}))
					if err != nil {
						return err
					}
					if useJSON(c) {
						return printJSON(resp.Msg)
					}
					if !resp.Msg.Enabled {
						fmt.Println("prober is disabled (config prober.enable)")
						return nil
					}
					fmt.Printf("interval %dms, multiplier %d\n",
						resp.Msg.IntervalMs, resp.Msg.Multiplier)
					headers := []string{"GROUP", "PATH", "DST", "STATE", "MISS", "FLAPS", "RTT", "LAST REPLY"}
					var rows [][]string
					for _, p := range resp.Msg.Paths {
						state := "up"
						if !p.Up {
							state = "down"
						}
						if !p.Probeable {
							state = "up (unprobed)"
						}
						rtt, last := "-", "-"
						if p.RttUsec > 0 {
							rtt = (time.Duration(p.RttUsec) * time.Microsecond).String()
						}
						if p.LastReplyUnixNano > 0 {
							last = time.Unix(0, p.LastReplyUnixNano).Format(time.TimeOnly)
						}
						rows = append(rows, []string{
							strconv.FormatUint(uint64(p.GroupId), 10),
							strconv.FormatUint(uint64(p.PathIndex), 10),
							orDash(p.Dst),
							state,
							strconv.FormatUint(uint64(p.MissStreak), 10),
							strconv.FormatUint(p.Transitions, 10),
							rtt,
							last,
						})
					}
					printTable(headers, rows)
					return nil
				},
			},
		},
	}
}

func orDash(v string) string {
	if v == "" {
		return "-"
	}
	return v
}
