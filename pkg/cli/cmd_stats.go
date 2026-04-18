package cli

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/urfave/cli/v2"
)

// typeFlagUsage builds the `--type` help string from bpf.SlotStatsMapTypes
// so renaming a map type doesn't leave a stale hint.
func typeFlagUsage() string {
	return strings.Join(bpf.SlotStatsMapTypes, " | ") + " (default: all)"
}

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
			slotStatsCommand(),
		},
	}
}

func slotStatsCommand() *cli.Command {
	return &cli.Command{
		Name:  "slot",
		Usage: "Per-tailcall-slot invocation counters (builtin + plugin)",
		Subcommands: []*cli.Command{
			{
				Name:  "show",
				Usage: "Display invocation counters per tail-call slot",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "type", Usage: typeFlagUsage()},
					&cli.BoolFlag{Name: "all", Usage: "Include slots with zero packets"},
					&cli.IntFlag{Name: "top", Usage: "Show only the top N slots by packet count"},
					&cli.BoolFlag{Name: "plugin-only", Usage: "Filter to plugin slots only"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					req := &v1.StatsSlotShowRequest{
						IncludeEmpty: c.Bool("all"),
					}
					if t := c.String("type"); t != "" {
						req.MapTypes = []string{t}
					}
					resp, err := clients.Stats.StatsSlotShow(context.Background(), connect.NewRequest(req))
					if err != nil {
						return err
					}

					entries := resp.Msg.Entries
					if c.Bool("plugin-only") {
						entries = filterPluginSlots(entries)
					}
					if top := c.Int("top"); top > 0 {
						sort.SliceStable(entries, func(i, j int) bool {
							return entries[i].Packets > entries[j].Packets
						})
						if len(entries) > top {
							entries = entries[:top]
						}
					}

					if useJSON(c) {
						return printJSON(entries)
					}
					headers := []string{"MAP", "SLOT", "NAME", "PACKETS", "BYTES"}
					var rows [][]string
					for _, e := range entries {
						rows = append(rows, []string{
							e.MapType,
							fmt.Sprintf("%d", e.Slot),
							e.Name,
							fmt.Sprintf("%d", e.Packets),
							fmt.Sprintf("%d", e.Bytes),
						})
					}
					printTable(headers, rows)
					return nil
				},
			},
			{
				Name:  "reset",
				Usage: "Reset per-slot counters",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "type", Usage: typeFlagUsage()},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					req := &v1.StatsSlotResetRequest{}
					if t := c.String("type"); t != "" {
						req.MapTypes = []string{t}
					}
					_, err := clients.Stats.StatsSlotReset(context.Background(), connect.NewRequest(req))
					if err != nil {
						return err
					}
					fmt.Println("Slot stats counters reset.")
					return nil
				},
			},
		},
	}
}

// filterPluginSlots keeps only entries whose slot is in the plugin range.
func filterPluginSlots(in []*v1.SlotStatsEntry) []*v1.SlotStatsEntry {
	out := in[:0]
	for _, e := range in {
		switch e.MapType {
		case bpf.MapTypeEndpoint:
			if e.Slot >= bpf.EndpointPluginBase {
				out = append(out, e)
			}
		case bpf.MapTypeHeadendV4, bpf.MapTypeHeadendV6:
			if e.Slot >= bpf.HeadendPluginBase {
				out = append(out, e)
			}
		}
	}
	return out
}
