package cli

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"connectrpc.com/connect"
	"github.com/urfave/cli/v2"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

func headendGroupCommand() *cli.Command {
	return &cli.Command{
		Name:    "headend-group",
		Aliases: []string{"hgroup"},
		Usage:   "Inspect the ECMP path groups the headend resolves through",
		Subcommands: []*cli.Command{
			{
				Name:  "list",
				Usage: "List every ECMP path group",
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.HGroup.HeadendGroupList(context.Background(),
						connect.NewRequest(&v1.HeadendGroupListRequest{}))
					if err != nil {
						return err
					}
					if useJSON(c) {
						return printJSON(resp.Msg.Groups)
					}
					headers := []string{"GROUP", "PREFIXES", "PATHS", "LIVE", "OWNER"}
					var rows [][]string
					for _, g := range resp.Msg.Groups {
						rows = append(rows, []string{
							strconv.FormatUint(uint64(g.GroupId), 10),
							joinOrDash(g.Prefixes),
							strconv.Itoa(len(g.Members)),
							liveSummary(g),
							g.Owner,
						})
					}
					printTable(headers, rows)
					return nil
				},
			},
			{
				Name:      "get",
				Usage:     "Show one group's members",
				ArgsUsage: "<group-id>",
				Action: func(c *cli.Context) error {
					if c.NArg() != 1 {
						return fmt.Errorf("usage: headend-group get <group-id>")
					}
					id, err := strconv.ParseUint(c.Args().First(), 10, 32)
					if err != nil {
						return fmt.Errorf("group id %q: %w", c.Args().First(), err)
					}
					clients := clientsFromContext(c)
					resp, err := clients.HGroup.HeadendGroupGet(context.Background(),
						connect.NewRequest(&v1.HeadendGroupGetRequest{GroupId: uint32(id)}))
					if err != nil {
						return err
					}
					g := resp.Msg.Group
					if useJSON(c) {
						return printJSON(g)
					}
					fmt.Printf("Group:    %d\n", g.GroupId)
					fmt.Printf("Prefixes: %s\n", joinOrDash(g.Prefixes))
					fmt.Printf("Owner:    %s\n", g.Owner)
					fmt.Printf("Liveness: %s\n", liveSummary(g))
					headers := []string{"INDEX", "SEGMENTS", "WEIGHT", "POLICY", "LIVE"}
					var rows [][]string
					for _, m := range g.Members {
						policy := "-"
						if m.PolicyId != 0 {
							policy = strconv.FormatUint(uint64(m.PolicyId), 10)
						}
						rows = append(rows, []string{
							strconv.FormatUint(uint64(m.Index), 10),
							joinOrDash(m.Segments),
							strconv.FormatUint(uint64(m.Weight), 10),
							policy,
							boolYesNo(m.Live),
						})
					}
					printTable(headers, rows)
					return nil
				},
			},
		},
	}
}

// liveSummary distinguishes "no prober has reported" from a real bitmap.
// They look the same in the data plane (both use every path) but mean very
// different things when an operator is asking why traffic moved.
func liveSummary(g *v1.HeadendGroup) string {
	if !g.LiveKnown {
		return "unprobed"
	}
	up := 0
	for _, m := range g.Members {
		if m.Live {
			up++
		}
	}
	return fmt.Sprintf("%d/%d up", up, len(g.Members))
}

func joinOrDash(v []string) string {
	if len(v) == 0 {
		return "-"
	}
	return strings.Join(v, ",")
}

func boolYesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
