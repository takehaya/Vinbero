package cli

import (
	"context"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/urfave/cli/v2"
)

func resolveLocatorBehavior(s string) (v1.LocatorBehaviorMode, error) {
	return resolveProtoEnum[v1.LocatorBehaviorMode](s, "LOCATOR_BEHAVIOR_MODE_", v1.LocatorBehaviorMode_value)
}

func formatLocatorBehavior(b v1.LocatorBehaviorMode) string {
	return formatProtoEnum(b, "LOCATOR_BEHAVIOR_MODE_")
}

func locatorCommand() *cli.Command {
	return &cli.Command{
		Name:    "locator",
		Aliases: []string{"loc"},
		Usage:   "Manage SRv6 locators",
		Subcommands: []*cli.Command{
			{
				Name:  "create",
				Usage: "Register a locator from which SIDs are allocated",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Required: true, Usage: "Locator name (operator-chosen)"},
					&cli.StringFlag{Name: "prefix", Required: true, Usage: "IPv6 prefix, e.g. fd00:1:1::/48"},
					&cli.UintFlag{Name: "block-len", Required: true, Usage: "Locator-block length in bits"},
					&cli.UintFlag{Name: "node-len", Required: true, Usage: "Locator-node length in bits"},
					&cli.UintFlag{Name: "function-len", Required: true, Usage: "Function length in bits"},
					&cli.UintFlag{Name: "argument-len", Value: 0, Usage: "Argument length in bits"},
					&cli.StringFlag{Name: "behavior", Value: "classic", Usage: "SID layout: classic | usid"},
					&cli.UintFlag{Name: "function-auto-start", Value: 0x10, Usage: "Auto-allocator lower bound"},
					&cli.UintFlag{Name: "function-auto-end", Value: 0xFFFE, Usage: "Auto-allocator upper bound"},
				},
				Action: func(c *cli.Context) error {
					behavior, err := resolveLocatorBehavior(c.String("behavior"))
					if err != nil {
						return err
					}
					loc := &v1.Locator{
						Name:              c.String("name"),
						Prefix:            c.String("prefix"),
						BlockLen:          uint32(c.Uint("block-len")),
						NodeLen:           uint32(c.Uint("node-len")),
						FunctionLen:       uint32(c.Uint("function-len")),
						ArgumentLen:       uint32(c.Uint("argument-len")),
						Behavior:          behavior,
						FunctionAutoStart: uint32(c.Uint("function-auto-start")),
						FunctionAutoEnd:   uint32(c.Uint("function-auto-end")),
					}
					clients := clientsFromContext(c)
					resp, err := clients.Locator.LocatorCreate(context.Background(),
						connect.NewRequest(&v1.LocatorCreateRequest{Locators: []*v1.Locator{loc}}))
					if err != nil {
						return err
					}
					return printOperationResult(resp.Msg.Created, resp.Msg.Errors, "Locator")
				},
			},
			{
				Name:  "delete",
				Usage: "Delete a locator",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Required: true},
					&cli.BoolFlag{Name: "force", Usage: "Drop the locator even if SIDs still reference it"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Locator.LocatorDelete(context.Background(),
						connect.NewRequest(&v1.LocatorDeleteRequest{
							Names: []string{c.String("name")},
							Force: c.Bool("force"),
						}))
					if err != nil {
						return err
					}
					if len(resp.Msg.Errors) > 0 {
						for _, e := range resp.Msg.Errors {
							fmt.Printf("error: %s: %s\n", e.TriggerPrefix, e.Reason)
						}
					}
					fmt.Printf("Deleted: %s\n", strings.Join(resp.Msg.DeletedNames, ", "))
					return nil
				},
			},
			{
				Name:  "list",
				Usage: "List registered locators",
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Locator.LocatorList(context.Background(),
						connect.NewRequest(&v1.LocatorListRequest{}))
					if err != nil {
						return err
					}
					if useJSON(c) {
						return printJSON(resp.Msg.Locators)
					}
					headers := []string{"NAME", "PREFIX", "BEHAVIOR", "BLOCK", "NODE", "FUNC", "ARG", "AUTO_RANGE"}
					var rows [][]string
					for _, l := range resp.Msg.Locators {
						rows = append(rows, []string{
							l.Name, l.Prefix, formatLocatorBehavior(l.Behavior),
							fmt.Sprintf("%d", l.BlockLen),
							fmt.Sprintf("%d", l.NodeLen),
							fmt.Sprintf("%d", l.FunctionLen),
							fmt.Sprintf("%d", l.ArgumentLen),
							fmt.Sprintf("0x%x..0x%x", l.FunctionAutoStart, l.FunctionAutoEnd),
						})
					}
					printTable(headers, rows)
					return nil
				},
			},
			{
				Name:  "get",
				Usage: "Show a single locator",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Required: true},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Locator.LocatorGet(context.Background(),
						connect.NewRequest(&v1.LocatorGetRequest{Name: c.String("name")}))
					if err != nil {
						return err
					}
					if useJSON(c) {
						return printJSON(resp.Msg.Locator)
					}
					l := resp.Msg.Locator
					fmt.Printf("Name:           %s\n", l.Name)
					fmt.Printf("Prefix:         %s\n", l.Prefix)
					fmt.Printf("Behavior:       %s\n", formatLocatorBehavior(l.Behavior))
					fmt.Printf("Block / Node:   %d / %d\n", l.BlockLen, l.NodeLen)
					fmt.Printf("Func / Arg:     %d / %d\n", l.FunctionLen, l.ArgumentLen)
					fmt.Printf("Auto range:     0x%x .. 0x%x\n", l.FunctionAutoStart, l.FunctionAutoEnd)
					return nil
				},
			},
		},
	}
}

