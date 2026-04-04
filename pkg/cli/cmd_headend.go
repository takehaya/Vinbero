package cli

import (
	"context"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/urfave/cli/v2"
)

func headendV4Command() *cli.Command {
	return &cli.Command{
		Name:    "headend-v4",
		Aliases: []string{"hv4"},
		Usage:   "Manage SRv6 Headend for IPv4",
		Subcommands: []*cli.Command{
			{
				Name:  "create",
				Usage: "Create a Headend v4 entry",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "trigger-prefix", Required: true, Usage: "IPv4 CIDR (e.g., 10.0.0.0/24)"},
					&cli.StringFlag{Name: "src-addr", Required: true, Usage: "Outer IPv6 source address"},
					&cli.StringFlag{Name: "segments", Required: true, Usage: "Segment list (comma-separated)"},
					&cli.StringFlag{Name: "mode", Value: "H_ENCAPS", Usage: "Headend mode (H_ENCAPS, H_INSERT)"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					mode, err := resolveMode(c.String("mode"))
					if err != nil {
						return err
					}
					entry := &v1.Headendv4{
						Mode:          mode,
						TriggerPrefix: c.String("trigger-prefix"),
						SrcAddr:       c.String("src-addr"),
						Segments:      strings.Split(c.String("segments"), ","),
					}
					resp, err := clients.Hv4.Headendv4Create(context.Background(),
						connect.NewRequest(&v1.Headendv4CreateRequest{Headendv4S: []*v1.Headendv4{entry}}))
					if err != nil {
						return err
					}
					return printOperationResult(resp.Msg.Created, resp.Msg.Errors, "Headend v4")
				},
			},
			{
				Name:  "delete",
				Usage: "Delete a Headend v4 entry",
				Flags: []cli.Flag{&cli.StringFlag{Name: "trigger-prefix", Required: true}},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Hv4.Headendv4Delete(context.Background(),
						connect.NewRequest(&v1.Headendv4DeleteRequest{TriggerPrefixes: []string{c.String("trigger-prefix")}}))
					if err != nil {
						return err
					}
					fmt.Printf("Deleted: %s\n", strings.Join(resp.Msg.DeletedTriggerPrefixes, ", "))
					return nil
				},
			},
			{
				Name:  "list",
				Usage: "List all Headend v4 entries",
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Hv4.Headendv4List(context.Background(),
						connect.NewRequest(&v1.Headendv4ListRequest{}))
					if err != nil {
						return err
					}
					if useJSON(c) {
						return printJSON(resp.Msg.Headendv4S)
					}
					headers := []string{"TRIGGER PREFIX", "MODE", "SRC ADDR", "SEGMENTS"}
					var rows [][]string
					for _, h := range resp.Msg.Headendv4S {
						rows = append(rows, []string{
							h.TriggerPrefix, formatMode(h.Mode), h.SrcAddr, strings.Join(h.Segments, ","),
						})
					}
					printTable(headers, rows)
					return nil
				},
			},
		},
	}
}

func headendV6Command() *cli.Command {
	return &cli.Command{
		Name:    "headend-v6",
		Aliases: []string{"hv6"},
		Usage:   "Manage SRv6 Headend for IPv6",
		Subcommands: []*cli.Command{
			{
				Name:  "create",
				Usage: "Create a Headend v6 entry",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "trigger-prefix", Required: true, Usage: "IPv6 CIDR"},
					&cli.StringFlag{Name: "src-addr", Required: true},
					&cli.StringFlag{Name: "segments", Required: true, Usage: "Segment list (comma-separated)"},
					&cli.StringFlag{Name: "mode", Value: "H_ENCAPS"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					mode, err := resolveMode(c.String("mode"))
					if err != nil {
						return err
					}
					entry := &v1.Headendv6{
						Mode:          mode,
						TriggerPrefix: c.String("trigger-prefix"),
						SrcAddr:       c.String("src-addr"),
						Segments:      strings.Split(c.String("segments"), ","),
					}
					resp, err := clients.Hv6.Headendv6Create(context.Background(),
						connect.NewRequest(&v1.Headendv6CreateRequest{Headendv6S: []*v1.Headendv6{entry}}))
					if err != nil {
						return err
					}
					return printOperationResult(resp.Msg.Created, resp.Msg.Errors, "Headend v6")
				},
			},
			{
				Name:  "delete",
				Usage: "Delete a Headend v6 entry",
				Flags: []cli.Flag{&cli.StringFlag{Name: "trigger-prefix", Required: true}},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Hv6.Headendv6Delete(context.Background(),
						connect.NewRequest(&v1.Headendv6DeleteRequest{TriggerPrefixes: []string{c.String("trigger-prefix")}}))
					if err != nil {
						return err
					}
					fmt.Printf("Deleted: %s\n", strings.Join(resp.Msg.DeletedTriggerPrefixes, ", "))
					return nil
				},
			},
			{
				Name:  "list",
				Usage: "List all Headend v6 entries",
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Hv6.Headendv6List(context.Background(),
						connect.NewRequest(&v1.Headendv6ListRequest{}))
					if err != nil {
						return err
					}
					if useJSON(c) {
						return printJSON(resp.Msg.Headendv6S)
					}
					headers := []string{"TRIGGER PREFIX", "MODE", "SRC ADDR", "SEGMENTS"}
					var rows [][]string
					for _, h := range resp.Msg.Headendv6S {
						rows = append(rows, []string{
							h.TriggerPrefix, formatMode(h.Mode), h.SrcAddr, strings.Join(h.Segments, ","),
						})
					}
					printTable(headers, rows)
					return nil
				},
			},
		},
	}
}

func headendL2Command() *cli.Command {
	return &cli.Command{
		Name:    "headend-l2",
		Aliases: []string{"hl2"},
		Usage:   "Manage SRv6 Headend for L2 frames",
		Subcommands: []*cli.Command{
			{
				Name:  "create",
				Usage: "Create a Headend L2 entry",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "interface", Required: true, Usage: "Customer-facing interface name"},
					&cli.UintFlag{Name: "vlan-id", Required: true, Usage: "VLAN ID (0 for untagged)"},
					&cli.StringFlag{Name: "src-addr", Required: true, Usage: "Outer IPv6 source address"},
					&cli.StringFlag{Name: "segments", Required: true, Usage: "Segment list (comma-separated)"},
					&cli.UintFlag{Name: "bd-id", Usage: "Bridge Domain ID (0 = direct encap)"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					entry := &v1.HeadendL2{
						InterfaceName: c.String("interface"),
						VlanId:        uint32(c.Uint("vlan-id")),
						SrcAddr:       c.String("src-addr"),
						Segments:      strings.Split(c.String("segments"), ","),
						BdId:          uint32(c.Uint("bd-id")),
					}
					resp, err := clients.Hl2.HeadendL2Create(context.Background(),
						connect.NewRequest(&v1.HeadendL2CreateRequest{HeadendL2S: []*v1.HeadendL2{entry}}))
					if err != nil {
						return err
					}
					return printOperationResult(resp.Msg.Created, resp.Msg.Errors, "Headend L2")
				},
			},
			{
				Name:  "delete",
				Usage: "Delete a Headend L2 entry",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "interface", Required: true},
					&cli.UintFlag{Name: "vlan-id", Required: true},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					target := &v1.HeadendL2DeleteTarget{
						InterfaceName: c.String("interface"),
						VlanId:        uint32(c.Uint("vlan-id")),
					}
					resp, err := clients.Hl2.HeadendL2Delete(context.Background(),
						connect.NewRequest(&v1.HeadendL2DeleteRequest{Targets: []*v1.HeadendL2DeleteTarget{target}}))
					if err != nil {
						return err
					}
					for _, d := range resp.Msg.Deleted {
						fmt.Printf("Deleted: %s vlan=%d\n", d.InterfaceName, d.VlanId)
					}
					return nil
				},
			},
			{
				Name:  "list",
				Usage: "List all Headend L2 entries",
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Hl2.HeadendL2List(context.Background(),
						connect.NewRequest(&v1.HeadendL2ListRequest{}))
					if err != nil {
						return err
					}
					if useJSON(c) {
						return printJSON(resp.Msg.HeadendL2S)
					}
					headers := []string{"INTERFACE", "VLAN", "SRC ADDR", "SEGMENTS", "BD_ID"}
					var rows [][]string
					for _, h := range resp.Msg.HeadendL2S {
						rows = append(rows, []string{
							h.InterfaceName,
							fmt.Sprintf("%d", h.VlanId),
							h.SrcAddr,
							strings.Join(h.Segments, ","),
							fmt.Sprintf("%d", h.BdId),
						})
					}
					printTable(headers, rows)
					return nil
				},
			},
		},
	}
}
