package cli

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/urfave/cli/v2"
)

func esCommand() *cli.Command {
	return &cli.Command{
		Name:    "es",
		Aliases: []string{"ethernet-segment"},
		Usage:   "Manage RFC 7432 Ethernet Segments (ESI master table)",
		Subcommands: []*cli.Command{
			{
				Name:  "create",
				Usage: "Register an Ethernet Segment",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "esi", Required: true, Usage: "RFC 7432 ESI (10 colon-separated hex bytes)"},
					&cli.BoolFlag{Name: "local-attached", Usage: "This PE attaches to the ES"},
					&cli.StringFlag{Name: "local-pe", Usage: "Local PE IPv6 (required when --local-attached, used for DF judgement)"},
					&cli.StringFlag{Name: "df-pe", Usage: "Initial Designated Forwarder IPv6 (optional; set later with df-set)"},
					&cli.StringFlag{Name: "mode", Value: "ALL_ACTIVE", Usage: "Redundancy mode: SINGLE_HOMING, ALL_ACTIVE, SINGLE_ACTIVE"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					mode, err := resolveEsiMode(c.String("mode"))
					if err != nil {
						return err
					}
					entry := &v1.EthernetSegment{
						Esi:             c.String("esi"),
						LocalAttached:   c.Bool("local-attached"),
						LocalPeSrcAddr:  c.String("local-pe"),
						DfPeSrcAddr:     c.String("df-pe"),
						RedundancyMode:  mode,
					}
					resp, err := clients.Es.EsCreate(context.Background(),
						connect.NewRequest(&v1.EsCreateRequest{Entries: []*v1.EthernetSegment{entry}}))
					if err != nil {
						return err
					}
					return printOperationResult(resp.Msg.Created, resp.Msg.Errors, "Ethernet Segment")
				},
			},
			{
				Name:  "delete",
				Usage: "Delete Ethernet Segments by ESI",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "esi", Required: true, Usage: "ESI to delete"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Es.EsDelete(context.Background(),
						connect.NewRequest(&v1.EsDeleteRequest{Esis: []string{c.String("esi")}}))
					if err != nil {
						return err
					}
					for _, esi := range resp.Msg.Deleted {
						fmt.Printf("Deleted ES %s\n", esi)
					}
					return nil
				},
			},
			{
				Name:  "list",
				Usage: "List Ethernet Segments",
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Es.EsList(context.Background(),
						connect.NewRequest(&v1.EsListRequest{}))
					if err != nil {
						return err
					}
					if useJSON(c) {
						return printJSON(resp.Msg.Entries)
					}
					headers := []string{"ESI", "LOCAL_ATTACHED", "LOCAL_PE", "DF_PE", "MODE"}
					var rows [][]string
					for _, e := range resp.Msg.Entries {
						rows = append(rows, []string{
							e.Esi,
							fmt.Sprintf("%t", e.LocalAttached),
							e.LocalPeSrcAddr,
							e.DfPeSrcAddr,
							formatEsiMode(e.RedundancyMode),
						})
					}
					printTable(headers, rows)
					return nil
				},
			},
			{
				Name:  "df-set",
				Usage: "Promote a PE to Designated Forwarder for an ES",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "esi", Required: true, Usage: "ESI"},
					&cli.StringFlag{Name: "pe", Required: true, Usage: "DF PE IPv6"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Es.EsSetDf(context.Background(),
						connect.NewRequest(&v1.EsSetDfRequest{Esi: c.String("esi"), DfPeSrcAddr: c.String("pe")}))
					if err != nil {
						return err
					}
					fmt.Printf("DF set: esi=%s df_pe=%s\n", resp.Msg.Updated.Esi, resp.Msg.Updated.DfPeSrcAddr)
					return nil
				},
			},
			{
				Name:  "df-clear",
				Usage: "Clear Designated Forwarder for an ES (all attached PEs forward BUM)",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "esi", Required: true},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Es.EsClearDf(context.Background(),
						connect.NewRequest(&v1.EsClearDfRequest{Esi: c.String("esi")}))
					if err != nil {
						return err
					}
					fmt.Printf("DF cleared: esi=%s\n", resp.Msg.Updated.Esi)
					return nil
				},
			},
		},
	}
}

func resolveEsiMode(s string) (v1.EsiRedundancyMode, error) {
	return resolveProtoEnum[v1.EsiRedundancyMode](s, "ESI_REDUNDANCY_MODE_", v1.EsiRedundancyMode_value)
}

func formatEsiMode(m v1.EsiRedundancyMode) string {
	return formatProtoEnum(m, "ESI_REDUNDANCY_MODE_")
}
