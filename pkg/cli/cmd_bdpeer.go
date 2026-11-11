package cli

import (
	"context"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/urfave/cli/v2"
)

func bdPeerCommand() *cli.Command {
	return &cli.Command{
		Name:    "bd-peer",
		Aliases: []string{"peer"},
		Usage:   "Manage Bridge Domain remote PEs",
		Subcommands: []*cli.Command{
			{
				Name:  "create",
				Usage: "Register a remote PE in a Bridge Domain",
				Description: "The peer takes one of the Bridge Domain's 32 flood slots: BUM frames are copied to it,\n" +
					"and MACs learned from its source address are forwarded to it. The flood slots are shared\n" +
					"with the EVPN RT3 (End.DT2M) peers BGP installs and the plugins' flood peers. EVPN RT2\n" +
					"(End.DT2U) peers do not take a flood slot, so a Bridge Domain reaches 32 remote PEs\n" +
					"(33 nodes) when no peer is created here. The create fails when all flood slots are in use.",
				Flags: []cli.Flag{
					&cli.UintFlag{Name: "bd-id", Required: true, Usage: "Bridge Domain ID"},
					&cli.StringFlag{Name: "src-addr", Required: true, Usage: "Outer IPv6 source address"},
					&cli.StringFlag{Name: "segments", Required: true, Usage: "Segment list (comma-separated)"},
					&cli.StringFlag{Name: "mode", Value: "H_ENCAPS_L2", Usage: "Headend mode (H_ENCAPS_L2, H_ENCAPS_L2_RED)"},
					&cli.StringFlag{Name: "esi", Usage: esiUsage},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					mode, err := resolveMode(c.String("mode"))
					if err != nil {
						return err
					}
					peer := &v1.BdPeer{
						BdId:     uint32(c.Uint("bd-id")),
						SrcAddr:  c.String("src-addr"),
						Segments: strings.Split(c.String("segments"), ","),
						Mode:     mode,
						Esi:      c.String("esi"),
					}
					resp, err := clients.Peer.BdPeerCreate(context.Background(),
						connect.NewRequest(&v1.BdPeerCreateRequest{Peers: []*v1.BdPeer{peer}}))
					if err != nil {
						return err
					}
					return printOperationResult(resp.Msg.Created, resp.Msg.Errors, "BD peer")
				},
			},
			{
				Name:  "delete",
				Usage: "Delete all peers for a Bridge Domain",
				Flags: []cli.Flag{
					&cli.UintFlag{Name: "bd-id", Required: true},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Peer.BdPeerDelete(context.Background(),
						connect.NewRequest(&v1.BdPeerDeleteRequest{BdIds: []uint32{uint32(c.Uint("bd-id"))}}))
					if err != nil {
						return err
					}
					for _, id := range resp.Msg.DeletedBdIds {
						fmt.Printf("Deleted peers for BD %d\n", id)
					}
					return nil
				},
			},
			{
				Name:  "flush",
				Usage: "Delete BD peers (requires --yes)",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "yes", Required: true, Usage: "Confirm the destructive operation"},
					&cli.UintFlag{Name: "bd-id", Usage: "Only flush this BD (default: all BDs)"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Peer.BdPeerFlush(context.Background(),
						connect.NewRequest(&v1.BdPeerFlushRequest{BdId: uint32(c.Uint("bd-id"))}))
					if err != nil {
						return err
					}
					fmt.Printf("Flushed %d BD peers\n", resp.Msg.DeletedCount)
					return nil
				},
			},
			{
				Name:  "list",
				Usage: "List Bridge Domain peers",
				Flags: []cli.Flag{
					&cli.UintFlag{Name: "bd-id", Usage: "Filter by BD ID (0 = all)"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Peer.BdPeerList(context.Background(),
						connect.NewRequest(&v1.BdPeerListRequest{BdId: uint32(c.Uint("bd-id"))}))
					if err != nil {
						return err
					}
					if useJSON(c) {
						return printJSON(resp.Msg.Peers)
					}
					headers := []string{"BD_ID", "SRC ADDR", "SEGMENTS", "MODE", "ESI"}
					var rows [][]string
					for _, p := range resp.Msg.Peers {
						rows = append(rows, []string{
							fmt.Sprintf("%d", p.BdId), p.SrcAddr, strings.Join(p.Segments, ","), formatMode(p.Mode), p.Esi,
						})
					}
					printTable(headers, rows)
					return nil
				},
			},
		},
	}
}
