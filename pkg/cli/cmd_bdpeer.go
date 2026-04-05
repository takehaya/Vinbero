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
				Flags: []cli.Flag{
					&cli.UintFlag{Name: "bd-id", Required: true, Usage: "Bridge Domain ID"},
					&cli.StringFlag{Name: "src-addr", Required: true, Usage: "Outer IPv6 source address"},
					&cli.StringFlag{Name: "segments", Required: true, Usage: "Segment list (comma-separated)"},
					&cli.StringFlag{Name: "mode", Value: "H_ENCAPS_L2", Usage: "Headend mode (H_ENCAPS_L2, H_ENCAPS_L2_RED)"},
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
					headers := []string{"BD_ID", "SRC ADDR", "SEGMENTS", "MODE"}
					var rows [][]string
					for _, p := range resp.Msg.Peers {
						rows = append(rows, []string{
							fmt.Sprintf("%d", p.BdId), p.SrcAddr, strings.Join(p.Segments, ","), formatMode(p.Mode),
						})
					}
					printTable(headers, rows)
					return nil
				},
			},
		},
	}
}
