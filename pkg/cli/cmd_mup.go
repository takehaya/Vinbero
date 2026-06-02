package cli

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/urfave/cli/v2"
)

func mupCommand() *cli.Command {
	return &cli.Command{
		Name:  "mup",
		Usage: "Manage local BGP MUP routes (SAFI 85) and auto-advertise them",
		Subcommands: []*cli.Command{
			{
				Name:  "create",
				Usage: "Define a local MUP route and advertise it into BGP",
				Flags: mupRouteFlags(false),
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Mup.MupCreate(context.Background(),
						connect.NewRequest(&v1.MupCreateRequest{Routes: []*v1.BgpMupRoute{mupRouteFromFlags(c)}}))
					if err != nil {
						return err
					}
					return reportSingle(resp.Msg.Errors, "MUP route", "created")
				},
			},
			{
				Name:  "update",
				Usage: "Replace a local MUP route (re-advertises)",
				Flags: mupRouteFlags(false),
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Mup.MupUpdate(context.Background(),
						connect.NewRequest(&v1.MupUpdateRequest{Routes: []*v1.BgpMupRoute{mupRouteFromFlags(c)}}))
					if err != nil {
						return err
					}
					return reportSingle(resp.Msg.Errors, "MUP route", "updated")
				},
			},
			{
				Name:  "delete",
				Usage: "Delete a local MUP route (withdraws it from BGP)",
				Flags: mupKeyFlags(),
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Mup.MupDelete(context.Background(),
						connect.NewRequest(&v1.MupDeleteRequest{Routes: []*v1.BgpMupRoute{mupRouteFromFlags(c)}}))
					if err != nil {
						return err
					}
					return reportSingle(resp.Msg.Errors, "MUP route", "deleted")
				},
			},
			{
				Name:  "list",
				Usage: "List the MUP routes this node originates",
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Mup.MupList(context.Background(),
						connect.NewRequest(&v1.MupListRequest{}))
					if err != nil {
						return err
					}
					if useJSON(c) {
						return printJSON(resp.Msg.Routes)
					}
					headers := []string{"TYPE", "RD", "PREFIX/ADDR/ENDPOINT", "TEID", "NEXT_HOP", "SID"}
					var rows [][]string
					for _, r := range resp.Msg.Routes {
						rows = append(rows, []string{
							r.GetRouteType(),
							r.GetRd(),
							mupListLocator(r),
							fmt.Sprintf("%d", r.GetTeid()),
							r.GetNextHop(),
							r.GetSrv6Sid(),
						})
					}
					printTable(headers, rows)
					return nil
				},
			},
		},
	}
}

// mupListLocator picks the field that locates a MUP route by type, for the
// single PREFIX/ADDR/ENDPOINT list column.
func mupListLocator(r *v1.BgpMupRoute) string {
	switch r.GetRouteType() {
	case "dsd":
		return r.GetAddress()
	case "t2st":
		return r.GetEndpoint()
	default: // isd / t1st
		return r.GetPrefix()
	}
}
