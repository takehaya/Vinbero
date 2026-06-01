package cli

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/urfave/cli/v2"
)

// reportMUP reports a single-item create/update/delete result: success iff no
// per-item error came back (each CLI mutation submits exactly one route).
func reportMUP(errs []*v1.OperationError, verb string) error {
	var ok []struct{}
	if len(errs) == 0 {
		ok = []struct{}{{}}
	}
	return printOperationResult(ok, errs, "MUP route", verb)
}

func mupCommand() *cli.Command {
	// Create/update share the full MUP route flags, but --next-hop is optional:
	// it defaults to the server's bgp.global.next_hop when omitted.
	defFlags := []cli.Flag{
		&cli.StringFlag{Name: "route-type", Required: true, Usage: "isd | dsd | t1st | t2st"},
		&cli.StringFlag{Name: "rd", Required: true, Usage: "Route distinguisher, e.g. 65000:100"},
		&cli.StringFlag{Name: "route-targets", Usage: "Export route targets (comma-separated)"},
		&cli.StringFlag{Name: "prefix", Usage: "isd segment prefix / t1st UE prefix (CIDR)"},
		&cli.StringFlag{Name: "address", Usage: "dsd direct-segment endpoint address"},
		&cli.UintFlag{Name: "teid", Usage: "GTP-U TEID (t1st exact / t2st prefix value)"},
		&cli.UintFlag{Name: "teid-len", Value: 32, Usage: "t2st significant TEID prefix bits (t1st: 32)"},
		&cli.UintFlag{Name: "qfi", Usage: "t1st QoS Flow Identifier"},
		&cli.UintFlag{Name: "rqi", Usage: "t1st Reflective QoS Indicator"},
		&cli.StringFlag{Name: "endpoint", Usage: "t1st gNB N3 address / t2st GTP tunnel endpoint"},
		&cli.StringFlag{Name: "source", Usage: "t1st optional source address"},
		&cli.UintFlag{Name: "segment-id2", Usage: "MUP Extended Community segment id (16-bit half)"},
		&cli.UintFlag{Name: "segment-id4", Usage: "MUP Extended Community segment id (32-bit half)"},
		&cli.StringFlag{Name: "sid", Usage: "Segment SRv6 SID (IPv6)"},
		&cli.StringFlag{Name: "next-hop", Usage: "BGP next hop (IPv6); defaults to bgp.global.next_hop"},
	}
	// Delete only needs the route type + the type's identifying fields.
	keyFlags := []cli.Flag{
		&cli.StringFlag{Name: "route-type", Required: true, Usage: "isd | dsd | t1st | t2st"},
		&cli.StringFlag{Name: "rd", Required: true, Usage: "Route distinguisher"},
		&cli.StringFlag{Name: "prefix", Usage: "isd segment prefix / t1st UE prefix (CIDR)"},
		&cli.StringFlag{Name: "address", Usage: "dsd direct-segment endpoint address"},
		&cli.UintFlag{Name: "teid", Usage: "GTP-U TEID (t1st / t2st)"},
		&cli.UintFlag{Name: "teid-len", Value: 32, Usage: "t2st TEID prefix bits"},
		&cli.StringFlag{Name: "endpoint", Usage: "t2st GTP tunnel endpoint"},
	}
	return &cli.Command{
		Name:  "mup",
		Usage: "Manage local BGP MUP routes (SAFI 85) and auto-advertise them",
		Subcommands: []*cli.Command{
			{
				Name:  "create",
				Usage: "Define a local MUP route and advertise it into BGP",
				Flags: defFlags,
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Mup.MupCreate(context.Background(),
						connect.NewRequest(&v1.MupCreateRequest{Routes: []*v1.BgpMupRoute{mupRouteFromFlags(c)}}))
					if err != nil {
						return err
					}
					return reportMUP(resp.Msg.Errors, "created")
				},
			},
			{
				Name:  "update",
				Usage: "Replace a local MUP route (re-advertises)",
				Flags: defFlags,
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Mup.MupUpdate(context.Background(),
						connect.NewRequest(&v1.MupUpdateRequest{Routes: []*v1.BgpMupRoute{mupRouteFromFlags(c)}}))
					if err != nil {
						return err
					}
					return reportMUP(resp.Msg.Errors, "updated")
				},
			},
			{
				Name:  "delete",
				Usage: "Delete a local MUP route (withdraws it from BGP)",
				Flags: keyFlags,
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Mup.MupDelete(context.Background(),
						connect.NewRequest(&v1.MupDeleteRequest{Routes: []*v1.BgpMupRoute{mupRouteFromFlags(c)}}))
					if err != nil {
						return err
					}
					return reportMUP(resp.Msg.Errors, "deleted")
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
