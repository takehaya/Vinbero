package cli

import (
	"context"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/urfave/cli/v2"
)

func bgpCommand() *cli.Command {
	return &cli.Command{
		Name:  "bgp",
		Usage: "Advertise and withdraw BGP routes",
		Subcommands: []*cli.Command{
			{
				Name:  "advertise-vpn",
				Usage: "Advertise a VPNv4/VPNv6 route with an SRv6 service SID",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "family", Value: "vpnv4", Usage: "vpnv4 | vpnv6"},
					&cli.StringFlag{Name: "prefix", Required: true, Usage: "VPN prefix CIDR"},
					&cli.StringFlag{Name: "rd", Required: true, Usage: "Route distinguisher, e.g. 65000:100"},
					&cli.StringFlag{Name: "rts", Usage: "Route targets (comma-separated)"},
					&cli.StringFlag{Name: "sid", Required: true, Usage: "SRv6 service SID (IPv6)"},
					&cli.StringFlag{Name: "next-hop", Required: true},
				},
				Action: func(c *cli.Context) error {
					r := &v1.BgpVpnRoute{
						Family:       c.String("family"),
						Prefix:       c.String("prefix"),
						Rd:           c.String("rd"),
						RouteTargets: csvFlag(c.String("rts")),
						Srv6Sid:      c.String("sid"),
						NextHop:      c.String("next-hop"),
					}
					clients := clientsFromContext(c)
					resp, err := clients.BgpRoute.BgpAdvertiseVpn(context.Background(),
						connect.NewRequest(&v1.BgpAdvertiseVpnRequest{Routes: []*v1.BgpVpnRoute{r}}))
					if err != nil {
						return err
					}
					return printOperationResult(resp.Msg.Advertised, resp.Msg.Errors, "BgpVpnRoute", "advertised")
				},
			},
			{
				Name:  "advertise-unicast",
				Usage: "Advertise an IPv6 unicast route",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "prefix", Required: true, Usage: "IPv6 prefix CIDR"},
					&cli.StringFlag{Name: "next-hop", Required: true},
				},
				Action: func(c *cli.Context) error {
					r := &v1.BgpUnicastRoute{
						Prefix:  c.String("prefix"),
						NextHop: c.String("next-hop"),
					}
					clients := clientsFromContext(c)
					resp, err := clients.BgpRoute.BgpAdvertiseUnicast(context.Background(),
						connect.NewRequest(&v1.BgpAdvertiseUnicastRequest{Routes: []*v1.BgpUnicastRoute{r}}))
					if err != nil {
						return err
					}
					return printOperationResult(resp.Msg.Advertised, resp.Msg.Errors, "BgpUnicastRoute", "advertised")
				},
			},
			{
				Name:  "withdraw",
				Usage: "Withdraw a previously advertised route",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "family", Required: true, Usage: "vpnv4 | vpnv6 | ipv6_unicast"},
					&cli.StringFlag{Name: "prefix", Required: true},
					&cli.StringFlag{Name: "rd", Usage: "Route distinguisher (VPN families only)"},
				},
				Action: func(c *cli.Context) error {
					k := &v1.BgpRouteKey{
						Family: c.String("family"),
						Prefix: c.String("prefix"),
						Rd:     c.String("rd"),
					}
					clients := clientsFromContext(c)
					resp, err := clients.BgpRoute.BgpWithdraw(context.Background(),
						connect.NewRequest(&v1.BgpWithdrawRequest{Keys: []*v1.BgpRouteKey{k}}))
					if err != nil {
						return err
					}
					return printOperationResult(resp.Msg.Withdrawn, resp.Msg.Errors, "BgpRouteKey", "withdrawn")
				},
			},
		},
	}
}
