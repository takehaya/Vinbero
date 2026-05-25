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
					&cli.UintFlag{Name: "color", Usage: "Color Extended Community for SR Policy steering (0 = none)"},
				},
				Action: func(c *cli.Context) error {
					r := &v1.BgpVpnRoute{
						Family:       c.String("family"),
						Prefix:       c.String("prefix"),
						Rd:           c.String("rd"),
						RouteTargets: csvFlag(c.String("rts")),
						Srv6Sid:      c.String("sid"),
						NextHop:      c.String("next-hop"),
						Color:        uint32(c.Uint("color")),
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
			{
				Name:  "advertise-sr-policy",
				Usage: "Advertise a local SR Policy (SAFI 73)",
				Flags: []cli.Flag{
					&cli.UintFlag{Name: "color", Required: true, Usage: "SR Policy color"},
					&cli.StringFlag{Name: "endpoint", Required: true, Usage: "SR Policy endpoint (IPv6)"},
					&cli.StringFlag{Name: "segments", Required: true, Usage: "Transport SID list (comma-separated IPv6)"},
					&cli.UintFlag{Name: "preference", Usage: "Candidate path preference (0 = RFC default)"},
					&cli.UintFlag{Name: "distinguisher", Usage: "Candidate path distinguisher"},
					&cli.StringFlag{Name: "next-hop", Required: true, Usage: "BGP next hop (IPv6)"},
				},
				Action: func(c *cli.Context) error {
					p := &v1.BgpSrPolicy{
						Color:         uint32(c.Uint("color")),
						Endpoint:      c.String("endpoint"),
						Segments:      csvFlag(c.String("segments")),
						Preference:    uint32(c.Uint("preference")),
						Distinguisher: uint32(c.Uint("distinguisher")),
						NextHop:       c.String("next-hop"),
					}
					clients := clientsFromContext(c)
					resp, err := clients.BgpRoute.BgpAdvertiseSrPolicy(context.Background(),
						connect.NewRequest(&v1.BgpAdvertiseSrPolicyRequest{Policies: []*v1.BgpSrPolicy{p}}))
					if err != nil {
						return err
					}
					return printOperationResult(resp.Msg.Advertised, resp.Msg.Errors, "BgpSrPolicy", "advertised")
				},
			},
			{
				Name:  "withdraw-sr-policy",
				Usage: "Withdraw a previously advertised SR Policy",
				Flags: []cli.Flag{
					&cli.UintFlag{Name: "color", Required: true, Usage: "SR Policy color"},
					&cli.StringFlag{Name: "endpoint", Required: true, Usage: "SR Policy endpoint (IPv6)"},
					&cli.UintFlag{Name: "distinguisher", Usage: "Candidate path distinguisher"},
				},
				Action: func(c *cli.Context) error {
					k := &v1.BgpSrPolicyKey{
						Color:         uint32(c.Uint("color")),
						Endpoint:      c.String("endpoint"),
						Distinguisher: uint32(c.Uint("distinguisher")),
					}
					clients := clientsFromContext(c)
					resp, err := clients.BgpRoute.BgpWithdrawSrPolicy(context.Background(),
						connect.NewRequest(&v1.BgpWithdrawSrPolicyRequest{Keys: []*v1.BgpSrPolicyKey{k}}))
					if err != nil {
						return err
					}
					return printOperationResult(resp.Msg.Withdrawn, resp.Msg.Errors, "BgpSrPolicyKey", "withdrawn")
				},
			},
			{
				Name:  "advertise-evpn-mac",
				Usage: "Advertise a local EVPN RT2 (MAC/IP) with an End.DT2U SID",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "rd", Required: true, Usage: "Route distinguisher, e.g. 65000:100"},
					&cli.StringFlag{Name: "route-targets", Required: true, Usage: "Export route targets (comma-separated)"},
					&cli.StringFlag{Name: "mac", Required: true, Usage: "MAC address (aa:bb:cc:dd:ee:ff)"},
					&cli.UintFlag{Name: "ethernet-tag", Usage: "EVPN Ethernet Tag ID"},
					&cli.StringFlag{Name: "sid", Required: true, Usage: "Local End.DT2U SID (IPv6)"},
					&cli.StringFlag{Name: "next-hop", Required: true, Usage: "BGP next hop (IPv6)"},
					&cli.StringFlag{Name: "esi", Usage: "Ethernet Segment Identifier (10-octet, optional)"},
				},
				Action: func(c *cli.Context) error {
					m := &v1.BgpEvpnMac{
						Rd:           c.String("rd"),
						RouteTargets: csvFlag(c.String("route-targets")),
						Mac:          c.String("mac"),
						EthernetTag:  uint32(c.Uint("ethernet-tag")),
						Sid:          c.String("sid"),
						NextHop:      c.String("next-hop"),
						Esi:          c.String("esi"),
					}
					clients := clientsFromContext(c)
					resp, err := clients.BgpRoute.BgpAdvertiseEvpnMac(context.Background(),
						connect.NewRequest(&v1.BgpAdvertiseEvpnMacRequest{Macs: []*v1.BgpEvpnMac{m}}))
					if err != nil {
						return err
					}
					return printOperationResult(resp.Msg.Advertised, resp.Msg.Errors, "BgpEvpnMac", "advertised")
				},
			},
			{
				Name:  "withdraw-evpn-mac",
				Usage: "Withdraw a previously advertised EVPN RT2",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "rd", Required: true, Usage: "Route distinguisher"},
					&cli.UintFlag{Name: "ethernet-tag", Usage: "EVPN Ethernet Tag ID"},
					&cli.StringFlag{Name: "mac", Required: true, Usage: "MAC address"},
				},
				Action: func(c *cli.Context) error {
					k := &v1.BgpEvpnMacKey{
						Rd:          c.String("rd"),
						EthernetTag: uint32(c.Uint("ethernet-tag")),
						Mac:         c.String("mac"),
					}
					clients := clientsFromContext(c)
					resp, err := clients.BgpRoute.BgpWithdrawEvpnMac(context.Background(),
						connect.NewRequest(&v1.BgpWithdrawEvpnMacRequest{Keys: []*v1.BgpEvpnMacKey{k}}))
					if err != nil {
						return err
					}
					return printOperationResult(resp.Msg.Withdrawn, resp.Msg.Errors, "BgpEvpnMacKey", "withdrawn")
				},
			},
		},
	}
}
