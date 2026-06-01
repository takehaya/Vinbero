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
			{
				Name:  "advertise-evpn-imet",
				Usage: "Advertise a local EVPN RT3 (Inclusive Multicast) with an End.DT2M SID",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "rd", Required: true, Usage: "Route distinguisher, e.g. 65000:100"},
					&cli.StringFlag{Name: "route-targets", Required: true, Usage: "Export route targets (comma-separated)"},
					&cli.UintFlag{Name: "ethernet-tag", Usage: "EVPN Ethernet Tag ID"},
					&cli.StringFlag{Name: "sid", Required: true, Usage: "Local End.DT2M flood SID (IPv6)"},
					&cli.StringFlag{Name: "next-hop", Required: true, Usage: "BGP next hop / originating router (IPv6)"},
				},
				Action: func(c *cli.Context) error {
					m := &v1.BgpEvpnImet{
						Rd:           c.String("rd"),
						RouteTargets: csvFlag(c.String("route-targets")),
						EthernetTag:  uint32(c.Uint("ethernet-tag")),
						Sid:          c.String("sid"),
						NextHop:      c.String("next-hop"),
					}
					clients := clientsFromContext(c)
					resp, err := clients.BgpRoute.BgpAdvertiseEvpnImet(context.Background(),
						connect.NewRequest(&v1.BgpAdvertiseEvpnImetRequest{Imets: []*v1.BgpEvpnImet{m}}))
					if err != nil {
						return err
					}
					return printOperationResult(resp.Msg.Advertised, resp.Msg.Errors, "BgpEvpnImet", "advertised")
				},
			},
			{
				Name:  "withdraw-evpn-imet",
				Usage: "Withdraw a previously advertised EVPN RT3",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "rd", Required: true, Usage: "Route distinguisher"},
					&cli.UintFlag{Name: "ethernet-tag", Usage: "EVPN Ethernet Tag ID"},
				},
				Action: func(c *cli.Context) error {
					k := &v1.BgpEvpnImetKey{
						Rd:          c.String("rd"),
						EthernetTag: uint32(c.Uint("ethernet-tag")),
					}
					clients := clientsFromContext(c)
					resp, err := clients.BgpRoute.BgpWithdrawEvpnImet(context.Background(),
						connect.NewRequest(&v1.BgpWithdrawEvpnImetRequest{Keys: []*v1.BgpEvpnImetKey{k}}))
					if err != nil {
						return err
					}
					return printOperationResult(resp.Msg.Withdrawn, resp.Msg.Errors, "BgpEvpnImetKey", "withdrawn")
				},
			},
			{
				Name:  "advertise-evpn-es",
				Usage: "Advertise a local EVPN RT4 (Ethernet Segment) with an ES-Import RT",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "rd", Required: true, Usage: "Route distinguisher, e.g. 65000:1"},
					&cli.StringFlag{Name: "esi", Required: true, Usage: "Ethernet Segment Identifier (10-octet, e.g. 00:11:...)"},
					&cli.StringFlag{Name: "es-import-rt", Required: true, Usage: "ES-Import route target as a MAC (aa:bb:cc:dd:ee:ff)"},
					&cli.StringFlag{Name: "next-hop", Required: true, Usage: "BGP next hop / originating PE source (IPv6)"},
				},
				Action: func(c *cli.Context) error {
					m := &v1.BgpEvpnEs{
						Rd:         c.String("rd"),
						Esi:        c.String("esi"),
						EsImportRt: c.String("es-import-rt"),
						NextHop:    c.String("next-hop"),
					}
					clients := clientsFromContext(c)
					resp, err := clients.BgpRoute.BgpAdvertiseEvpnEs(context.Background(),
						connect.NewRequest(&v1.BgpAdvertiseEvpnEsRequest{Segments: []*v1.BgpEvpnEs{m}}))
					if err != nil {
						return err
					}
					return printOperationResult(resp.Msg.Advertised, resp.Msg.Errors, "BgpEvpnEs", "advertised")
				},
			},
			{
				Name:  "withdraw-evpn-es",
				Usage: "Withdraw a previously advertised EVPN RT4",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "rd", Required: true, Usage: "Route distinguisher"},
					&cli.StringFlag{Name: "esi", Required: true, Usage: "Ethernet Segment Identifier (10-octet)"},
				},
				Action: func(c *cli.Context) error {
					k := &v1.BgpEvpnEsKey{
						Rd:  c.String("rd"),
						Esi: c.String("esi"),
					}
					clients := clientsFromContext(c)
					resp, err := clients.BgpRoute.BgpWithdrawEvpnEs(context.Background(),
						connect.NewRequest(&v1.BgpWithdrawEvpnEsRequest{Keys: []*v1.BgpEvpnEsKey{k}}))
					if err != nil {
						return err
					}
					return printOperationResult(resp.Msg.Withdrawn, resp.Msg.Errors, "BgpEvpnEsKey", "withdrawn")
				},
			},
			{
				Name:  "advertise-mup",
				Usage: "Advertise a BGP MUP route (SAFI 85; --route-type isd|dsd|t1st|t2st)",
				Flags: mupRouteFlags(true),
				Action: func(c *cli.Context) error {
					r := mupRouteFromFlags(c)
					clients := clientsFromContext(c)
					resp, err := clients.BgpRoute.BgpAdvertiseMup(context.Background(),
						connect.NewRequest(&v1.BgpAdvertiseMupRequest{Routes: []*v1.BgpMupRoute{r}}))
					if err != nil {
						return err
					}
					return printOperationResult(resp.Msg.Advertised, resp.Msg.Errors, "BgpMupRoute", "advertised")
				},
			},
			{
				Name:  "withdraw-mup",
				Usage: "Withdraw a previously advertised BGP MUP route",
				Flags: mupKeyFlags(),
				Action: func(c *cli.Context) error {
					r := mupRouteFromFlags(c)
					clients := clientsFromContext(c)
					resp, err := clients.BgpRoute.BgpWithdrawMup(context.Background(),
						connect.NewRequest(&v1.BgpWithdrawMupRequest{Routes: []*v1.BgpMupRoute{r}}))
					if err != nil {
						return err
					}
					return printOperationResult(resp.Msg.Withdrawn, resp.Msg.Errors, "BgpMupRoute", "withdrawn")
				},
			},
		},
	}
}

// mupRouteFlags returns the full MUP route flag set shared by `bgp advertise-mup`
// and `mup create/update`. requireNextHop is true for the explicit advertise
// command (next hop mandatory) and false for `mup create/update`, where an
// omitted next hop defaults to bgp.global.next_hop server-side.
func mupRouteFlags(requireNextHop bool) []cli.Flag {
	nextHopUsage := "BGP next hop (IPv6)"
	if !requireNextHop {
		nextHopUsage = "BGP next hop (IPv6); defaults to bgp.global.next_hop"
	}
	return []cli.Flag{
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
		&cli.StringFlag{Name: "next-hop", Required: requireNextHop, Usage: nextHopUsage},
	}
}

// mupKeyFlags returns the smaller flag set for withdraw / delete: the route type
// plus the type's identifying fields. Shared by `bgp withdraw-mup` and
// `mup delete`.
func mupKeyFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "route-type", Required: true, Usage: "isd | dsd | t1st | t2st"},
		&cli.StringFlag{Name: "rd", Required: true, Usage: "Route distinguisher"},
		&cli.StringFlag{Name: "prefix", Usage: "isd segment prefix / t1st UE prefix (CIDR)"},
		&cli.StringFlag{Name: "address", Usage: "dsd direct-segment endpoint address"},
		&cli.UintFlag{Name: "teid", Usage: "GTP-U TEID (t1st / t2st)"},
		&cli.UintFlag{Name: "teid-len", Value: 32, Usage: "t2st TEID prefix bits"},
		&cli.StringFlag{Name: "endpoint", Usage: "t2st GTP tunnel endpoint"},
	}
}

// mupRouteFromFlags assembles a BgpMupRoute from the shared MUP command flags.
// Unset fields stay zero; the server validates per route type.
func mupRouteFromFlags(c *cli.Context) *v1.BgpMupRoute {
	return &v1.BgpMupRoute{
		RouteType:    c.String("route-type"),
		Rd:           c.String("rd"),
		RouteTargets: csvFlag(c.String("route-targets")),
		Prefix:       c.String("prefix"),
		Address:      c.String("address"),
		Teid:         uint32(c.Uint("teid")),
		TeidLen:      uint32(c.Uint("teid-len")),
		Qfi:          uint32(c.Uint("qfi")),
		Rqi:          uint32(c.Uint("rqi")),
		Endpoint:     c.String("endpoint"),
		Source:       c.String("source"),
		SegmentId2:   uint32(c.Uint("segment-id2")),
		SegmentId4:   uint32(c.Uint("segment-id4")),
		Srv6Sid:      c.String("sid"),
		NextHop:      c.String("next-hop"),
	}
}
