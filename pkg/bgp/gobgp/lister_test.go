package gobgp_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	gobgpapi "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	gobgpsrv "github.com/osrg/gobgp/v4/pkg/server"
	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bgp/gobgp"
)

const (
	listerPE1ListenPort = 10191 // remote PE (RT2 source, plain gobgp)
	listerPE2ListenPort = 10192 // Vinbero PE (the ListRoutes side)
)

// ListRoutes returns peer-learned routes from the loc-rib snapshot, skips
// this node's own advertisements (which the rib holds but the live watch
// stream never delivers), and reports ErrSessionNotStarted before Start.
// No BPF / applier involved -- this pins the lister surface alone.
func TestListRoutes_PeerLearnedOnlyAndLocalOriginSkipped(t *testing.T) {
	ctx := context.Background()

	fresh := gobgp.NewSession(zap.NewNop())
	if err := fresh.ListRoutes(bgp.FamilyEVPN, func(bgp.RouteEvent) {}); !errors.Is(err, bgp.ErrSessionNotStarted) {
		t.Fatalf("ListRoutes before Start: err = %v, want ErrSessionNotStarted", err)
	}

	// PE2: the Vinbero session under test.
	pe2 := gobgp.NewSession(zap.NewNop())
	if err := pe2.Start(ctx, bgp.GlobalConfig{
		LocalASN: 65002, RouterID: "10.0.0.2", ListenPort: listerPE2ListenPort,
	}); err != nil {
		t.Fatalf("PE2 Start: %v", err)
	}
	t.Cleanup(func() { _ = pe2.Stop(ctx) })
	if err := pe2.AddPeer(ctx, bgp.PeerConfig{
		Neighbor: "127.0.0.1", PeerASN: 65001,
		HoldTimeSec: 90, KeepaliveSec: 30,
		Families: []bgp.Family{bgp.FamilyEVPN},
	}); err != nil {
		t.Fatalf("PE2 AddPeer: %v", err)
	}

	// PE2 advertises its own RT3 (the EVPN exporter's shape): this lands in
	// PE2's loc-rib as a locally originated path and must NOT come back out
	// of ListRoutes.
	if err := pe2.PushEVPNInclusiveMulticast(ctx, bgp.EVPNRoute{
		Type:    bgp.EVPNRouteTypeInclusiveMulticast,
		RD:      "65002:100",
		RTs:     []string{"65000:100"},
		SRv6SID: "fd00:2:2:d2ff::",
		NextHop: "2001:db8::2",
	}); err != nil {
		t.Fatalf("PE2 PushEVPNInclusiveMulticast: %v", err)
	}

	// PE1: plain gobgp, advertises the peer-learned RT2.
	pe1 := gobgpsrv.NewBgpServer()
	go pe1.Serve()
	t.Cleanup(func() { pe1.Stop() })
	if err := pe1.StartBgp(ctx, &gobgpapi.StartBgpRequest{
		Global: &gobgpapi.Global{Asn: 65001, RouterId: "10.0.0.1", ListenPort: listerPE1ListenPort},
	}); err != nil {
		t.Fatalf("PE1 StartBgp: %v", err)
	}
	if err := pe1.AddPeer(ctx, &gobgpapi.AddPeerRequest{Peer: &gobgpapi.Peer{
		Conf: &gobgpapi.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 65002},
		Transport: &gobgpapi.Transport{
			RemoteAddress: "127.0.0.1", RemotePort: listerPE2ListenPort, LocalAddress: "127.0.0.1",
		},
		AfiSafis: []*gobgpapi.AfiSafi{{Config: &gobgpapi.AfiSafiConfig{
			Family: &gobgpapi.Family{Afi: gobgpapi.Family_AFI_L2VPN, Safi: gobgpapi.Family_SAFI_EVPN},
		}}},
	}}); err != nil {
		t.Fatalf("PE1 AddPeer: %v", err)
	}

	const mac = "aa:bb:cc:00:00:42"
	hw, err := net.ParseMAC(mac)
	if err != nil {
		t.Fatalf("parse MAC: %v", err)
	}
	rd := gobgppkt.NewRouteDistinguisherTwoOctetAS(65000, 100)
	nlri := gobgppkt.NewEVPNNLRI(
		gobgppkt.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT,
		&gobgppkt.EVPNMacIPAdvertisementRoute{
			RD:               rd,
			ETag:             0,
			MacAddressLength: 48,
			MacAddress:       hw,
			Labels:           []uint32{0},
		},
	)
	infoSubTLV := gobgppkt.NewSRv6InformationSubTLV(netip.MustParseAddr("fd00:1:1:d2::"), gobgppkt.END_DT2U)
	svcTLV := gobgppkt.NewSRv6ServiceTLV(gobgppkt.TLVTypeSRv6L2Service, infoSubTLV)
	prefixSID := gobgppkt.NewPathAttributePrefixSID(svcTLV)
	origin := gobgppkt.NewPathAttributeOrigin(0)
	rt := gobgppkt.NewTwoOctetAsSpecificExtended(gobgppkt.EC_SUBTYPE_ROUTE_TARGET, 65000, 100, true)
	extComm := gobgppkt.NewPathAttributeExtendedCommunities([]gobgppkt.ExtendedCommunityInterface{rt})
	mpReach, err := gobgppkt.NewPathAttributeMpReachNLRI(
		gobgppkt.RF_EVPN, []gobgppkt.PathNLRI{{NLRI: nlri}}, netip.MustParseAddr("2001:db8::1"))
	if err != nil {
		t.Fatalf("build MP_REACH_NLRI: %v", err)
	}
	if _, err := pe1.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{{
		Family: gobgppkt.RF_EVPN,
		Nlri:   nlri,
		Attrs:  []gobgppkt.PathAttributeInterface{origin, extComm, prefixSID, mpReach},
	}}}); err != nil {
		t.Fatalf("PE1 AddPath: %v", err)
	}

	// The RT2 must appear in the snapshot once the session converges; the
	// own RT3 must never appear no matter how often we list.
	list := func() (rt2s, rt3s int) {
		t.Helper()
		if err := pe2.ListRoutes(bgp.FamilyEVPN, func(ev bgp.RouteEvent) {
			if ev.Family != bgp.FamilyEVPN || ev.EVPN == nil {
				t.Errorf("non-EVPN event from an EVPN list: %+v", ev)
				return
			}
			if ev.IsWithdraw {
				t.Errorf("rib-resident path delivered as withdraw: %+v", ev.EVPN)
			}
			switch ev.EVPN.Type {
			case bgp.EVPNRouteTypeMACIP:
				if ev.EVPN.MAC == mac {
					rt2s++
				}
			case bgp.EVPNRouteTypeInclusiveMulticast:
				rt3s++
			}
		}); err != nil {
			t.Fatalf("ListRoutes: %v", err)
		}
		return rt2s, rt3s
	}
	waitFor(t, "peer RT2 visible in the loc-rib snapshot", 30*time.Second, func() bool {
		rt2s, _ := list()
		return rt2s == 1
	})
	if _, rt3s := list(); rt3s != 0 {
		t.Errorf("own RT3 leaked out of ListRoutes (local-origin filter broken): %d", rt3s)
	}

	// Family filter: a vpnv4 snapshot of this rib is empty (nothing was
	// advertised under vpnv4), and never yields EVPN events.
	if err := pe2.ListRoutes(bgp.FamilyVPNv4, func(ev bgp.RouteEvent) {
		t.Errorf("vpnv4 list yielded an event: %+v", ev)
	}); err != nil {
		t.Fatalf("ListRoutes(vpnv4): %v", err)
	}
}
