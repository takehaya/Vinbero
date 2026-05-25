package gobgp_test

import (
	"context"
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
	"github.com/takehaya/vinbero/pkg/bgp/apply"
	"github.com/takehaya/vinbero/pkg/bgp/gobgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/fib"
	"github.com/takehaya/vinbero/pkg/locator"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// Non-standard listen ports so the EVPN E2E can run alongside the VPNv4
// one without colliding on the loopback.
const (
	evpnPE1ListenPort = 10181 // remote PE (RT2 source, plain gobgp)
	evpnPE2ListenPort = 10182 // Vinbero PE (RT2 sink, gobgp.Session + Applier)
)

const (
	evpnBDID      = uint16(100)
	evpnMAC       = "aa:bb:cc:00:00:01"
	evpnDT2USID   = "fd00:2:2:d2::" // remote PE's End.DT2U service SID
	evpnImportRT  = "65000:100"
	evpnLocatorPx = "fd00:1:1::" // source locator prefix -> local encap source
)

// TestE2E_EVPNRT2ToFdbAndBdPeer is the Phase E1 end-to-end test: a remote
// PE advertises an EVPN RT2 (MAC/IP) carrying an End.DT2U SID in the SRv6
// L2 Service TLV over a real BGP session (AFI 25 / SAFI 70), and the
// Vinbero PE's receive pipeline (gobgp.Session -> Applier) must install it
// as a bd_peer_map encap entry plus an fdb_map MAC->peer mapping. This
// proves the E1 control plane drives the real BPF maps over the wire; the
// L2 forwarding-on-wire path is exercised by the dt2 data-plane tests and
// the EVPN interop scenario. Requires root for the BPF collection load.
func TestE2E_EVPNRT2ToFdbAndBdPeer(t *testing.T) {
	ctx := context.Background()

	objs, err := bpf.ReadCollection(nil, nil)
	if err != nil {
		t.Fatalf("load BPF collection (needs root): %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	mapOps := bpf.NewMapOperations(objs)

	locMgr := locator.NewManager()
	if err := locMgr.Add(&locator.Locator{
		Name:              "LOC1",
		Prefix:            netip.MustParsePrefix("fd00:1:1::/48"),
		BlockLen:          32,
		NodeLen:           16,
		FunctionLen:       16,
		ArgumentLen:       64,
		Behavior:          locator.BehaviorClassic,
		FunctionAutoStart: 0x10,
		FunctionAutoEnd:   0xFFFF,
	}); err != nil {
		t.Fatalf("locator Add: %v", err)
	}

	// The EVPN RT2 only installs when its route target matches a binding
	// carrying a bridge domain.
	vm := vrfbgp.NewManager()
	if err := vm.Bind(vrfbgp.Binding{
		VRFName: "evi-100", ImportRTs: []string{evpnImportRT}, BDID: evpnBDID,
	}); err != nil {
		t.Fatalf("vrf bind: %v", err)
	}
	applier := apply.NewApplier(mapOps, locMgr, vm,
		fib.NewKernelInjector(), "LOC1", 65002, zap.NewNop())

	// Vinbero PE (PE2): the code under test.
	pe2 := gobgp.NewSession(zap.NewNop())
	if err := pe2.Start(ctx, bgp.GlobalConfig{
		LocalASN: 65002, RouterID: "10.0.0.2", ListenPort: evpnPE2ListenPort,
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
	cancelSub, err := pe2.Subscribe("", applier.Apply)
	if err != nil {
		t.Fatalf("PE2 Subscribe: %v", err)
	}
	t.Cleanup(cancelSub)

	// Remote PE (PE1): plain gobgp, the RT2 source.
	pe1 := gobgpsrv.NewBgpServer()
	go pe1.Serve()
	t.Cleanup(func() { pe1.Stop() })
	if err := pe1.StartBgp(ctx, &gobgpapi.StartBgpRequest{
		Global: &gobgpapi.Global{Asn: 65001, RouterId: "10.0.0.1", ListenPort: evpnPE1ListenPort},
	}); err != nil {
		t.Fatalf("PE1 StartBgp: %v", err)
	}
	if err := pe1.AddPeer(ctx, &gobgpapi.AddPeerRequest{Peer: &gobgpapi.Peer{
		Conf: &gobgpapi.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 65002},
		Transport: &gobgpapi.Transport{
			RemoteAddress: "127.0.0.1", RemotePort: evpnPE2ListenPort, LocalAddress: "127.0.0.1",
		},
		AfiSafis: []*gobgpapi.AfiSafi{{Config: &gobgpapi.AfiSafiConfig{
			Family: &gobgpapi.Family{Afi: gobgpapi.Family_AFI_L2VPN, Safi: gobgpapi.Family_SAFI_EVPN},
		}}},
	}}); err != nil {
		t.Fatalf("PE1 AddPeer: %v", err)
	}

	waitFor(t, "BGP session ESTABLISHED", 30*time.Second, func() bool {
		peers, err := pe2.Peers(ctx)
		if err != nil {
			return false
		}
		for _, p := range peers {
			if p.SessionState == "established" {
				return true
			}
		}
		return false
	})

	// PE1 advertises an RT2 with the End.DT2U SID in the SRv6 L2 Service TLV.
	rd := gobgppkt.NewRouteDistinguisherTwoOctetAS(65000, 100)
	hw, err := net.ParseMAC(evpnMAC)
	if err != nil {
		t.Fatalf("parse MAC: %v", err)
	}
	// Build the MAC-only RT2 NLRI via the constructor (which computes the
	// NLRI length) rather than the IP-requiring NewEVPNMacIPAdvertisementRoute.
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
	infoSubTLV := gobgppkt.NewSRv6InformationSubTLV(netip.MustParseAddr(evpnDT2USID), gobgppkt.END_DT2U)
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

	var fdb *bpf.FdbEntry
	waitFor(t, "RT2 MAC installed in fdb_map", 15*time.Second, func() bool {
		e, err := mapOps.GetFdb(evpnBDID, hw)
		if err != nil {
			return false
		}
		fdb = e
		return true
	})

	if fdb.IsRemote != 1 || fdb.BdId != evpnBDID {
		t.Errorf("fdb entry = %+v, want IsRemote=1 BdId=%d", fdb, evpnBDID)
	}
	peer, err := mapOps.GetBdPeer(evpnBDID, fdb.PeerIndex)
	if err != nil {
		t.Fatalf("bd_peer at index %d not installed: %v", fdb.PeerIndex, err)
	}
	wantSID := netip.MustParseAddr(evpnDT2USID).As16()
	if peer.Segments[0] != wantSID {
		t.Errorf("bd_peer Segments[0] = %v, want End.DT2U SID %v", peer.Segments[0], wantSID)
	}
	wantSrc := netip.MustParseAddr(evpnLocatorPx).As16()
	if peer.SrcAddr != wantSrc {
		t.Errorf("bd_peer SrcAddr = %v, want local encap source %v", peer.SrcAddr, wantSrc)
	}
}
