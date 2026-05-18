package gobgp_test

import (
	"context"
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

// Loopback ports for the two BGP speakers. Non-standard so the test
// needs no privilege for the listener (BPF map load still needs root).
const (
	pe1ListenPort = 10179 // remote PE (route source, plain gobgp)
	pe2ListenPort = 10180 // Vinbero PE (route sink, gobgp.Session + Applier)
)

// waitFor polls cond until it returns true or the timeout elapses.
func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timeout after %s waiting for %s", timeout, what)
}

// TestE2E_VPNv4RouteToHeadendMap is the Phase 1d end-to-end test: a
// remote PE advertises a VPNv4 route carrying an SRv6 service SID over a
// real BGP session, and the Vinbero PE's receive pipeline
// (gobgp.Session -> Applier) must materialize it as a headend_v4_map
// entry. Requires root for the BPF collection load.
func TestE2E_VPNv4RouteToHeadendMap(t *testing.T) {
	ctx := context.Background()

	// --- Vinbero PE data plane: real BPF maps + applier ---
	objs, err := bpf.ReadCollection(nil, nil)
	if err != nil {
		t.Fatalf("load BPF collection (needs root): %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	mapOps := bpf.NewMapOperations(objs)

	locMgr := locator.NewManager()
	srcLoc := locator.Locator{
		Name:              "LOC1",
		Prefix:            netip.MustParsePrefix("fd00:1:1::/48"),
		BlockLen:          32,
		NodeLen:           16,
		FunctionLen:       16,
		ArgumentLen:       64,
		Behavior:          locator.BehaviorClassic,
		FunctionAutoStart: 0x10,
		FunctionAutoEnd:   0xFFFF,
	}
	if err := locMgr.Add(&srcLoc); err != nil {
		t.Fatalf("locator Add: %v", err)
	}
	applier := apply.NewApplier(mapOps, locMgr, vrfbgp.NewManager(),
		fib.NewKernelInjector(), "LOC1", 65002, zap.NewNop())

	// --- Vinbero PE (PE2): gobgp.Session, the code under test ---
	pe2 := gobgp.NewSession(zap.NewNop())
	if err := pe2.Start(ctx, bgp.GlobalConfig{
		LocalASN: 65002, RouterID: "10.0.0.2", ListenPort: pe2ListenPort,
	}); err != nil {
		t.Fatalf("PE2 Start: %v", err)
	}
	t.Cleanup(func() { _ = pe2.Stop(ctx) })
	if err := pe2.AddPeer(ctx, bgp.PeerConfig{
		Neighbor: "127.0.0.1", PeerASN: 65001,
		HoldTimeSec: 90, KeepaliveSec: 30,
		Families: []bgp.Family{bgp.FamilyVPNv4},
	}); err != nil {
		t.Fatalf("PE2 AddPeer: %v", err)
	}
	cancelSub, err := pe2.Subscribe("", applier.Apply)
	if err != nil {
		t.Fatalf("PE2 Subscribe: %v", err)
	}
	t.Cleanup(cancelSub)

	// --- Remote PE (PE1): plain gobgp BgpServer, the route source ---
	pe1 := gobgpsrv.NewBgpServer()
	go pe1.Serve()
	t.Cleanup(func() { pe1.Stop() })
	if err := pe1.StartBgp(ctx, &gobgpapi.StartBgpRequest{
		Global: &gobgpapi.Global{Asn: 65001, RouterId: "10.0.0.1", ListenPort: pe1ListenPort},
	}); err != nil {
		t.Fatalf("PE1 StartBgp: %v", err)
	}
	// PE1 actively connects to PE2's non-standard listen port.
	if err := pe1.AddPeer(ctx, &gobgpapi.AddPeerRequest{Peer: &gobgpapi.Peer{
		Conf: &gobgpapi.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 65002},
		Transport: &gobgpapi.Transport{
			RemoteAddress: "127.0.0.1",
			RemotePort:    pe2ListenPort,
			LocalAddress:  "127.0.0.1",
		},
		AfiSafis: []*gobgpapi.AfiSafi{{Config: &gobgpapi.AfiSafiConfig{
			Family: &gobgpapi.Family{Afi: gobgpapi.Family_AFI_IP, Safi: gobgpapi.Family_SAFI_MPLS_VPN},
		}}},
	}}); err != nil {
		t.Fatalf("PE1 AddPeer: %v", err)
	}

	// --- Wait for the session to come up ---
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

	// --- PE1 advertises a VPNv4 route with an SRv6 End.DT4 service SID ---
	const (
		vpnPrefix = "10.0.0.0/24"
		serviceID = "fd00:1:1:a::"
	)
	rd := gobgppkt.NewRouteDistinguisherTwoOctetAS(65000, 100)
	nlri, err := gobgppkt.NewLabeledVPNIPAddrPrefix(
		netip.MustParsePrefix(vpnPrefix), *gobgppkt.NewMPLSLabelStack(0), rd)
	if err != nil {
		t.Fatalf("build VPNv4 NLRI: %v", err)
	}
	infoSubTLV := gobgppkt.NewSRv6InformationSubTLV(
		netip.MustParseAddr(serviceID), gobgppkt.SRBehavior(gobgppkt.END_DT4))
	svcTLV := gobgppkt.NewSRv6ServiceTLV(gobgppkt.TLVTypeSRv6L3Service, infoSubTLV)
	prefixSID := gobgppkt.NewPathAttributePrefixSID(svcTLV)
	origin := gobgppkt.NewPathAttributeOrigin(0)
	rt := gobgppkt.NewTwoOctetAsSpecificExtended(gobgppkt.EC_SUBTYPE_ROUTE_TARGET, 65000, 100, true)
	extComm := gobgppkt.NewPathAttributeExtendedCommunities(
		[]gobgppkt.ExtendedCommunityInterface{rt})
	mpReach, err := gobgppkt.NewPathAttributeMpReachNLRI(
		gobgppkt.RF_IPv4_VPN, []gobgppkt.PathNLRI{{NLRI: nlri}}, netip.MustParseAddr("2001:db8::1"))
	if err != nil {
		t.Fatalf("build MP_REACH_NLRI: %v", err)
	}

	if _, err := pe1.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{{
		Family: gobgppkt.RF_IPv4_VPN,
		Nlri:   nlri,
		Attrs:  []gobgppkt.PathAttributeInterface{origin, extComm, prefixSID, mpReach},
	}}}); err != nil {
		t.Fatalf("PE1 AddPath: %v", err)
	}

	// --- The route must surface as a headend_v4_map entry on PE2 ---
	var entry *bpf.HeadendEntry
	waitFor(t, "VPNv4 route installed in headend_v4_map", 15*time.Second, func() bool {
		e, err := mapOps.GetHeadendV4(vpnPrefix)
		if err != nil {
			return false
		}
		entry = e
		return true
	})

	// The outer destination / single segment must be the advertised SID.
	wantSID := netip.MustParseAddr(serviceID).As16()
	if entry.DstAddr != wantSID {
		t.Errorf("headend DstAddr = %v, want service SID %v", entry.DstAddr, wantSID)
	}
	if entry.NumSegments != 1 {
		t.Errorf("headend NumSegments = %d, want 1", entry.NumSegments)
	}
	if entry.Segments[0] != wantSID {
		t.Errorf("headend Segments[0] = %v, want %v", entry.Segments[0], wantSID)
	}
	// The encap source must come from the source locator's prefix.
	wantSrc := netip.MustParseAddr("fd00:1:1::").As16()
	if entry.SrcAddr != wantSrc {
		t.Errorf("headend SrcAddr = %v, want locator prefix %v", entry.SrcAddr, wantSrc)
	}
}
