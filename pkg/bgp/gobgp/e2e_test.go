package gobgp_test

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

// The VPNv4 route the remote PE advertises across the E2E tests.
const (
	e2eVPNPrefix  = "10.0.0.0/24"
	e2eServiceSID = "fd00:1:1:a::100" // SRv6 End.DT4 service SID
	e2eLocatorPfx = "fd00:1:1::"      // source locator prefix -> encap source
)

// Ethernet / IPv6 header lengths used by the encap verifier and the
// netns capture filter.
const (
	ethHeaderLen  = 14
	ipv6HeaderLen = 40
	ipv6AddrLen   = 16
)

// e2eInnerSrc / e2eInnerDst are the inner IPv4 endpoints the data-plane
// tests inject; the destination falls inside e2eVPNPrefix.
var (
	e2eInnerSrc = net.IPv4(192, 0, 2, 1)
	e2eInnerDst = net.IPv4(10, 0, 0, 5)
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

// e2eReceive is the data plane produced by the BGP receive pipeline.
type e2eReceive struct {
	objs   *bpf.BpfObjects
	mapOps *bpf.MapOperations
	entry  *bpf.HeadendEntry // the headend_v4_map entry the route created
}

// setupVPNv4Receive runs the full receive pipeline: a remote PE
// advertises a VPNv4 route carrying an SRv6 End.DT4 service SID over a
// real BGP session, and the function returns once the Vinbero PE has
// materialized it as a headend_v4_map entry. Requires root for the BPF
// collection load.
func setupVPNv4Receive(t *testing.T) e2eReceive {
	t.Helper()
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
	applier := apply.NewApplier(mapOps, mapOps, locMgr, vrfbgp.NewManager(),
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
	rd := gobgppkt.NewRouteDistinguisherTwoOctetAS(65000, 100)
	nlri, err := gobgppkt.NewLabeledVPNIPAddrPrefix(
		netip.MustParsePrefix(e2eVPNPrefix), *gobgppkt.NewMPLSLabelStack(0), rd)
	if err != nil {
		t.Fatalf("build VPNv4 NLRI: %v", err)
	}
	infoSubTLV := gobgppkt.NewSRv6InformationSubTLV(
		netip.MustParseAddr(e2eServiceSID), gobgppkt.SRBehavior(gobgppkt.END_DT4))
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
		e, err := mapOps.GetHeadendV4(e2eVPNPrefix)
		if err != nil {
			return false
		}
		entry = e
		return true
	})
	return e2eReceive{objs: objs, mapOps: mapOps, entry: entry}
}

// TestE2E_VPNv4RouteToHeadendMap is the Phase 1d end-to-end test: a
// remote PE advertises a VPNv4 route carrying an SRv6 service SID over a
// real BGP session, and the Vinbero PE's receive pipeline
// (gobgp.Session -> Applier) must materialize it as a headend_v4_map
// entry with the right encap parameters.
func TestE2E_VPNv4RouteToHeadendMap(t *testing.T) {
	r := setupVPNv4Receive(t)

	// The outer destination / single segment must be the advertised SID.
	wantSID := netip.MustParseAddr(e2eServiceSID).As16()
	if r.entry.DstAddr != wantSID {
		t.Errorf("headend DstAddr = %v, want service SID %v", r.entry.DstAddr, wantSID)
	}
	if r.entry.NumSegments != 1 {
		t.Errorf("headend NumSegments = %d, want 1", r.entry.NumSegments)
	}
	if r.entry.Segments[0] != wantSID {
		t.Errorf("headend Segments[0] = %v, want %v", r.entry.Segments[0], wantSID)
	}
	// The encap source must come from the source locator's prefix.
	wantSrc := netip.MustParseAddr(e2eLocatorPfx).As16()
	if r.entry.SrcAddr != wantSrc {
		t.Errorf("headend SrcAddr = %v, want locator prefix %v", r.entry.SrcAddr, wantSrc)
	}
}

// TestE2E_VPNv4BgpToXdpEncap is the full control-plane-to-data-plane
// proof: after a VPNv4 route is learned over BGP and installed by the
// Applier (setupVPNv4Receive), a plain IPv4 packet whose destination
// falls inside the advertised prefix is run through the real XDP
// program via BPF_PROG_TEST_RUN. The program must SRv6-encapsulate it
// toward the SID that arrived over BGP -- i.e. the route actually
// drives the data plane.
func TestE2E_VPNv4BgpToXdpEncap(t *testing.T) {
	r := setupVPNv4Receive(t)

	// A plain IPv4 packet destined inside the BGP-advertised prefix.
	pkt := buildPlainIPv4Packet(t, e2eInnerSrc, e2eInnerDst)

	// Run the real XDP program against the collection the Applier populated.
	opts := ebpf.RunOptions{Data: pkt, DataOut: make([]byte, 1500), Repeat: 1}
	ret, err := r.objs.VinberoMain.Run(&opts)
	if err != nil {
		t.Fatalf("BPF_PROG_TEST_RUN: %v", err)
	}
	if ret != bpf.XDP_PASS {
		t.Fatalf("XDP action = %d, want XDP_PASS (%d) after H.Encaps", ret, bpf.XDP_PASS)
	}

	outerSrc := netip.MustParseAddr(e2eLocatorPfx).As16()
	sid := netip.MustParseAddr(e2eServiceSID).As16()
	verifyEncapTowardSID(t, opts.DataOut, outerSrc, sid, e2eInnerSrc, e2eInnerDst)
}

// buildPlainIPv4Packet assembles an Ethernet/IPv4/ICMP echo frame.
func buildPlainIPv4Packet(t *testing.T, src, dst net.IP) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		Protocol: layers.IPProtocolICMPv4, SrcIP: src, DstIP: dst,
	}
	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id:       1234, Seq: 1,
	}
	buf := gopacket.NewSerializeBuffer()
	serOpts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, serOpts, eth, ip4, icmp,
		gopacket.Payload(make([]byte, 32))); err != nil {
		t.Fatalf("build IPv4 packet: %v", err)
	}
	return buf.Bytes()
}

// verifyEncapTowardSID asserts pkt is H.Encaps output: an outer IPv6
// header (src = locator, dst = SID) optionally followed by an SRH
// carrying the SID, with the original inner IPv4 preserved. Both the
// SRH-present and SRH-omitted single-segment encodings are accepted.
func verifyEncapTowardSID(t *testing.T, pkt []byte, outerSrc, sid [16]byte, innerSrc, innerDst net.IP) {
	t.Helper()
	if len(pkt) < ethHeaderLen+ipv6HeaderLen {
		t.Fatalf("encapsulated packet too short: %d bytes", len(pkt))
	}
	if v := pkt[ethHeaderLen] >> 4; v != 6 {
		t.Fatalf("outer IP version = %d, want 6 (IPv6)", v)
	}
	if got := pkt[ethHeaderLen+8 : ethHeaderLen+24]; !bytes.Equal(got, outerSrc[:]) {
		t.Errorf("outer IPv6 src = %x, want locator prefix %x", got, outerSrc)
	}
	if got := pkt[ethHeaderLen+24 : ethHeaderLen+ipv6HeaderLen]; !bytes.Equal(got, sid[:]) {
		t.Errorf("outer IPv6 dst = %x, want service SID %x", got, sid)
	}

	inner := ethHeaderLen + ipv6HeaderLen
	switch nh := pkt[ethHeaderLen+6]; nh {
	case uint8(layers.IPProtocolIPv6Routing):
		srh := ethHeaderLen + ipv6HeaderLen
		if len(pkt) < srh+8+ipv6AddrLen {
			t.Fatalf("packet too short for SRH: %d bytes", len(pkt))
		}
		if rt := pkt[srh+2]; rt != 4 {
			t.Errorf("SRH routing type = %d, want 4 (SR)", rt)
		}
		if seg := pkt[srh+8 : srh+8+ipv6AddrLen]; !bytes.Equal(seg, sid[:]) {
			t.Errorf("SRH segment = %x, want service SID %x", seg, sid)
		}
		inner = srh + (int(pkt[srh+1])+1)*8
	case uint8(layers.IPProtocolIPv4):
		// single-segment H.Encaps may omit the SRH; inner sits right after IPv6
	default:
		t.Fatalf("outer IPv6 next header = %d, want 43 (SRH) or 4 (IPIP)", nh)
	}

	if len(pkt) < inner+20 {
		t.Fatalf("packet too short for inner IPv4: %d bytes", len(pkt))
	}
	if v := pkt[inner] >> 4; v != 4 {
		t.Errorf("inner IP version = %d, want 4 (original IPv4 preserved)", v)
	}
	if got := net.IP(pkt[inner+12 : inner+16]); !got.Equal(innerSrc.To4()) {
		t.Errorf("inner IPv4 src = %s, want %s", got, innerSrc)
	}
	if got := net.IP(pkt[inner+16 : inner+20]); !got.Equal(innerDst.To4()) {
		t.Errorf("inner IPv4 dst = %s, want %s", got, innerDst)
	}
}
