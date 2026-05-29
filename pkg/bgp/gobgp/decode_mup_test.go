package gobgp

import (
	"net/netip"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// teidAddr builds the netip.Addr (4-byte, MSB-first) gobgp uses to carry a TEID.
func teidAddr(teid uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{
		byte(teid >> 24), byte(teid >> 16), byte(teid >> 8), byte(teid),
	})
}

func mupPath(nlri *gobgppkt.MUPNLRI, attrs ...gobgppkt.PathAttributeInterface) *apiutil.Path {
	return &apiutil.Path{Family: gobgppkt.RF_MUP_IPv4, Nlri: nlri, Attrs: attrs}
}

func TestDecodeMUP_ISD(t *testing.T) {
	rd := gobgppkt.NewRouteDistinguisherTwoOctetAS(65000, 100)
	nlri := gobgppkt.NewMUPInterworkSegmentDiscoveryRoute(rd, netip.MustParsePrefix("192.0.2.0/24"))

	got := decodeMUPRoute(mupPath(nlri))
	if got == nil {
		t.Fatal("decodeMUPRoute returned nil")
	}
	if got.Type != bgp.MUPRouteTypeISD {
		t.Errorf("type = %s, want isd", got.Type)
	}
	if got.RD != "65000:100" || got.Prefix != "192.0.2.0/24" {
		t.Errorf("rd/prefix = %q/%q, want 65000:100/192.0.2.0/24", got.RD, got.Prefix)
	}
}

func TestDecodeMUP_DSD(t *testing.T) {
	rd := gobgppkt.NewRouteDistinguisherTwoOctetAS(65000, 100)
	nlri := gobgppkt.NewMUPDirectSegmentDiscoveryRoute(rd, netip.MustParseAddr("192.0.2.1"))

	got := decodeMUPRoute(mupPath(nlri))
	if got == nil {
		t.Fatal("decodeMUPRoute returned nil")
	}
	if got.Type != bgp.MUPRouteTypeDSD {
		t.Errorf("type = %s, want dsd", got.Type)
	}
	if got.Address != "192.0.2.1" {
		t.Errorf("address = %q, want 192.0.2.1", got.Address)
	}
}

func TestDecodeMUP_T1ST(t *testing.T) {
	rd := gobgppkt.NewRouteDistinguisherTwoOctetAS(65000, 100)
	ep := netip.MustParseAddr("203.0.113.5") // gNB N3
	nlri := gobgppkt.NewMUPType1SessionTransformedRoute(
		rd, netip.MustParsePrefix("10.0.0.1/32"), teidAddr(0x12345678), 9, ep, nil)

	got := decodeMUPRoute(mupPath(nlri))
	if got == nil {
		t.Fatal("decodeMUPRoute returned nil")
	}
	if got.Type != bgp.MUPRouteTypeT1ST {
		t.Errorf("type = %s, want t1st", got.Type)
	}
	if got.Prefix != "10.0.0.1/32" {
		t.Errorf("ue prefix = %q, want 10.0.0.1/32", got.Prefix)
	}
	// T1ST TEID is exact (32 significant bits).
	if got.TEID != 0x12345678 || got.TEIDLen != 32 {
		t.Errorf("teid = 0x%08X/%d, want 0x12345678/32", got.TEID, got.TEIDLen)
	}
	if got.QFI != 9 {
		t.Errorf("qfi = %d, want 9", got.QFI)
	}
	if got.Endpoint != "203.0.113.5" {
		t.Errorf("endpoint = %q, want 203.0.113.5", got.Endpoint)
	}
}

func TestDecodeMUP_T2ST_TEIDPrefix(t *testing.T) {
	rd := gobgppkt.NewRouteDistinguisherTwoOctetAS(65000, 100)
	ep := netip.MustParseAddr("192.0.2.100") // GTP tunnel endpoint (32 bits)
	// EndpointAddressLength = 32 (endpoint) + 8 (TEID prefix bits) = 40.
	nlri := gobgppkt.NewMUPType2SessionTransformedRoute(rd, 40, ep, teidAddr(0xAB000000))

	got := decodeMUPRoute(mupPath(nlri))
	if got == nil {
		t.Fatal("decodeMUPRoute returned nil")
	}
	if got.Type != bgp.MUPRouteTypeT2ST {
		t.Errorf("type = %s, want t2st", got.Type)
	}
	if got.Endpoint != "192.0.2.100" {
		t.Errorf("endpoint = %q, want 192.0.2.100", got.Endpoint)
	}
	// TEID is a /8 prefix: value 0xAB000000, significant length 8.
	if got.TEID != 0xAB000000 || got.TEIDLen != 8 {
		t.Errorf("teid = 0x%08X/%d, want 0xAB000000/8", got.TEID, got.TEIDLen)
	}
}

func TestDecodeMUP_SegmentID(t *testing.T) {
	rd := gobgppkt.NewRouteDistinguisherTwoOctetAS(65000, 100)
	nlri := gobgppkt.NewMUPType2SessionTransformedRoute(rd, 64, netip.MustParseAddr("192.0.2.100"), teidAddr(0x11223344))
	ext := &gobgppkt.PathAttributeExtendedCommunities{
		Value: []gobgppkt.ExtendedCommunityInterface{gobgppkt.NewMUPExtended(7, 0xdeadbeef)},
	}

	got := decodeMUPRoute(mupPath(nlri, ext))
	if got == nil {
		t.Fatal("decodeMUPRoute returned nil")
	}
	if got.SegmentID2 != 7 || got.SegmentID4 != 0xdeadbeef {
		t.Errorf("segment id = %d:%08x, want 7:deadbeef", got.SegmentID2, got.SegmentID4)
	}
	// Full 32-bit TEID for prefixlen 64 (32 endpoint + 32 TEID).
	if got.TEID != 0x11223344 || got.TEIDLen != 32 {
		t.Errorf("teid = 0x%08X/%d, want 0x11223344/32", got.TEID, got.TEIDLen)
	}
}

// IPv6 T2ST: EndpointAddressLength covers the 128-bit endpoint plus the TEID
// prefix bits, so teidLen = EndpointAddressLength - 128.
func TestDecodeMUP_T2ST_IPv6(t *testing.T) {
	rd := gobgppkt.NewRouteDistinguisherTwoOctetAS(65000, 100)
	ep := netip.MustParseAddr("2001:db8::1") // GTP6 tunnel endpoint (128 bits)
	// 128 (endpoint) + 8 (TEID prefix bits) = 136.
	nlri := gobgppkt.NewMUPType2SessionTransformedRoute(rd, 136, ep, teidAddr(0xAB000000))

	got := decodeMUPRoute(mupPath(nlri))
	if got == nil || got.Type != bgp.MUPRouteTypeT2ST {
		t.Fatalf("decoded = %+v", got)
	}
	if got.Endpoint != "2001:db8::1" {
		t.Errorf("endpoint = %q, want 2001:db8::1", got.Endpoint)
	}
	if got.TEID != 0xAB000000 || got.TEIDLen != 8 {
		t.Errorf("teid = 0x%08X/%d, want 0xAB000000/8", got.TEID, got.TEIDLen)
	}
}

// A T2ST whose EndpointAddressLength is below the endpoint's own width is
// malformed (it would otherwise install a match-all-TEID wildcard); decode skips it.
func TestDecodeMUP_T2ST_MalformedLength(t *testing.T) {
	rd := gobgppkt.NewRouteDistinguisherTwoOctetAS(65000, 100)
	ep := netip.MustParseAddr("192.0.2.100")
	// EndpointAddressLength 24 < 32 (the IPv4 endpoint width) → malformed.
	nlri := gobgppkt.NewMUPType2SessionTransformedRoute(rd, 24, ep, teidAddr(0))
	if got := decodeMUPRoute(mupPath(nlri)); got != nil {
		t.Errorf("decodeMUPRoute(malformed T2ST length) = %+v, want nil", got)
	}
}

// A non-MUP NLRI yields nil so the caller skips it.
func TestDecodeMUP_NotMUPNLRI(t *testing.T) {
	nlri, err := gobgppkt.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
	if err != nil {
		t.Fatalf("NewIPAddrPrefix: %v", err)
	}
	p := &apiutil.Path{Family: gobgppkt.RF_MUP_IPv4, Nlri: nlri}
	if got := decodeMUPRoute(p); got != nil {
		t.Errorf("decodeMUPRoute(non-MUP NLRI) = %+v, want nil", got)
	}
}

// pathToRouteEvent recognizes the MUP family and routes it to ev.MUP.
func TestPathToRouteEvent_MUP(t *testing.T) {
	rd := gobgppkt.NewRouteDistinguisherTwoOctetAS(65000, 100)
	nlri := gobgppkt.NewMUPInterworkSegmentDiscoveryRoute(rd, netip.MustParsePrefix("192.0.2.0/24"))
	ev, ok := pathToRouteEvent(mupPath(nlri))
	if !ok {
		t.Fatal("pathToRouteEvent ok = false, want true")
	}
	if ev.Family != bgp.FamilyMUPIPv4 || ev.MUP == nil {
		t.Errorf("event = {family %s, mup %v}, want {mup_ipv4, non-nil}", ev.Family, ev.MUP)
	}
}
