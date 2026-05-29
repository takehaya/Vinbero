package gobgp

import (
	"net/netip"
	"testing"

	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// sidEqual compares two SRv6 SID strings by value, tolerating formatting
// differences in the textual IPv6 rendering.
func sidEqual(t *testing.T, got, want string) bool {
	t.Helper()
	return netip.MustParseAddr(got) == netip.MustParseAddr(want)
}

// Each encoder is the inverse of decodeMUPRoute: encode a MUPRoute, decode the
// resulting path, and the round trip must preserve the route's fields.
func TestEncodeDecodeMUP_RoundTrip(t *testing.T) {
	const (
		rd = "65000:100"
		nh = "fd00:1::1"
	)

	t.Run("ISD", func(t *testing.T) {
		in := bgp.MUPRoute{Type: bgp.MUPRouteTypeISD, RD: rd, Prefix: "192.0.2.0/24", SRv6SID: "fd00:2:2:b::", NextHop: nh}
		p, err := encodeMUPISDPath(in)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		got := decodeMUPRoute(p)
		if got == nil || got.Type != bgp.MUPRouteTypeISD || got.RD != rd || got.Prefix != "192.0.2.0/24" {
			t.Fatalf("decoded = %+v", got)
		}
		if !sidEqual(t, got.SRv6SID, in.SRv6SID) {
			t.Errorf("sid = %q, want %q", got.SRv6SID, in.SRv6SID)
		}
	})

	t.Run("DSD", func(t *testing.T) {
		in := bgp.MUPRoute{Type: bgp.MUPRouteTypeDSD, RD: rd, Address: "192.0.2.1", SegmentID2: 7, SegmentID4: 0xdeadbeef, SRv6SID: "fd00:3:3:c::", NextHop: nh}
		p, err := encodeMUPDSDPath(in)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		got := decodeMUPRoute(p)
		if got == nil || got.Type != bgp.MUPRouteTypeDSD || got.Address != "192.0.2.1" {
			t.Fatalf("decoded = %+v", got)
		}
		if got.SegmentID2 != 7 || got.SegmentID4 != 0xdeadbeef {
			t.Errorf("segment id = %d:%08x, want 7:deadbeef", got.SegmentID2, got.SegmentID4)
		}
	})

	t.Run("T1ST", func(t *testing.T) {
		in := bgp.MUPRoute{
			Type: bgp.MUPRouteTypeT1ST, RD: rd, Prefix: "10.0.0.1/32",
			TEID: 0x12345678, TEIDLen: 32, QFI: 9, Endpoint: "203.0.113.5",
			SRv6SID: "fd00:2:2:b::", NextHop: nh,
		}
		p, err := encodeMUPT1STPath(in)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		got := decodeMUPRoute(p)
		if got == nil || got.Type != bgp.MUPRouteTypeT1ST {
			t.Fatalf("decoded = %+v", got)
		}
		if got.Prefix != "10.0.0.1/32" || got.TEID != 0x12345678 || got.QFI != 9 || got.Endpoint != "203.0.113.5" {
			t.Errorf("decoded T1ST = {prefix %s, teid 0x%08X, qfi %d, ep %s}", got.Prefix, got.TEID, got.QFI, got.Endpoint)
		}
	})

	t.Run("T1ST_IPv6", func(t *testing.T) {
		in := bgp.MUPRoute{
			Type: bgp.MUPRouteTypeT1ST, RD: rd, Prefix: "2001:db8:a::1/128",
			TEID: 0x12345678, TEIDLen: 32, QFI: 5, Endpoint: "2001:db8:b::1",
			SRv6SID: "fd00:6:6:b::", NextHop: nh,
		}
		p, err := encodeMUPT1STPath(in)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if p.Family != gobgppkt.RF_MUP_IPv6 {
			t.Errorf("family = %v, want RF_MUP_IPv6", p.Family)
		}
		got := decodeMUPRoute(p)
		if got == nil || got.Prefix != "2001:db8:a::1/128" || got.Endpoint != "2001:db8:b::1" || got.TEID != 0x12345678 {
			t.Fatalf("decoded T1ST v6 = %+v", got)
		}
	})

	t.Run("T2ST_IPv6_TEIDPrefix", func(t *testing.T) {
		in := bgp.MUPRoute{
			Type: bgp.MUPRouteTypeT2ST, RD: rd, Endpoint: "2001:db8::1",
			TEID: 0xAB000000, TEIDLen: 8, SRv6SID: "fd00:6:6:c::", NextHop: nh,
		}
		p, err := encodeMUPT2STPath(in)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if p.Family != gobgppkt.RF_MUP_IPv6 {
			t.Errorf("family = %v, want RF_MUP_IPv6", p.Family)
		}
		got := decodeMUPRoute(p)
		if got == nil || got.Endpoint != "2001:db8::1" || got.TEID != 0xAB000000 || got.TEIDLen != 8 {
			t.Fatalf("decoded T2ST v6 = %+v", got)
		}
	})

	t.Run("T2ST_TEIDPrefix", func(t *testing.T) {
		in := bgp.MUPRoute{
			Type: bgp.MUPRouteTypeT2ST, RD: rd, Endpoint: "192.0.2.100",
			TEID: 0xAB000000, TEIDLen: 8, SegmentID2: 1, SegmentID4: 2,
			SRv6SID: "fd00:3:3:c::", NextHop: nh,
		}
		p, err := encodeMUPT2STPath(in)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		got := decodeMUPRoute(p)
		if got == nil || got.Type != bgp.MUPRouteTypeT2ST || got.Endpoint != "192.0.2.100" {
			t.Fatalf("decoded = %+v", got)
		}
		if got.TEID != 0xAB000000 || got.TEIDLen != 8 {
			t.Errorf("teid = 0x%08X/%d, want 0xAB000000/8", got.TEID, got.TEIDLen)
		}
		if got.SegmentID2 != 1 || got.SegmentID4 != 2 {
			t.Errorf("segment id = %d:%d, want 1:2", got.SegmentID2, got.SegmentID4)
		}
	})
}
