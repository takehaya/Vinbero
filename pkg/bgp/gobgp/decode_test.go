package gobgp

import (
	"net/netip"
	"testing"

	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func TestDecodeSRv6SID(t *testing.T) {
	sid := netip.MustParseAddr("fd00:1:1::100")
	psid := &gobgppkt.PathAttributePrefixSID{
		TLVs: []gobgppkt.PrefixSIDTLVInterface{
			&gobgppkt.SRv6ServiceTLV{
				TLV:     gobgppkt.TLV{Type: gobgppkt.TLVTypeSRv6L3Service},
				SubTLVs: []gobgppkt.PrefixSIDTLVInterface{
					&gobgppkt.SRv6InformationSubTLV{SID: sid.AsSlice()},
				},
			},
		},
	}
	got := decodeSRv6SID([]gobgppkt.PathAttributeInterface{psid}, 0, gobgppkt.TLVTypeSRv6L3Service)
	if got != sid.String() {
		t.Errorf("decodeSRv6SID = %q, want %q", got, sid.String())
	}
}

func TestDecodeSRv6SID_AbsentAttribute(t *testing.T) {
	// A path with no Prefix-SID attribute yields an empty SID.
	if got := decodeSRv6SID(nil, 0, gobgppkt.TLVTypeSRv6L3Service); got != "" {
		t.Errorf("decodeSRv6SID(nil) = %q, want empty", got)
	}
}

// TestDecodeSRv6SID_Transposition covers RFC 9252 §4 transposition: the
// SID Structure Sub-Sub-TLV says 16 bits are transposed at offset 64,
// so the SID TLV on the wire carries only the bare locator fd00:200::
// and the function value travels in the VPN label. decodeSRv6SID must
// fold the label bits back to reconstruct the full SID -- this is what
// FRR (and Cisco / Juniper) advertise.
func TestDecodeSRv6SID_Transposition(t *testing.T) {
	onWire := netip.MustParseAddr("fd00:200::")
	psid := &gobgppkt.PathAttributePrefixSID{
		TLVs: []gobgppkt.PrefixSIDTLVInterface{
			&gobgppkt.SRv6ServiceTLV{
				TLV:     gobgppkt.TLV{Type: gobgppkt.TLVTypeSRv6L3Service},
				SubTLVs: []gobgppkt.PrefixSIDTLVInterface{
					&gobgppkt.SRv6InformationSubTLV{
						SID: onWire.AsSlice(),
						SubSubTLVs: []gobgppkt.PrefixSIDTLVInterface{
							// lbl=32 lnl=16 fl=16 al=0 tl=16 to=64
							gobgppkt.NewSRv6SIDStructureSubSubTLV(32, 16, 16, 0, 16, 64),
						},
					},
				},
			},
		},
	}
	// The function value 1 travels in the high 16 bits of the 20-bit label.
	const label = 1 << (20 - 16)
	got := decodeSRv6SID([]gobgppkt.PathAttributeInterface{psid}, label, gobgppkt.TLVTypeSRv6L3Service)
	if want := "fd00:200:0:0:1::"; got != want {
		t.Errorf("decodeSRv6SID with transposition = %q, want %q", got, want)
	}

	// Without the label the bare locator must come back unchanged, so a
	// non-transposing peer is unaffected.
	if got := decodeSRv6SID([]gobgppkt.PathAttributeInterface{psid}, 0, gobgppkt.TLVTypeSRv6L3Service); got != "fd00:200::" {
		t.Errorf("decodeSRv6SID transposition with zero label = %q, want fd00:200::", got)
	}
}

// TestDecodeSRv6SID_TranspositionMalformed: a SID Structure Sub-Sub-TLV
// whose transposed window (offset+length) runs past the 128-bit SID is
// malformed -- the real SID cannot be reconstructed, so decodeSRv6SID
// drops it rather than return a truncated, wrong encap target.
func TestDecodeSRv6SID_TranspositionMalformed(t *testing.T) {
	psid := &gobgppkt.PathAttributePrefixSID{
		TLVs: []gobgppkt.PrefixSIDTLVInterface{
			&gobgppkt.SRv6ServiceTLV{
				TLV:     gobgppkt.TLV{Type: gobgppkt.TLVTypeSRv6L3Service},
				SubTLVs: []gobgppkt.PrefixSIDTLVInterface{
					&gobgppkt.SRv6InformationSubTLV{
						SID: netip.MustParseAddr("fd00:200::").AsSlice(),
						SubSubTLVs: []gobgppkt.PrefixSIDTLVInterface{
							// offset 120 + length 20 = 140 > 128 bits.
							gobgppkt.NewSRv6SIDStructureSubSubTLV(32, 16, 16, 0, 20, 120),
						},
					},
				},
			},
		},
	}
	if got := decodeSRv6SID([]gobgppkt.PathAttributeInterface{psid}, 0xFFFFF, gobgppkt.TLVTypeSRv6L3Service); got != "" {
		t.Errorf("malformed transposition: decodeSRv6SID = %q, want empty", got)
	}
}

func TestDecodeRouteTargets(t *testing.T) {
	rt := gobgppkt.NewTwoOctetAsSpecificExtended(
		gobgppkt.EC_SUBTYPE_ROUTE_TARGET, 65000, 100, true)
	// A Site-of-Origin community shares the wire type but must not be
	// reported as an RT.
	soo := gobgppkt.NewTwoOctetAsSpecificExtended(
		gobgppkt.EC_SUBTYPE_ROUTE_ORIGIN, 65000, 999, true)
	ec := &gobgppkt.PathAttributeExtendedCommunities{
		Value: []gobgppkt.ExtendedCommunityInterface{rt, soo},
	}
	got := decodeRouteTargets([]gobgppkt.PathAttributeInterface{ec})
	if len(got) != 1 {
		t.Fatalf("decodeRouteTargets returned %v, want exactly one RT", got)
	}
	if got[0] != "65000:100" {
		t.Errorf("RT = %q, want 65000:100", got[0])
	}
}

func TestDecodeRouteTargets_None(t *testing.T) {
	if got := decodeRouteTargets(nil); got != nil {
		t.Errorf("decodeRouteTargets(nil) = %v, want nil", got)
	}
}

func TestDecodeColor(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		ec := &gobgppkt.PathAttributeExtendedCommunities{
			Value: []gobgppkt.ExtendedCommunityInterface{gobgppkt.NewColorExtended(100)},
		}
		if got := decodeColor([]gobgppkt.PathAttributeInterface{ec}); got != 100 {
			t.Errorf("decodeColor = %d, want 100", got)
		}
	})
	t.Run("absent", func(t *testing.T) {
		if got := decodeColor(nil); got != 0 {
			t.Errorf("decodeColor(nil) = %d, want 0", got)
		}
	})
	t.Run("highest-wins", func(t *testing.T) {
		ec := &gobgppkt.PathAttributeExtendedCommunities{
			Value: []gobgppkt.ExtendedCommunityInterface{
				gobgppkt.NewColorExtended(50),
				gobgppkt.NewColorExtended(200),
				gobgppkt.NewColorExtended(100),
			},
		}
		if got := decodeColor([]gobgppkt.PathAttributeInterface{ec}); got != 200 {
			t.Errorf("decodeColor (multiple) = %d, want highest 200", got)
		}
	})
}

func TestDecodeNextHop(t *testing.T) {
	t.Run("mp-reach", func(t *testing.T) {
		nh := netip.MustParseAddr("2001:db8::1")
		mp := &gobgppkt.PathAttributeMpReachNLRI{Nexthop: nh}
		if got := decodeNextHop([]gobgppkt.PathAttributeInterface{mp}); got != nh.String() {
			t.Errorf("decodeNextHop (mp-reach) = %q, want %q", got, nh.String())
		}
	})
	t.Run("legacy-next-hop", func(t *testing.T) {
		nh := netip.MustParseAddr("10.0.0.1")
		attr := &gobgppkt.PathAttributeNextHop{Value: nh}
		if got := decodeNextHop([]gobgppkt.PathAttributeInterface{attr}); got != nh.String() {
			t.Errorf("decodeNextHop (legacy) = %q, want %q", got, nh.String())
		}
	})
	t.Run("absent", func(t *testing.T) {
		if got := decodeNextHop(nil); got != "" {
			t.Errorf("decodeNextHop(nil) = %q, want empty", got)
		}
	})
}

func TestNlriString_Nil(t *testing.T) {
	if got := nlriString(nil); got != "" {
		t.Errorf("nlriString(nil) = %q, want empty", got)
	}
}
