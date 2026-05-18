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
				SubTLVs: []gobgppkt.PrefixSIDTLVInterface{
					&gobgppkt.SRv6InformationSubTLV{SID: sid.AsSlice()},
				},
			},
		},
	}
	got := decodeSRv6SID([]gobgppkt.PathAttributeInterface{psid})
	if got != sid.String() {
		t.Errorf("decodeSRv6SID = %q, want %q", got, sid.String())
	}
}

func TestDecodeSRv6SID_AbsentAttribute(t *testing.T) {
	// A path with no Prefix-SID attribute yields an empty SID.
	if got := decodeSRv6SID(nil); got != "" {
		t.Errorf("decodeSRv6SID(nil) = %q, want empty", got)
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
