package bgp

import (
	"net/netip"
	"testing"
)

// N3 regression: MUPRoute.Family classifies an IPv4-mapped IPv6 endpoint
// (::ffff:a.b.c.d) as FamilyMUPIPv4. Without Addr.Unmap, netip.Addr.Is4
// returns false for the mapped form so the route silently falls into
// FamilyMUPIPv6 and fillMUPExportRTs reads the wrong family's RTs.
func TestMUPRoute_Family_IPv4MappedIPv6(t *testing.T) {
	cases := []struct {
		name string
		mr   MUPRoute
		want Family
	}{
		{"T2ST mapped v4 endpoint", MUPRoute{Type: MUPRouteTypeT2ST, Endpoint: "::ffff:10.0.0.1"}, FamilyMUPIPv4},
		{"T2ST native v6 endpoint", MUPRoute{Type: MUPRouteTypeT2ST, Endpoint: "2001:db8::1"}, FamilyMUPIPv6},
		{"T2ST plain v4 endpoint", MUPRoute{Type: MUPRouteTypeT2ST, Endpoint: "10.0.0.1"}, FamilyMUPIPv4},
		{"DSD mapped v4 address", MUPRoute{Type: MUPRouteTypeDSD, Address: "::ffff:10.0.0.1"}, FamilyMUPIPv4},
		{"ISD v4 prefix", MUPRoute{Type: MUPRouteTypeISD, Prefix: "10.0.0.0/24"}, FamilyMUPIPv4},
		{"T1ST v6 prefix", MUPRoute{Type: MUPRouteTypeT1ST, Prefix: "2001:db8::/64"}, FamilyMUPIPv6},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := tc.mr.Family()
			if !ok {
				t.Fatalf("Family() ok=false for %+v", tc.mr)
			}
			if got != tc.want {
				t.Errorf("Family() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseFamily(t *testing.T) {
	tests := []struct {
		in      string
		want    Family
		wantErr bool
	}{
		{in: "vpnv4", want: FamilyVPNv4},
		{in: "vpnv6", want: FamilyVPNv6},
		{in: "ipv4_unicast", want: FamilyIPv4Unicast},
		{in: "ipv6_unicast", want: FamilyIPv6Unicast},
		{in: "sr_policy_ipv6", want: FamilySRPolicyIPv6},
		{in: "", wantErr: true},
		{in: "VPNV4", wantErr: true}, // case-sensitive on purpose
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseFamily(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseFamily(%q) = %q, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseFamily(%q) returned %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("ParseFamily(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestValidateIPv6NextHop(t *testing.T) {
	tests := []struct {
		in      string
		wantErr bool
	}{
		{in: "2001:db8:ff::1"},                  // routable IPv6 -> ok
		{in: "fd00:1::1"},                       // ULA -> ok
		{in: "", wantErr: true},                 // empty
		{in: "not-an-ip", wantErr: true},        // garbage
		{in: "192.0.2.1", wantErr: true},        // IPv4
		{in: "::ffff:192.0.2.1", wantErr: true}, // v4-in-6
		{in: "::", wantErr: true},               // unspecified -> blackhole
		{in: "::1", wantErr: true},              // loopback
		{in: "fe80::1", wantErr: true},          // link-local
		{in: "ff02::1", wantErr: true},          // multicast
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			addr, err := ValidateIPv6NextHop(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Errorf("ValidateIPv6NextHop(%q) = %v, want error", tc.in, addr)
				}
				return
			}
			if err != nil {
				t.Errorf("ValidateIPv6NextHop(%q): unexpected error %v", tc.in, err)
			}
		})
	}
}

// TestPathSource covers the identity ECMP aggregation keys on. The zero
// value must read as "locally originated", because that is what gobgp
// hands back for this node's own advertisements and ListRoutes uses it to
// skip them.
func TestPathSource(t *testing.T) {
	peer := netip.MustParseAddr("fd00::1")

	t.Run("zero value is local", func(t *testing.T) {
		var s PathSource
		if !s.IsLocal() {
			t.Error("zero PathSource must report IsLocal")
		}
		if got := s.String(); got != "local" {
			t.Errorf("String() = %q, want %q", got, "local")
		}
	})

	t.Run("peer without add-path", func(t *testing.T) {
		s := PathSource{Peer: peer}
		if s.IsLocal() {
			t.Error("a path from a peer must not report IsLocal")
		}
		if got, want := s.String(), "fd00::1"; got != want {
			t.Errorf("String() = %q, want %q", got, want)
		}
	})

	t.Run("peer with add-path id", func(t *testing.T) {
		s := PathSource{Peer: peer, PathID: 3}
		if got, want := s.String(), "fd00::1#3"; got != want {
			t.Errorf("String() = %q, want %q", got, want)
		}
	})

	t.Run("comparable and usable as a map key", func(t *testing.T) {
		// The accumulator keys per-path state on this struct, so it must be
		// comparable and must not collide across peers or path ids.
		seen := map[PathSource]int{}
		seen[PathSource{Peer: peer, PathID: 1}]++
		seen[PathSource{Peer: peer, PathID: 2}]++
		seen[PathSource{Peer: netip.MustParseAddr("fd00::2"), PathID: 1}]++
		seen[PathSource{Peer: peer, PathID: 1}]++
		if len(seen) != 3 {
			t.Fatalf("distinct sources collapsed: got %d keys, want 3", len(seen))
		}
		if n := seen[PathSource{Peer: peer, PathID: 1}]; n != 2 {
			t.Errorf("repeat of one source counted %d times, want 2", n)
		}
	})
}

// SegmentList and SegmentLists are two views of one thing, and only the BGP
// decoder fills both. Lists() is what keeps a locally configured path -- which
// carries just SegmentList -- from looking empty to a weighted consumer.
func TestCandidatePathLists(t *testing.T) {
	a := netip.MustParseAddr("fd00:1::1")
	b := netip.MustParseAddr("fd00:2::1")

	t.Run("decoder-populated set is returned as is", func(t *testing.T) {
		cp := CandidatePath{
			SegmentList: []netip.Addr{a},
			SegmentLists: []WeightedSegmentList{
				{Segments: []netip.Addr{a}, Weight: 1},
				{Segments: []netip.Addr{b}, Weight: 4},
			},
		}
		got := cp.Lists()
		if len(got) != 2 || got[1].Weight != 4 {
			t.Fatalf("Lists() = %v, want both weighted lists", got)
		}
	})

	t.Run("single-list producer is normalized to one equal share", func(t *testing.T) {
		// This is the shape LocalSRPolicy and the advertise API produce.
		cp := CandidatePath{SegmentList: []netip.Addr{a, b}}
		got := cp.Lists()
		if len(got) != 1 {
			t.Fatalf("Lists() = %v, want one synthesized list", got)
		}
		if got[0].Weight != SRPolicyDefaultWeight {
			t.Errorf("weight = %d, want the default %d", got[0].Weight, SRPolicyDefaultWeight)
		}
		if len(got[0].Segments) != 2 {
			t.Errorf("segments = %v, want both carried through", got[0].Segments)
		}
	})

	t.Run("an ineligible candidate has no lists", func(t *testing.T) {
		if got := (CandidatePath{}).Lists(); got != nil {
			t.Errorf("Lists() = %v, want nil for a candidate with no segments", got)
		}
	})
}
