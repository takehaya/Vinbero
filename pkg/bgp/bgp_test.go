package bgp

import "testing"

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
		{in: "ipv6_unicast", want: FamilyIPv6Unicast},
		{in: "sr_policy_ipv6", want: FamilySRPolicyIPv6},
		{in: "", wantErr: true},
		{in: "ipv4_unicast", wantErr: true},
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
