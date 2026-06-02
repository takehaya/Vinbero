package bgp

import "testing"

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
