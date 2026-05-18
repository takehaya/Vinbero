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
