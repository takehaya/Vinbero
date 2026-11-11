package evpn

import (
	"strings"
	"testing"
)

func TestValidateESI(t *testing.T) {
	cases := []struct {
		name    string
		esi     [ESILen]byte
		wantErr string // substring; empty means valid
	}{
		{"type 0 zero (single-homed)", [ESILen]byte{}, ""},
		{"type 0 any value", [ESILen]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 0xff}, ""},
		{"type 1 valid", [ESILen]byte{1, 0xaa, 0xbb, 0xcc, 0, 0, 1, 0, 5, 0}, ""},
		{"type 1 nonzero last octet", [ESILen]byte{1, 0xaa, 0xbb, 0xcc, 0, 0, 1, 0, 5, 1}, "octet 10 is 0x01 but must be 0x00"},
		{"type 1 all ff", [ESILen]byte{1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, "LACP-based"},
		{"type 2 valid", [ESILen]byte{2, 0xaa, 0xbb, 0xcc, 0, 0, 1, 0x80, 0, 0}, ""},
		{"type 2 nonzero last octet", [ESILen]byte{2, 0xaa, 0xbb, 0xcc, 0, 0, 1, 0x80, 0, 9}, "bridge MAC"},
		{"type 3 valid with ff last octet", [ESILen]byte{3, 0xaa, 0xbb, 0xcc, 0, 0, 1, 0, 0, 0xff}, ""},
		{"type 4 valid", [ESILen]byte{4, 10, 0, 0, 1, 0, 0, 0, 9, 0}, ""},
		{"type 4 nonzero last octet", [ESILen]byte{4, 10, 0, 0, 1, 0, 0, 0, 9, 2}, "router ID"},
		{"type 5 valid", [ESILen]byte{5, 0, 0, 0xfd, 0xe8, 0, 0, 0, 3, 0}, ""},
		{"type 5 nonzero last octet", [ESILen]byte{5, 0, 0, 0xfd, 0xe8, 0, 0, 0, 3, 3}, "AS number"},
		{"type 6", [ESILen]byte{6}, "not defined"},
		{"type 0xff", [ESILen]byte{0xff, 1}, "not defined"},
	}
	for _, c := range cases {
		err := ValidateESI(c.esi)
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("%s: unexpected error %v", c.name, err)
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Errorf("%s: error %v, want it to contain %q", c.name, err, c.wantErr)
		}
	}
}
