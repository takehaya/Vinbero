package cli

import "testing"

// A behavior is conventionally written in hex (RFC 8986 numbers them that
// way), so reading 0x0013 as decimal 13 would claim a different one.
func TestParseBehaviorFlags(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []uint32
	}{
		{name: "empty", in: nil},
		{name: "decimal", in: []string{"19"}, want: []uint32{19}},
		{name: "hex", in: []string{"0x0013"}, want: []uint32{0x13}},
		{name: "uppercase hex", in: []string{"0XFE01"}, want: []uint32{0xFE01}},
		{name: "mixed", in: []string{"0xFE01", "65000"}, want: []uint32{0xFE01, 65000}},
		{name: "whitespace", in: []string{" 0xFE01 "}, want: []uint32{0xFE01}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseBehaviorFlags(tt.in)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
}

// A codepoint is 16 bits; a larger value must be refused rather than
// truncated into someone else's behavior.
func TestParseBehaviorFlagsRejectsBadValues(t *testing.T) {
	for _, in := range []string{"", "nonsense", "0x10000", "70000", "-1"} {
		if _, err := parseBehaviorFlags([]string{in}); err == nil {
			t.Errorf("value %q was accepted", in)
		}
	}
}
