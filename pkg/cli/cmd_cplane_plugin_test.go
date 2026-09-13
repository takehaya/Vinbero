package cli

import (
	"math"
	"testing"
)

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

// uint is 64 bits on the platforms this runs on, so a slot number wider
// than the request field wraps silently. --endpoint-slot 4294967328 would
// arrive at the daemon as 32, pass its range check, and grant a slot the
// operator never named.
func TestSlotFlagsThatDoNotFitAreRefused(t *testing.T) {
	if _, err := uintSliceToUint32("endpoint-slot", []uint{math.MaxUint32 + 1}); err == nil {
		t.Fatal("a slot number wider than 32 bits was accepted")
	}
	got, err := uintSliceToUint32("endpoint-slot", []uint{32, 33})
	if err != nil {
		t.Fatalf("ordinary slots were refused: %v", err)
	}
	if len(got) != 2 || got[0] != 32 || got[1] != 33 {
		t.Fatalf("converted %v, want the slots as given", got)
	}
}
