package gobgp

import (
	"testing"

	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// The list is what stops a plugin claiming a behavior vinbero implements.
// A codepoint dropped from it is a codepoint a plugin can take, and the
// routes carrying it stop reaching the built-in appliers -- which is the
// wrong-meaning install the claim rule exists to prevent, arriving through
// the rule itself.
func TestBuiltinEndpointBehaviorsCoverWhatVinberoImplements(t *testing.T) {
	got := make(map[uint16]struct{}, len(BuiltinEndpointBehaviors()))
	for _, b := range BuiltinEndpointBehaviors() {
		got[b] = struct{}{}
	}

	// The behaviors vinbero's data plane implements, named rather than
	// counted: a test that only counted would pass after a substitution.
	want := []struct {
		name string
		code gobgppkt.SRBehavior
	}{
		{"End", gobgppkt.END},
		{"End.PSP", gobgppkt.END_WITH_PSP},
		{"End.USP", gobgppkt.END_WITH_USP},
		{"End.X", gobgppkt.ENDX},
		{"End.T", gobgppkt.ENDT},
		{"End.DX4", gobgppkt.END_DX4},
		{"End.DX6", gobgppkt.END_DX6},
		{"End.DT4", gobgppkt.END_DT4},
		{"End.DT6", gobgppkt.END_DT6},
		{"End.DT46", gobgppkt.END_DT46},
		{"End.DX2", gobgppkt.END_DX2},
		{"End.DT2U", gobgppkt.END_DT2U},
		{"End.DT2M", gobgppkt.END_DT2M},
		{"End.B6.Encaps", gobgppkt.END_B6_ENCAPS},
		{"End.B6.Encaps.Red", gobgppkt.END_B6_ENCAPS_Red},
	}
	for _, w := range want {
		if _, ok := got[uint16(w.code)]; !ok {
			t.Errorf("%s (%#x) is missing, so a plugin could claim a behavior vinbero implements",
				w.name, uint16(w.code))
		}
	}

	// Zero is not a behavior, and reserving it here would be a second
	// place saying so.
	if _, ok := got[0]; ok {
		t.Error("codepoint 0 is in the list; it means \"no behavior\" and is refused separately")
	}

	// The private range an operator picks from must stay claimable, or the
	// mechanism this list guards has nothing left to offer.
	for _, cp := range []uint16{0xFE01, 0xFEFF, 0xFFFF} {
		if _, ok := got[cp]; ok {
			t.Errorf("%#x is reserved as built-in, but it is in the range operators claim from", cp)
		}
	}
}
