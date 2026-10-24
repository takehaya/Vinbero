package gobgp

import (
	"errors"
	"fmt"
	"testing"

	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/takehaya/vinbero/pkg/bgp/demux"
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

// Explicit IANA RFC assignments checked on 2026-10-24, independent of the
// pinned GoBGP constants. Exercise the registry wired by vinberod, not just
// membership: both registration and replacement must reject standard values.
func TestBuiltinEndpointBehaviorsReserveStandardAssignments(t *testing.T) {
	standard := []uint16{
		// RFC 8986 (0 is rejected separately; 0xFFFF remains opaque).
		0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008,
		0x0009, 0x000A, 0x000B, 0x000C, 0x000E, 0x000F, 0x0010, 0x0011,
		0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0017, 0x0018, 0x001B,
		0x001C, 0x001D, 0x001E, 0x001F, 0x0020, 0x0021, 0x0022, 0x0023,
		0x0024, 0x0025, 0x0026, 0x0027, 0x7FFF,
		// RFC 9433, RFC 9491, RFC 9524, RFC 9801, RFC 10018.
		0x0028, 0x0029, 0x0045, 0x0046, 0x0047, 0x0048, 0x0054, 0x004B,
		0x009E, 0x009F, 0x00A0, 0x004C, 0x004D, 0x004E,
		// RFC 9800, section 12.1, Table 1.
		0x002B, 0x002C, 0x002D, 0x002E, 0x002F, 0x0030, 0x0031, 0x0032,
		0x0034, 0x0035, 0x0036, 0x0037, 0x0038, 0x0039, 0x003A, 0x003B,
		0x0055, 0x0056, 0x0057, 0x0058, 0x0059, 0x005A, 0x005B, 0x005C,
		0x005D, 0x005E, 0x005F, 0x0060, 0x0061,
		0x0065, 0x0066, 0x0067, 0x0068, 0x0069, 0x006A, 0x006B, 0x006C,
		0x006D, 0x006E, 0x006F, 0x0070,
		0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077, 0x0078, 0x0079,
		0x007A, 0x007B, 0x007C,
		0x007F, 0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086,
		0x0087, 0x0088, 0x0089, 0x008A, 0x008B, 0x008C, 0x008D,
	}
	for _, cp := range standard {
		t.Run(fmt.Sprintf("%#04x", cp), func(t *testing.T) {
			r := demux.NewClaimRegistry(BuiltinEndpointBehaviors())
			if err := r.Claim("custom", []uint16{cp}); !errors.Is(err, demux.ErrUnclaimable) {
				t.Fatalf("Claim(%#x) = %v; want ErrUnclaimable", cp, err)
			}
			if r.IsClaimed(cp) {
				t.Fatal("rejected standard behavior became claimed")
			}
			if err := r.Claim("custom", []uint16{0xFE01}); err != nil {
				t.Fatal(err)
			}
			if err := r.Replace("custom", []uint16{cp}); !errors.Is(err, demux.ErrUnclaimable) {
				t.Fatalf("Replace(%#x) = %v; want ErrUnclaimable", cp, err)
			}
			if !r.IsClaimed(0xFE01) || r.IsClaimed(cp) {
				t.Fatal("rejected replacement changed claims")
			}
		})
	}
}

func TestBuiltinEndpointBehaviorsKeepCustomClaims(t *testing.T) {
	// Preserve existing custom claims, including draft-only assignments and
	// unassigned holes between RFC assignments. This is not an IANA policy gate.
	for _, cp := range []uint16{
		0x000D, 0x001A, 0x002A, 0x0033, 0x003C, 0x0044, 0x0049, 0x004A,
		0x004F, 0x0053, 0x0062, 0x0063, 0x0064, 0x0071, 0x007D, 0x007E,
		0x008E, 0x009D, 0x00A1, 0x7FFE, 0x8000, 0x87FF, 0xFE01, 0xFEFF, 0xFFFF,
	} {
		r := demux.NewClaimRegistry(BuiltinEndpointBehaviors())
		if err := r.Claim("custom", []uint16{cp}); err != nil {
			t.Errorf("Claim(%#x) = %v; existing custom value must remain claimable", cp, err)
		}
	}
}
