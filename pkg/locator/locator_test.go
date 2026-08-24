package locator

import (
	"errors"
	"net/netip"
	"testing"
)

func makeClassic48(t *testing.T) Locator {
	t.Helper()
	prefix := netip.MustParsePrefix("fd00:1:1::/48")
	return Locator{
		Name: "LOC1", Prefix: prefix,
		BlockLen: 32, NodeLen: 16, FunctionLen: 16, ArgumentLen: 64,
		Behavior:          BehaviorClassic,
		FunctionAutoStart: 0x10, FunctionAutoEnd: 0xFFFE,
	}
}

func makeUSID48(t *testing.T) Locator {
	t.Helper()
	return Locator{
		Name: "USID1", Prefix: netip.MustParsePrefix("fd00:0:0:aa::/48"),
		BlockLen: 32, NodeLen: 16, FunctionLen: 16, ArgumentLen: 0,
		Behavior:          BehaviorUSID,
		FunctionAutoStart: 1, FunctionAutoEnd: 0xFFFE,
	}
}

func TestValidate_OK(t *testing.T) {
	loc := makeClassic48(t)
	if err := loc.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_Errors(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Locator)
	}{
		{"empty-name", func(l *Locator) { l.Name = "" }},
		{"bad-prefix-bits", func(l *Locator) { l.BlockLen = 24 }}, // block+node now 40 != prefix 48
		{"oversize-funclen", func(l *Locator) { l.FunctionLen = 64; l.ArgumentLen = 16 }},
		{"auto-end<start", func(l *Locator) { l.FunctionAutoStart = 100; l.FunctionAutoEnd = 50 }},
		{"unknown-behavior", func(l *Locator) { l.Behavior = Behavior(99) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			loc := makeClassic48(t)
			tc.mutate(&loc)
			if err := loc.Validate(); err == nil {
				t.Errorf("expected error")
			}
		})
	}
}

func TestValidate_USID(t *testing.T) {
	loc := makeUSID48(t)
	if err := loc.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Locator)
	}{
		{"prefix-length", func(l *Locator) { l.NodeLen = 8 }},
		{"function-length", func(l *Locator) { l.FunctionLen = 15 }},
		{"argument-length", func(l *Locator) { l.ArgumentLen = 64 }},
		{"non-f3216-block", func(l *Locator) { l.BlockLen = 40; l.NodeLen = 8 }},
		{"non-f3216-node", func(l *Locator) {
			l.BlockLen = 24
			l.NodeLen = 24
			l.Prefix = netip.MustParsePrefix("fd00::/48")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			loc := makeUSID48(t)
			tc.mutate(&loc)
			if err := loc.Validate(); !errors.Is(err, ErrInvalidLocator) {
				t.Errorf("Validate: got %v, want ErrInvalidLocator", err)
			}
		})
	}
}

func TestBuildSID_RoundTrip(t *testing.T) {
	loc := makeClassic48(t)
	for _, fn := range []uint32{0, 0x1, 0x10, 0xABCD, 0xFFFF} {
		sid, err := loc.BuildSID(fn)
		if err != nil {
			t.Fatalf("BuildSID(%#x): %v", fn, err)
		}
		got, ok, err := loc.ParseSID(sid)
		if err != nil || !ok {
			t.Fatalf("ParseSID(%s): ok=%v err=%v", sid, ok, err)
		}
		if got != fn {
			t.Errorf("round-trip: got %#x want %#x sid=%s", got, fn, sid)
		}
	}
}

func TestParseSID_ForeignPrefixMisses(t *testing.T) {
	loc := makeClassic48(t)
	foreign := netip.MustParseAddr("2001:db8::1")
	if _, ok, _ := loc.ParseSID(foreign); ok {
		t.Errorf("ParseSID on foreign prefix should miss")
	}
}

func TestBuildSID_OutOfRange(t *testing.T) {
	loc := makeClassic48(t)
	_, err := loc.BuildSID(0x10000) // function_len=16, max=0xFFFF
	if !errors.Is(err, ErrFunctionOutOfRange) {
		t.Errorf("expected ErrFunctionOutOfRange, got %v", err)
	}
}

func TestBuildSID_USIDRoundTrip(t *testing.T) {
	loc := makeUSID48(t)
	for _, fn := range []uint32{1, 0xaa, 0xf321, 0xffff} {
		sid, err := loc.BuildSID(fn)
		if err != nil {
			t.Fatalf("BuildSID(%#x): %v", fn, err)
		}
		got, ok, err := loc.ParseSID(sid)
		if err != nil || !ok || got != fn {
			t.Errorf("ParseSID(%s) = (%#x, %v, %v), want (%#x, true, nil)", sid, got, ok, err, fn)
		}
	}
	sid, err := loc.BuildSID(0xaa)
	if err != nil {
		t.Fatalf("BuildSID(0xaa): %v", err)
	}
	if want := netip.MustParseAddr("fd00:0:0:aa::"); sid != want {
		t.Errorf("BuildSID(0xaa) = %s, want %s", sid, want)
	}
}

func TestParseSID_USIDRejectsNonZeroRemainder(t *testing.T) {
	loc := makeUSID48(t)
	for _, sid := range []netip.Addr{
		netip.MustParseAddr("fd00:0:0:aa::1"),
		netip.MustParseAddr("fd00:0:0:aa:8000::"),
	} {
		if _, ok, err := loc.ParseSID(sid); err != nil || ok {
			t.Errorf("ParseSID(%s) = (ok=%v, err=%v), want (false, nil)", sid, ok, err)
		}
	}
}

func TestParseSID_USIDRejectsZeroFunction(t *testing.T) {
	loc := makeUSID48(t)
	// The bare locator prefix carries CSID 0 (the container terminator),
	// which BuildSID and the allocator refuse to mint; ParseSID must not
	// report it as a valid service uSID either.
	bare := netip.MustParseAddr("fd00:0:0::")
	if _, ok, err := loc.ParseSID(bare); err != nil || ok {
		t.Errorf("ParseSID(%s) = (ok=%v, err=%v), want (false, nil)", bare, ok, err)
	}
}

func TestBuildSID_USIDZeroReserved(t *testing.T) {
	loc := makeUSID48(t)
	if _, err := loc.BuildSID(0); !errors.Is(err, ErrFunctionReserved) {
		t.Errorf("BuildSID(0): got %v, want ErrFunctionReserved", err)
	}
}
