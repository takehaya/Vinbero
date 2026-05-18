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

func TestUSID_Unimplemented(t *testing.T) {
	loc := makeClassic48(t)
	loc.Behavior = BehaviorUSID
	if _, err := loc.BuildSID(0x10); !errors.Is(err, ErrUnimplemented) {
		t.Errorf("BuildSID uSID: want ErrUnimplemented, got %v", err)
	}
	if _, _, err := loc.ParseSID(netip.MustParseAddr("fd00:1:1::1")); !errors.Is(err, ErrUnimplemented) {
		t.Errorf("ParseSID uSID: want ErrUnimplemented, got %v", err)
	}
}
