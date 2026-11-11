package bpf

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// The Go index layout must be the one the data plane is compiled with: the
// MAX_BUM_NEXTHOPS and BD_PEER_* definitions in src/core/xdp_prog.h.
func TestBdPeerLayoutMatchesC(t *testing.T) {
	src, err := os.ReadFile("../../src/core/xdp_prog.h")
	if err != nil {
		t.Fatal(err)
	}
	defs := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^#define (MAX_BUM_NEXTHOPS|BD_PEER_\w+) (.+)$`).FindAllStringSubmatch(string(src), -1) {
		defs[m[1]] = m[2]
	}
	var eval func(string) int
	eval = func(expr string) int {
		if n, err := strconv.ParseInt(expr, 0, 32); err == nil {
			return int(n)
		}
		if m := regexp.MustCompile(`^\((\w+) \+ (\w+)\)$`).FindStringSubmatch(expr); m != nil {
			return eval(defs[m[1]]) + eval(defs[m[2]])
		}
		if v, ok := defs[expr]; ok {
			return eval(v)
		}
		t.Fatalf("cannot evaluate %q", expr)
		return 0
	}
	for name, want := range map[string]int{
		"MAX_BUM_NEXTHOPS":       MaxBumNexthops,
		"BD_PEER_FLOOD_RESERVED": BdPeerFloodReserved,
		"BD_PEER_ES_BASE":        EsPeerIndexBase,
		"BD_PEER_ES_COUNT":       MaxEsPeersPerBd,
		"BD_PEER_UNICAST_BASE":   UnicastPeerIndexBase,
		"BD_PEER_UNICAST_COUNT":  MaxUnicastPeersPerBd,
		"BD_PEER_INDEX_INVALID":  bdPeerIndexInvalid,
	} {
		v, ok := defs[name]
		if !ok {
			t.Errorf("%s is not defined in xdp_prog.h", name)
			continue
		}
		if got := eval(v); got != want {
			t.Errorf("%s = %d in C, %d in Go", name, got, want)
		}
	}
}

// The ranges do not overlap, the reserved part of the flood range is what
// the flood slots in use leave, and the allocator's choice follows
// FloodExclude.
func TestBdPeerRanges(t *testing.T) {
	ranges := []BdPeerRange{FloodPeerRange, ReservedFloodPeerRange, EsPeerRange, UnicastPeerRange}
	for i, a := range ranges {
		for _, b := range ranges[i+1:] {
			if a.Base < b.End() && b.Base < a.End() {
				t.Errorf("%s overlaps %s", a, b)
			}
		}
	}
	if FloodPeerRange.End() != ReservedFloodPeerRange.Base || ReservedFloodPeerRange.End() != EsPeerRange.Base ||
		EsPeerRange.End() != UnicastPeerRange.Base {
		t.Errorf("ranges are not contiguous: %v", ranges)
	}
	if !LegacyEsPeerRange.Contains(8) || !LegacyEsPeerRange.Contains(39) || LegacyEsPeerRange.Contains(40) {
		t.Errorf("earlier ES range = %s, want [8, 40)", LegacyEsPeerRange)
	}
	if got := PeerRangeFor(&HeadendEntry{FloodExclude: 1}); got != UnicastPeerRange {
		t.Errorf("FloodExclude entry allocates from %s", got)
	}
	if got := PeerRangeFor(&HeadendEntry{}); got != FloodPeerRange {
		t.Errorf("flood entry allocates from %s", got)
	}
	for _, c := range []struct {
		index uint16
		entry HeadendEntry
		ok    bool
	}{
		{0, HeadendEntry{}, true},
		{MaxBumNexthops - 1, HeadendEntry{FloodExclude: 1}, true},
		{MaxBumNexthops, HeadendEntry{}, false},
		{BdPeerFloodReserved - 1, HeadendEntry{}, false},
		{EsPeerIndexBase, HeadendEntry{FloodExclude: 1}, true},
		{UnicastPeerIndexBase, HeadendEntry{FloodExclude: 1}, true},
		{UnicastPeerIndexBase, HeadendEntry{}, false},
		{UnicastPeerRange.End(), HeadendEntry{FloodExclude: 1}, false},
	} {
		if err := checkBdPeerIndex(c.index, &c.entry); (err == nil) != c.ok {
			t.Errorf("checkBdPeerIndex(%d, FloodExclude=%d) = %v, want ok=%v", c.index, c.entry.FloodExclude, err, c.ok)
		}
	}
}
