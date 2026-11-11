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
		"MAX_BUM_NEXTHOPS":      MaxBumNexthops,
		"BD_PEER_ES_BASE":       EsPeerIndexBase,
		"BD_PEER_ES_COUNT":      MaxEsPeersPerBd,
		"BD_PEER_UNICAST_BASE":  UnicastPeerIndexBase,
		"BD_PEER_UNICAST_COUNT": MaxUnicastPeersPerBd,
		"BD_PEER_INDEX_INVALID": bdPeerIndexInvalid,
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

// The ranges do not overlap and leave no gap, the flood range is the 32
// slots, and the allocator's choice follows FloodExclude.
func TestBdPeerRanges(t *testing.T) {
	ranges := []BdPeerRange{FloodPeerRange, EsPeerRange, UnicastPeerRange}
	for i, a := range ranges {
		for _, b := range ranges[i+1:] {
			if a.Base < b.End() && b.Base < a.End() {
				t.Errorf("%s overlaps %s", a, b)
			}
		}
	}
	if FloodPeerRange.Base != 0 || FloodPeerRange.End() != EsPeerRange.Base || EsPeerRange.End() != UnicastPeerRange.Base {
		t.Errorf("ranges are not contiguous: %v", ranges)
	}
	if MaxBumNexthops != 32 || FloodPeerRange.Count != 32 || EsPeerRange.Base != 32 || UnicastPeerRange.Base != 64 {
		t.Errorf("layout = %v, want flood [0, 32), ES [32, 64), unicast [64, 128)", ranges)
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
		{7, HeadendEntry{}, true},
		{8, HeadendEntry{}, true},
		{MaxBumNexthops - 1, HeadendEntry{}, true},
		{MaxBumNexthops - 1, HeadendEntry{FloodExclude: 1}, true},
		{EsPeerIndexBase, HeadendEntry{FloodExclude: 1}, true},
		{UnicastPeerIndexBase, HeadendEntry{FloodExclude: 1}, true},
		{UnicastPeerIndexBase, HeadendEntry{}, false},
		{UnicastPeerRange.End(), HeadendEntry{FloodExclude: 1}, false},
	} {
		if err := checkBdPeerIndex(c.index, &c.entry); (err == nil) != c.ok {
			t.Errorf("checkBdPeerIndex(%d, FloodExclude=%d) = %v, want ok=%v", c.index, c.entry.FloodExclude, err, c.ok)
		}
	}
	for _, c := range []struct {
		index uint16
		group uint32
		want  bool
	}{
		{0, 0, false}, {8, 0, false}, {0, 7, true}, {8, 7, true}, {31, 7, true}, {32, 7, false}, {39, 7, false},
	} {
		if got := IsFloodRangeEsPeer(c.index, &HeadendEntry{GroupId: c.group}); got != c.want {
			t.Errorf("IsFloodRangeEsPeer(%d, group %d) = %v, want %v", c.index, c.group, got, c.want)
		}
	}
	if IsFloodRangeEsPeer(8, nil) {
		t.Error("IsFloodRangeEsPeer(8, nil) = true")
	}
}

// Slot keys carry the build number and the slot, and stay apart from the
// local ACs' ifindex keys; the C and Go definitions agree.
func TestBumSlotKey(t *testing.T) {
	for _, c := range []struct {
		gen  uint32
		slot uint16
		want uint32
	}{
		{0, 0, 0x80000000}, {1, 0, 0x80000100}, {1, 31, 0x8000011f}, {bumSlotGenMask, 31, 0xffffff1f},
		{bumSlotGenMask + 1, 7, 0x80000007}, // the build number wraps
	} {
		got := BumSlotKey(c.gen, c.slot)
		if got != c.want {
			t.Errorf("BumSlotKey(%#x, %d) = %#x, want %#x", c.gen, c.slot, got, c.want)
		}
		if slot, ok := BumSlotIndex(got); !ok || slot != c.slot {
			t.Errorf("BumSlotIndex(%#x) = %d, %v", got, slot, ok)
		}
	}
	if _, ok := BumSlotIndex(0x7fffffff); ok {
		t.Error("an ifindex key reads as a slot key")
	}
	src, err := os.ReadFile("../../src/l2vpn/bum_xdp.h")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"BUM_SLOT_KEY_BASE":    "0x80000000u",
		"BUM_SLOT_GEN_MASK":    "0x7fffffu",
		"BUM_PLAN_MAX_UPLINKS": strconv.Itoa(BumPlanMaxUplinks),
	} {
		m := regexp.MustCompile(`(?m)^#define ` + name + ` (\S+)`).FindSubmatch(src)
		if m == nil || string(m[1]) != want {
			t.Errorf("%s in bum_xdp.h = %q, want %s", name, m, want)
		}
	}
	if !regexp.MustCompile(`(?m)^#define BUM_SLOT_KEY\(gen, i\) \(BUM_SLOT_KEY_BASE \| \(\(\(gen\) & BUM_SLOT_GEN_MASK\) << 8\) \| \(i\)\)$`).Match(src) {
		t.Error("BUM_SLOT_KEY in bum_xdp.h is not BASE | (gen & GEN_MASK) << 8 | slot")
	}
}

// A BD devmap holding n entries gets the next power of two (its bucket
// count, which a broadcast walks), at least bumDevmapMinEntries.
func TestBumDevmapSize(t *testing.T) {
	for n, want := range map[int]uint32{0: 4, 1: 4, 4: 4, 5: 8, 9: 16, 33: 64, 34: 64, 64: 64, 65: 128, 256: 256} {
		if got := bumDevmapSize(n); got != want {
			t.Errorf("bumDevmapSize(%d) = %d, want %d", n, got, want)
		}
	}
}
