package resolve

import (
	"reflect"
	"testing"

	"github.com/takehaya/vinbero/sdk/go/cplane"
)

func TestRangeResultsOrderAndOwnership(t *testing.T) {
	shared := []cplane.BGPPathKey{{Peer: "original"}}
	p := &Plan[string, string]{pairs: []Pair[string, string]{
		{Left: "first", Right: "right", Context: "tenant", Revision: 4, LeftPaths: shared, RightPaths: shared},
		{Left: "second", Right: "right", Context: "tenant", Revision: 4, LeftPaths: shared, RightPaths: shared},
	}}
	want := p.Results()
	var saved []Pair[string, string]
	p.Range(func(pair Pair[string, string]) {
		if !reflect.DeepEqual(pair, want[len(saved)]) {
			t.Fatalf("wrong order or aliased callback: %+v", pair)
		}
		saved = append(saved, pair)
		pair.LeftPaths[0].Peer = "caller-left"
		if pair.RightPaths[0].Peer != "original" {
			t.Fatal("left and right path lists alias")
		}
		pair.RightPaths[0].Peer = "caller-right"
	})
	if len(saved) != len(want) || !reflect.DeepEqual(p.Results(), want) {
		t.Fatal("range omitted results or mutated the plan")
	}
	saved[0].LeftPaths[0].Peer = "first-left"
	saved[0].RightPaths[0].Peer = "first-right"
	if saved[1].LeftPaths[0].Peer != "caller-left" || saved[1].RightPaths[0].Peer != "caller-right" {
		t.Fatal("retained callback values share path lists")
	}
	p.pairs[0].Revision++
	shared[0].Peer = "updated"
	if saved[0].Revision != 4 || saved[0].LeftPaths[0].Peer != "first-left" || saved[1].RightPaths[0].Peer != "caller-right" {
		t.Fatal("plan update changed a retained callback value")
	}
	p.clear()
	p.Range(func(Pair[string, string]) { t.Fatal("empty plan returned a stale result") })
}

func TestCopyResultsOwnershipAndReuse(t *testing.T) {
	p := &Plan[string, string]{pairs: []Pair[string, string]{
		{Left: "left", Right: "right", Context: "tenant", Revision: 4,
			LeftPaths:  []cplane.BGPPathKey{{Peer: "left-peer"}},
			RightPaths: []cplane.BGPPathKey{{Peer: "right-peer"}}},
	}}
	saved := p.Results()
	dst := p.CopyResults(nil)
	if !reflect.DeepEqual(dst, saved) {
		t.Fatalf("snapshot differs: %+v", dst)
	}
	outer, left, right := &dst[0], &dst[0].LeftPaths[0], &dst[0].RightPaths[0]
	dst[0].Left, dst[0].LeftPaths[0].Peer, dst[0].RightPaths[0].Peer = "changed", "changed", "changed"
	if !reflect.DeepEqual(p.Results(), saved) {
		t.Fatal("caller mutation changed the plan")
	}
	dst = p.CopyResults(dst)
	if !reflect.DeepEqual(dst, saved) || &dst[0] != outer || &dst[0].LeftPaths[0] != left || &dst[0].RightPaths[0] != right {
		t.Fatal("copy did not restore values and reuse all destination buffers")
	}
	if allocs := testing.AllocsPerRun(100, func() { dst = p.CopyResults(dst) }); allocs != 0 {
		t.Fatalf("steady-size copy allocated %g objects", allocs)
	}
	p.pairs[0].Revision++
	p.pairs[0].LeftPaths[0].Peer = "new-left"
	p.pairs[0].RightPaths[0].Peer = "new-right"
	if !reflect.DeepEqual(dst, saved) {
		t.Fatal("plan mutation changed a caller-owned snapshot before reuse")
	}
	dst = p.CopyResults(dst)
	if !reflect.DeepEqual(dst, p.Results()) || saved[0].Revision != 4 || saved[0].LeftPaths[0].Peer != "left-peer" {
		t.Fatal("copy was stale or a Results snapshot changed")
	}
}

func TestCopyResultsGrowthShrinkAndClear(t *testing.T) {
	pair := Pair[string, string]{Left: "a", Right: "b", Context: "tenant", Revision: 2,
		LeftPaths:  []cplane.BGPPathKey{{Peer: "l1"}, {Peer: "l2"}},
		RightPaths: []cplane.BGPPathKey{{Peer: "r1"}, {Peer: "r2"}}}
	p := &Plan[string, string]{pairs: []Pair[string, string]{pair}}
	dst := p.CopyResults(nil)
	// Grow the outer and nested buffers, preserving an independent saved copy.
	saved := p.Results()
	p.pairs = append(p.pairs, pair)
	p.pairs[0].RightPaths = append([]cplane.BGPPathKey(nil), pair.RightPaths...)
	p.pairs[0].RightPaths = append(p.pairs[0].RightPaths, cplane.BGPPathKey{Peer: "r3"})
	dst = p.CopyResults(dst)
	if !reflect.DeepEqual(dst, p.Results()) {
		t.Fatal("growth lost results")
	}
	old := dst
	left, right := dst[0].LeftPaths, dst[0].RightPaths
	p.pairs = p.pairs[:1]
	p.pairs[0].LeftPaths = p.pairs[0].LeftPaths[:1]
	p.pairs[0].RightPaths = nil
	dst = p.CopyResults(dst)
	if !reflect.DeepEqual(old[1], Pair[string, string]{}) || left[1] != (cplane.BGPPathKey{}) {
		t.Fatal("discarded pair or left path retained stale references")
	}
	for _, key := range right {
		if key != (cplane.BGPPathKey{}) {
			t.Fatal("discarded right path retained stale references")
		}
	}
	if len(dst) != 1 || len(dst[0].LeftPaths) != 1 || len(dst[0].RightPaths) != 0 || len(saved) != 1 || len(saved[0].LeftPaths) != 2 {
		t.Fatal("shrink or independent Results snapshot changed")
	}
	p.clear()
	dst = p.CopyResults(dst)
	if len(dst) != 0 || cap(dst) == 0 || !reflect.DeepEqual(old[0], Pair[string, string]{}) {
		t.Fatal("empty plan failed to clear destination while retaining its capacity")
	}
	if got := p.CopyResults(nil); got != nil {
		t.Fatal("empty copy unexpectedly allocated")
	}
	p.pairs = []Pair[string, string]{pair}
	dst = p.CopyResults(dst)
	if !reflect.DeepEqual(dst, p.Results()) {
		t.Fatal("regrowth after clearing lost results")
	}
}
