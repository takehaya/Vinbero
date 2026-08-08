package server

import (
	"testing"

	"github.com/takehaya/vinbero/pkg/bpf"
)

func entryWithSegments(sids ...string) *bpf.HeadendEntry {
	e := &bpf.HeadendEntry{NumSegments: uint8(len(sids))}
	segs, _, err := bpf.ParseSegments(sids)
	if err != nil {
		panic(err)
	}
	e.Segments = segs
	return e
}

// The segment array is fixed-size, so anything past NumSegments is zero and
// would otherwise be reported as a real :: hop.
func TestSegmentStringsStopsAtNumSegments(t *testing.T) {
	e := entryWithSegments("fd00:1::1", "fd00:2::2")
	got := segmentStrings(e)
	if len(got) != 2 {
		t.Fatalf("got %v, want two segments", got)
	}
	if got[0] != "fd00:1::1" || got[1] != "fd00:2::2" {
		t.Errorf("segments = %v", got)
	}

	// A NumSegments larger than the array must not read past it.
	e.NumSegments = 200
	if n := len(segmentStrings(e)); n > len(e.Segments) {
		t.Errorf("read %d segments from an array of %d", n, len(e.Segments))
	}
}

func TestBuildGroupLiveness(t *testing.T) {
	info := &bpf.EcmpGroupInfo{NumPaths: 2}
	info.Weight[0] = 1
	info.Weight[1] = 3
	paths := []*bpf.HeadendEntry{
		entryWithSegments("fd00:1::1"),
		entryWithSegments("fd00:2::2"),
	}

	t.Run("no liveness entry means every path is used", func(t *testing.T) {
		// The data plane treats a missing bitmap as fail-open, so reporting
		// paths as down here would contradict what is actually forwarding.
		g := buildGroup(7, info, paths, nil, bpf.OwnerRPC, 0, false)
		for _, m := range g.Members {
			if !m.Live {
				t.Errorf("member %d reported down with no liveness entry", m.Index)
			}
		}
		if g.LiveKnown {
			t.Error("LiveKnown must be false when the group has no entry")
		}
	})

	t.Run("bitmap selects per member", func(t *testing.T) {
		g := buildGroup(7, info, paths, nil, bpf.OwnerRPC, 0b10, true)
		if g.Members[0].Live {
			t.Error("member 0 should be down")
		}
		if !g.Members[1].Live {
			t.Error("member 1 should be up")
		}
	})

	t.Run("weights come from the group info", func(t *testing.T) {
		g := buildGroup(7, info, paths, nil, bpf.OwnerRPC, 0, false)
		if g.Members[0].Weight != 1 || g.Members[1].Weight != 3 {
			t.Errorf("weights = %d,%d want 1,3", g.Members[0].Weight, g.Members[1].Weight)
		}
	})

	t.Run("a missing path entry is reported, not hidden", func(t *testing.T) {
		// GetEcmpGroup yields a nil element for a slot the group info counts
		// but the path map has not caught up to. Dropping it would make the
		// member list silently disagree with num_paths.
		g := buildGroup(7, info, []*bpf.HeadendEntry{paths[0], nil}, nil, bpf.OwnerRPC, 0, false)
		if len(g.Members) != 2 {
			t.Fatalf("got %d members, want the hole reported", len(g.Members))
		}
		if len(g.Members[1].Segments) != 0 {
			t.Errorf("the hole should carry no segments, got %v", g.Members[1].Segments)
		}
	})
}
