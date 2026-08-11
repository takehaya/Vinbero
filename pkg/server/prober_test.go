package server

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"connectrpc.com/connect"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/prober"
)

type fakeStatusSource []prober.PathStatus

func (f fakeStatusSource) Status() []prober.PathStatus { return f }

func TestProberServer_DisabledReportsEmpty(t *testing.T) {
	s := NewProberServer(nil, 0, 0)
	resp, err := s.ProberStatus(context.Background(), connect.NewRequest(&v1.ProberStatusRequest{}))
	if err != nil {
		t.Fatalf("ProberStatus: %v", err)
	}
	if resp.Msg.Enabled || len(resp.Msg.Paths) != 0 {
		t.Fatalf("disabled prober reported %+v", resp.Msg)
	}
}

func TestProberServer_StatusSortedAndRendered(t *testing.T) {
	src := fakeStatusSource{
		{GroupID: 2, PathIndex: 1, Dst: netip.MustParseAddr("fd00::3"), Probeable: true, Up: false, MissStreak: 4},
		{GroupID: 1, PathIndex: 0, Probeable: false, Up: true},
		{GroupID: 2, PathIndex: 0, Dst: netip.MustParseAddr("fd00::2"), Probeable: true, Up: true,
			RTT: 250 * time.Microsecond, LastReply: time.Unix(100, 0)},
	}
	s := NewProberServer(src, 100, 3)
	resp, err := s.ProberStatus(context.Background(), connect.NewRequest(&v1.ProberStatusRequest{}))
	if err != nil {
		t.Fatalf("ProberStatus: %v", err)
	}
	m := resp.Msg
	if !m.Enabled || m.IntervalMs != 100 || m.Multiplier != 3 {
		t.Fatalf("header = %+v", m)
	}
	if len(m.Paths) != 3 {
		t.Fatalf("paths = %d", len(m.Paths))
	}
	// Sorted by {group, path}.
	if m.Paths[0].GroupId != 1 || m.Paths[1].PathIndex != 0 || m.Paths[2].PathIndex != 1 {
		t.Fatalf("order wrong: %+v", m.Paths)
	}
	if m.Paths[0].Dst != "" {
		t.Errorf("unprobeable path rendered dst %q", m.Paths[0].Dst)
	}
	if m.Paths[1].RttUsec != 250 || m.Paths[1].LastReplyUnixNano != time.Unix(100, 0).UnixNano() {
		t.Errorf("rtt/last reply = %+v", m.Paths[1])
	}
	if m.Paths[2].Up || m.Paths[2].MissStreak != 4 {
		t.Errorf("down path = %+v", m.Paths[2])
	}
}
