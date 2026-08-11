package server

import (
	"context"
	"slices"

	"connectrpc.com/connect"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/prober"
)

// ProberStatusSource is the surface ProberServer needs from the prober: a
// snapshot of every registered path. Nil means no prober is configured.
type ProberStatusSource interface {
	Status() []prober.PathStatus
}

type ProberServer struct {
	source     ProberStatusSource
	intervalMs uint32
	multiplier uint32
}

// NewProberServer wires the status RPC. source is nil when the prober is
// disabled; the RPC then reports enabled=false.
func NewProberServer(source ProberStatusSource, intervalMs, multiplier uint32) *ProberServer {
	return &ProberServer{source: source, intervalMs: intervalMs, multiplier: multiplier}
}

func (s *ProberServer) ProberStatus(
	ctx context.Context,
	req *connect.Request[v1.ProberStatusRequest],
) (*connect.Response[v1.ProberStatusResponse], error) {
	resp := &v1.ProberStatusResponse{}
	if s.source == nil {
		return connect.NewResponse(resp), nil
	}
	resp.Enabled = true
	resp.IntervalMs = s.intervalMs
	resp.Multiplier = s.multiplier

	paths := s.source.Status()
	slices.SortFunc(paths, func(a, b prober.PathStatus) int {
		if a.GroupID != b.GroupID {
			if a.GroupID < b.GroupID {
				return -1
			}
			return 1
		}
		return int(a.PathIndex) - int(b.PathIndex)
	})
	for _, p := range paths {
		st := &v1.ProbePathStatus{
			GroupId:     p.GroupID,
			PathIndex:   uint32(p.PathIndex),
			Probeable:   p.Probeable,
			Up:          p.Up,
			MissStreak:  uint32(p.MissStreak),
			Transitions: p.Transitions,
			RttUsec:     p.RTT.Microseconds(),
		}
		if p.Dst.IsValid() {
			st.Dst = p.Dst.String()
		}
		if !p.LastReply.IsZero() {
			st.LastReplyUnixNano = p.LastReply.UnixNano()
		}
		resp.Paths = append(resp.Paths, st)
	}
	return connect.NewResponse(resp), nil
}
