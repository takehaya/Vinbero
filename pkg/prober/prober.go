// Package prober implements SRv6-aware liveness probing for headend ECMP
// path groups. Each registered path is probed with an ICMPv6 echo request
// that traverses the path's transport segments (an SRH built from the
// member's segment list) and terminates at the advertising PE's routable
// address, so the probe validates the actual SRv6 forwarding path rather
// than shortest-path reachability. The remote side needs nothing beyond the
// kernel's ICMPv6 echo handling.
//
// A path state flip writes the group's liveness bitmap into ecmp_live_map
// (one atomic 8-byte swap); the data plane masks its weighted selection
// with it. The prober is the fast mask, BGP withdrawal the slow truth: a
// path with every probe lost is skipped within roughly multiplier*interval,
// long before the withdraw arrives, and comes back with hysteresis (the
// same number of consecutive replies).
package prober

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Target names one probeable path of a group. Segments are the transport
// hops the probe must traverse (usually the member's segment list minus the
// terminal service SID); Dst is the final destination the echo must reach
// -- the advertising PE's routable address. An invalid Dst marks the path
// unprobeable: it stays permanently up rather than being failed by a probe
// that could never succeed.
type Target struct {
	PathIndex uint8
	Segments  []netip.Addr
	Dst       netip.Addr
}

// Registry is what the BGP applier talks to. Register replaces the target
// set of a group (the applier calls it after every group write, so
// membership can only drift as far as one reconcile); Unregister drops the
// group and restores the data plane's fail-open default.
type Registry interface {
	Register(groupID uint32, targets []Target)
	Unregister(groupID uint32)
}

// Noop is the Registry used when no prober is configured.
type Noop struct{}

func (Noop) Register(uint32, []Target) {}
func (Noop) Unregister(uint32)        {}

// liveWriter is the pkg/bpf surface the prober writes.
type liveWriter interface {
	SetEcmpLive(groupID uint32, bitmap uint64) error
	DeleteEcmpLive(groupID uint32) error
}

// wire abstracts the probe transport so the state machine is testable
// without raw sockets.
type wire interface {
	// send emits one echo request for the target, stamped with the token
	// (ICMPv6 identifier) and sequence number.
	send(t Target, token uint16, seq uint16) error
	// recv blocks for the next echo reply; ok is false once closed.
	recv() (token, seq uint16, ok bool)
	close()
}

// Config tunes the prober.
type Config struct {
	// Interval between probes of one path. Also the reply window: a reply
	// must land before the path's next probe to count.
	Interval time.Duration
	// Multiplier is the hysteresis in both directions: this many
	// consecutive lost probes take a path down, this many consecutive
	// replies bring it back.
	Multiplier int
}

type pathState struct {
	target Target
	token  uint16
	seq    uint16
	// probeable is false when the target carries no valid destination;
	// such a path is never probed and never taken down.
	probeable bool

	up          bool
	missStreak  int
	okStreak    int
	transitions uint64

	sentAt    time.Time
	replySeen bool
	lastReply time.Time
	rtt       time.Duration
}

type groupState struct {
	paths []*pathState
}

// Prober drives the probe schedule and owns the liveness bitmaps.
type Prober struct {
	live   liveWriter
	wire   wire
	cfg    Config
	logger *zap.Logger

	mu     sync.Mutex
	groups map[uint32]*groupState
	tokens map[uint16]*pathState // ICMPv6 identifier -> path
	nextTk uint16

	stopCh chan struct{}
	doneCh chan struct{}
}

// New builds a Prober probing from src. It opens the raw sockets
// immediately (they need CAP_NET_RAW, held at daemon startup) but probes
// nothing until Start.
func New(live liveWriter, src netip.Addr, cfg Config, logger *zap.Logger) (*Prober, error) {
	if cfg.Interval <= 0 {
		cfg.Interval = 100 * time.Millisecond
	}
	if cfg.Multiplier <= 0 {
		cfg.Multiplier = 3
	}
	w, err := newRawWire(src)
	if err != nil {
		return nil, fmt.Errorf("open prober sockets: %w", err)
	}
	p := newWithWire(live, w, cfg, logger)
	return p, nil
}

// newWithWire is the injectable constructor the tests use.
func newWithWire(live liveWriter, w wire, cfg Config, logger *zap.Logger) *Prober {
	return &Prober{
		live:   live,
		wire:   w,
		cfg:    cfg,
		logger: logger.Named("prober"),
		groups: make(map[uint32]*groupState),
		tokens: make(map[uint16]*pathState),
	}
}

// Register replaces the group's target set. The bitmap is written
// immediately with every path up: from this moment the data plane is under
// prober control, and the first lost probes -- not the registration --
// decide what goes down. Safe to call from the applier's route goroutines.
func (p *Prober) Register(groupID uint32, targets []Target) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if old, ok := p.groups[groupID]; ok {
		p.releaseLocked(old)
	}
	gs := &groupState{}
	for _, t := range targets {
		ps := &pathState{
			target:    t,
			up:        true,
			probeable: t.Dst.Is6() && !t.Dst.Is4In6() && !t.Dst.IsUnspecified(),
		}
		if ps.probeable {
			tk, ok := p.allocTokenLocked(ps)
			if !ok {
				p.logger.Warn("prober token space exhausted; path not probed",
					zap.Uint32("group_id", groupID), zap.Uint8("path", t.PathIndex))
				ps.probeable = false
			} else {
				ps.token = tk
			}
		}
		gs.paths = append(gs.paths, ps)
	}
	p.groups[groupID] = gs
	if err := p.live.SetEcmpLive(groupID, bitmapOf(gs)); err != nil {
		p.logger.Error("write initial liveness bitmap",
			zap.Uint32("group_id", groupID), zap.Error(err))
	}
}

// Unregister drops the group and removes its bitmap, restoring the data
// plane's no-prober fail-open default.
func (p *Prober) Unregister(groupID uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	gs, ok := p.groups[groupID]
	if !ok {
		return
	}
	p.releaseLocked(gs)
	delete(p.groups, groupID)
	if err := p.live.DeleteEcmpLive(groupID); err != nil {
		p.logger.Error("delete liveness bitmap",
			zap.Uint32("group_id", groupID), zap.Error(err))
	}
}

func (p *Prober) releaseLocked(gs *groupState) {
	for _, ps := range gs.paths {
		if ps.probeable {
			delete(p.tokens, ps.token)
		}
	}
}

// allocTokenLocked hands out a free ICMPv6 identifier. The space is 16 bit
// against a practical population of at most a few thousand paths, so a
// linear probe from a rolling cursor terminates quickly.
func (p *Prober) allocTokenLocked(ps *pathState) (uint16, bool) {
	for range 65536 {
		p.nextTk++
		if _, taken := p.tokens[p.nextTk]; !taken {
			p.tokens[p.nextTk] = ps
			return p.nextTk, true
		}
	}
	return 0, false
}

// Start launches the probe scheduler and the reply reader.
func (p *Prober) Start() {
	p.stopCh = make(chan struct{})
	p.doneCh = make(chan struct{})
	go p.readLoop()
	go func() {
		defer close(p.doneCh)
		ticker := time.NewTicker(p.cfg.Interval)
		defer ticker.Stop()
		for {
			select {
			case <-p.stopCh:
				return
			case now := <-ticker.C:
				p.tick(now)
			}
		}
	}()
}

// Stop halts probing and closes the sockets. Registered bitmaps are left
// in place: on shutdown the daemon's map cleanup (or the next run's sweep)
// owns them, and yanking them here would flip the data plane to fail-open
// mid-flight for no reason.
func (p *Prober) Stop() {
	if p.stopCh != nil {
		close(p.stopCh)
		<-p.doneCh
	}
	p.wire.close()
}

// tick runs one probe round: for every probeable path, first judge the
// previous round (reply seen or not), then emit the next probe. Judging at
// send time gives every probe exactly one interval to be answered.
func (p *Prober) tick(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for groupID, gs := range p.groups {
		changed := false
		for _, ps := range gs.paths {
			if !ps.probeable {
				continue
			}
			if !ps.sentAt.IsZero() {
				if ps.judgeLocked(p.cfg.Multiplier) {
					changed = true
					p.logger.Info("probe path state change",
						zap.Uint32("group_id", groupID),
						zap.Uint8("path", ps.target.PathIndex),
						zap.Bool("up", ps.up),
						zap.String("dst", ps.target.Dst.String()))
				}
			}
			ps.seq++
			ps.sentAt = now
			ps.replySeen = false
			if err := p.wire.send(ps.target, ps.token, ps.seq); err != nil {
				// A send failure is indistinguishable from a lost probe for
				// the state machine; just log it.
				p.logger.Debug("probe send", zap.Error(err))
			}
		}
		if changed {
			if err := p.live.SetEcmpLive(groupID, bitmapOf(gs)); err != nil {
				p.logger.Error("write liveness bitmap",
					zap.Uint32("group_id", groupID), zap.Error(err))
			}
		}
	}
}

// judgeLocked folds the previous round's outcome into the streaks and
// reports whether the up/down state flipped.
func (ps *pathState) judgeLocked(multiplier int) bool {
	if ps.replySeen {
		ps.missStreak = 0
		ps.okStreak++
		if !ps.up && ps.okStreak >= multiplier {
			ps.up = true
			ps.transitions++
			return true
		}
		return false
	}
	ps.okStreak = 0
	ps.missStreak++
	if ps.up && ps.missStreak >= multiplier {
		ps.up = false
		ps.transitions++
		return true
	}
	return false
}

// handleReply matches one echo reply to its path. Only the current
// sequence counts: a straggler from an earlier round says nothing about
// the round being judged.
func (p *Prober) handleReply(token, seq uint16, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ps, ok := p.tokens[token]
	if !ok || seq != ps.seq {
		return
	}
	ps.replySeen = true
	ps.lastReply = now
	ps.rtt = now.Sub(ps.sentAt)
}

// bitmapOf renders the group's up-bits, indexed by the data plane's path
// index.
func bitmapOf(gs *groupState) uint64 {
	var bm uint64
	for _, ps := range gs.paths {
		if ps.up {
			bm |= 1 << ps.target.PathIndex
		}
	}
	return bm
}

// PathStatus is one path's snapshot for the ProberService.
type PathStatus struct {
	GroupID     uint32
	PathIndex   uint8
	Dst         netip.Addr
	Probeable   bool
	Up          bool
	MissStreak  int
	Transitions uint64
	RTT         time.Duration
	LastReply   time.Time
}

// Status snapshots every registered path, ordered by {group, path}.
func (p *Prober) Status() []PathStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []PathStatus
	for groupID, gs := range p.groups {
		for _, ps := range gs.paths {
			out = append(out, PathStatus{
				GroupID:     groupID,
				PathIndex:   ps.target.PathIndex,
				Dst:         ps.target.Dst,
				Probeable:   ps.probeable,
				Up:          ps.up,
				MissStreak:  ps.missStreak,
				Transitions: ps.transitions,
				RTT:         ps.rtt,
				LastReply:   ps.lastReply,
			})
		}
	}
	return out
}

// readLoop feeds echo replies from the wire into the state machine until
// the wire is closed.
func (p *Prober) readLoop() {
	for {
		token, seq, ok := p.wire.recv()
		if !ok {
			return
		}
		p.handleReply(token, seq, time.Now())
	}
}
