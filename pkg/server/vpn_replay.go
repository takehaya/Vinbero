package server

import (
	"errors"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
)

const (
	vpnReplayRetryMin = time.Second
	vpnReplayRetryMax = 30 * time.Second
)

// vpnReplayer re-applies the VPN loc-rib on its own goroutine. A replay reads
// the whole rib, so it must not run under the VrfBgpServer mutation mutex or
// inside the RPC that committed the binding: a CNI ADD has a short deadline
// and other pods' RPCs share that mutex.
//
// The binding is already committed when a replay is requested, and the routes
// it rescues are never re-delivered, so the RPC cannot usefully report a
// failure. A failed replay is logged and retried with backoff until it
// succeeds. Requests made while a replay runs are merged into the next one.
type vpnReplayer struct {
	replay func([]bgp.Family) error
	logger *zap.Logger
	// retryMin and retryMax bound the delay between failed attempts.
	retryMin, retryMax time.Duration

	mu      sync.Mutex
	dirty   map[bgp.Family]struct{}
	running bool
}

func newVPNReplayer(replay func([]bgp.Family) error, logger *zap.Logger) *vpnReplayer {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &vpnReplayer{
		replay:   replay,
		logger:   logger,
		retryMin: vpnReplayRetryMin,
		retryMax: vpnReplayRetryMax,
		dirty:    make(map[bgp.Family]struct{}),
	}
}

// request schedules a replay of families and returns without waiting for it.
func (r *vpnReplayer) request(families []bgp.Family) {
	if len(families) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, fam := range families {
		r.dirty[fam] = struct{}{}
	}
	if !r.running {
		r.running = true
		go r.run()
	}
}

func (r *vpnReplayer) run() {
	delay := r.retryMin
	for {
		families := r.take()
		if families == nil {
			return
		}
		start := time.Now()
		err := r.replay(families)
		switch {
		case err == nil:
			delay = r.retryMin
			r.logger.Info("replayed VPN loc-rib",
				zap.Any("families", families), zap.Duration("took", time.Since(start)))
		case errors.Is(err, bgp.ErrSessionNotStarted):
			// Routes received after the session starts see the binding,
			// so there is nothing to rescue.
			delay = r.retryMin
		default:
			r.logger.Warn("VPN loc-rib replay failed; retrying",
				zap.Any("families", families), zap.Duration("retry_in", delay), zap.Error(err))
			r.requeue(families)
			time.Sleep(delay)
			delay = min(delay*2, r.retryMax)
		}
	}
}

// take returns the pending families and clears them, or stops the worker and
// returns nil when there are none.
func (r *vpnReplayer) take() []bgp.Family {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.dirty) == 0 {
		r.running = false
		return nil
	}
	families := make([]bgp.Family, 0, len(r.dirty))
	for fam := range r.dirty {
		families = append(families, fam)
	}
	clear(r.dirty)
	return families
}

// requeue puts families back after a failed attempt; the worker is running.
func (r *vpnReplayer) requeue(families []bgp.Family) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, fam := range families {
		r.dirty[fam] = struct{}{}
	}
}
