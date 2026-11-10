package server

import (
	"errors"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bgp/apply"
)

const (
	vpnReplayRetryMin = time.Second
	vpnReplayRetryMax = 30 * time.Second
	// vpnReplayMaxRetries bounds one series of retries. The delay doubles
	// from vpnReplayRetryMin up to vpnReplayRetryMax, so six retries come
	// after 1, 2, 4, 8, 16 and 30 seconds: about a minute, which outlasts a
	// transient failure (a map briefly full, a write racing a restart)
	// without replaying the loc-rib for ever on one that will not go away
	// (a bridge domain at its flood-list limit, an entry another owner
	// holds).
	vpnReplayMaxRetries = 6
)

// vpnReplayer re-applies the loc-rib, or only the applier's tracked state,
// on its own goroutine. A replay reads the whole rib, so it must not run
// under the VrfBgpServer mutation mutex or inside the RPC that committed the
// binding: a CNI ADD has a short deadline and other pods' RPCs share that
// mutex.
//
// The binding is already committed when a replay is requested, and the routes
// it rescues are never re-delivered, so the RPC cannot usefully report a
// failure. What a failure needs decides the retry (see
// apply.Applier.ReplayAndReconcile): a failed write of tracked state is
// retried with the tracked pass alone, a route a replay could not write and
// does not track by another replay of its family, and a replay that could
// not read the rib by the whole replay. Retries back off and are bounded: a
// series that still fails after vpnReplayMaxRetries retries is logged once
// and dropped. A new request runs at once, ends any backoff wait, and starts
// a fresh series. Requests made while a pass runs are merged into the next
// one.
type vpnReplayer struct {
	replay func([]bgp.Family) error // runs the tracked pass after the replay
	// tracked runs the tracked pass alone; nil turns tracked-only retries
	// into nothing to do.
	tracked func() error
	logger  *zap.Logger
	// retryMin and retryMax bound the delay between failed attempts, and
	// maxRetries the attempts of one series.
	retryMin, retryMax time.Duration
	maxRetries         int

	mu sync.Mutex
	// dirty and dirtyTracked are the work to do now; retry and retryTracked
	// the work a failed attempt left, run after the backoff delay.
	dirty        map[bgp.Family]struct{}
	dirtyTracked bool
	retry        map[bgp.Family]struct{}
	retryTracked bool
	// attempts counts the failed attempts of the current series, and series
	// changes with every request, so the worker restarts its delay.
	attempts int
	series   uint64
	wake     chan struct{}
	running  bool
}

func newVPNReplayer(replay func([]bgp.Family) error, tracked func() error, logger *zap.Logger) *vpnReplayer {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &vpnReplayer{
		replay:     replay,
		tracked:    tracked,
		logger:     logger,
		retryMin:   vpnReplayRetryMin,
		retryMax:   vpnReplayRetryMax,
		maxRetries: vpnReplayMaxRetries,
		dirty:      make(map[bgp.Family]struct{}),
		retry:      make(map[bgp.Family]struct{}),
		wake:       make(chan struct{}, 1),
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
	r.startLocked()
}

// requestTracked schedules the tracked pass alone and returns without
// waiting for it. The applier calls it when a write of tracked state failed
// outside that pass; it must not block.
func (r *vpnReplayer) requestTracked() {
	if r.tracked == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dirtyTracked = true
	r.startLocked()
}

// startLocked starts a fresh series: what was waiting for a retry runs now
// with the new request, the delay and the attempt count restart, and a
// worker waiting out a backoff is woken.
func (r *vpnReplayer) startLocked() {
	for fam := range r.retry {
		r.dirty[fam] = struct{}{}
	}
	clear(r.retry)
	r.dirtyTracked = r.dirtyTracked || r.retryTracked
	r.retryTracked = false
	r.attempts = 0
	r.series++
	if !r.running {
		r.running = true
		go r.run()
		return
	}
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (r *vpnReplayer) run() {
	delay := r.retryMin
	var series uint64
	for {
		r.mu.Lock()
		if r.series != series {
			series, delay = r.series, r.retryMin
		}
		if len(r.dirty) == 0 && !r.dirtyTracked {
			if len(r.retry) == 0 && !r.retryTracked {
				r.running = false
				r.mu.Unlock()
				return
			}
			r.mu.Unlock()
			r.backoff(delay)
			delay = min(delay*2, r.retryMax)
			continue
		}
		families := make([]bgp.Family, 0, len(r.dirty))
		for fam := range r.dirty {
			families = append(families, fam)
		}
		clear(r.dirty)
		tracked := r.dirtyTracked
		r.dirtyTracked = false
		// A wake for work taken here is spent: it must not cut short the
		// backoff after this attempt.
		select {
		case <-r.wake:
		default:
		}
		r.mu.Unlock()

		start := time.Now()
		var err error
		switch {
		case len(families) > 0:
			// The replay runs the tracked pass after it.
			err = r.replay(families)
		case tracked:
			err = r.tracked()
		}
		again, againTracked, failing := classifyReplayError(err, families)
		if len(again) == 0 && !againTracked {
			if len(families) > 0 {
				r.logger.Info("replayed loc-rib",
					zap.Any("families", families), zap.Duration("took", time.Since(start)))
			}
			continue
		}
		r.mu.Lock()
		if r.series != series {
			// A request arrived during the attempt and started a fresh
			// series, which runs now; the failed work goes with it.
			for _, fam := range again {
				r.dirty[fam] = struct{}{}
			}
			r.dirtyTracked = r.dirtyTracked || againTracked
			r.mu.Unlock()
			continue
		}
		r.attempts++
		if r.attempts > r.maxRetries {
			r.attempts = 0
			r.mu.Unlock()
			r.logger.Error("giving up retrying failed writes until the next replay request",
				zap.Int("retries", r.maxRetries), zap.Int("still_failing", failing),
				zap.Any("families", again), zap.Bool("tracked", againTracked), zap.Error(err))
			continue
		}
		for _, fam := range again {
			r.retry[fam] = struct{}{}
		}
		r.retryTracked = r.retryTracked || againTracked
		r.mu.Unlock()
		r.logger.Warn("writes failed; retrying",
			zap.Any("families", again), zap.Bool("tracked", againTracked),
			zap.Int("still_failing", failing), zap.Duration("retry_in", delay), zap.Error(err))
	}
}

// backoff waits delay, or less when a request wakes it, and then makes the
// waiting retries due.
func (r *vpnReplayer) backoff(delay time.Duration) {
	t := time.NewTimer(delay)
	select {
	case <-t.C:
	case <-r.wake:
		t.Stop()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for fam := range r.retry {
		r.dirty[fam] = struct{}{}
	}
	clear(r.retry)
	r.dirtyTracked = r.dirtyTracked || r.retryTracked
	r.retryTracked = false
}

// classifyReplayError says what a failed pass needs: the families to replay
// again, whether the tracked pass alone must run again, and how many writes
// are still failing (0 when unknown). families is what the pass replayed.
// Before the session starts every route still arrives after the binding, so
// bgp.ErrSessionNotStarted needs nothing.
func classifyReplayError(err error, families []bgp.Family) (again []bgp.Family, tracked bool, failing int) {
	seen := map[bgp.Family]bool{}
	add := func(fams ...bgp.Family) {
		for _, f := range fams {
			if !seen[f] {
				seen[f] = true
				again = append(again, f)
			}
		}
	}
	var visit func(error)
	visit = func(e error) {
		if e == nil {
			return
		}
		if j, ok := e.(interface{ Unwrap() []error }); ok {
			for _, c := range j.Unwrap() {
				visit(c)
			}
			return
		}
		var tw *apply.TrackedWriteError
		var uw *apply.UnwrittenRoutesError
		switch {
		case errors.Is(e, bgp.ErrSessionNotStarted):
		case errors.As(e, &tw):
			tracked = true
			failing += tw.Failed()
		case errors.As(e, &uw):
			add(uw.Family)
			failing += uw.Routes
		case len(families) == 0:
			// The tracked pass alone failed in a way it did not count.
			tracked = true
		default:
			// The replay itself failed (the rib could not be read).
			add(families...)
		}
	}
	visit(err)
	return again, tracked, failing
}
