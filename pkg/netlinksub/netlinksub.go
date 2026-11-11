// Package netlinksub holds what every netlink subscription of the daemon
// does the same way: how it learns why a subscription ended, how long it
// waits before subscribing again, and what it logs.
//
// A subscription of github.com/vishvananda/netlink ends by closing its
// channel. Its ErrorCallback also reports errors that do not end it: the
// library skips a message that a userspace process sent to the group (the
// sender's port id is not 0) and keeps reading. State tells the two apart
// by the channel closing, so a skipped message is logged at debug level and
// only an ended subscription is a warning.
//
// None of the daemon's subscriptions use the library's ListExisting. It
// sends the dump request from the subscribed socket with the socket's groups
// as the destination, and the kernel delivers a request a privileged sender
// addresses to a group to every other socket bound to that group: each
// subscriber in the namespace, ours and other programs', receives our
// request. The existing state is listed with an ordinary request instead,
// after subscribing.
package netlinksub

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

// Delays between subscribe attempts: the first attempt waits MinDelay, each
// failure doubles the wait up to MaxDelay. Tests shorten them.
var (
	MinDelay = time.Second
	MaxDelay = 30 * time.Second
)

// State follows one subscription for the loop that owns it and logs each of
// its state changes once: ended, failed to subscribe again (again only when
// the error changes), restored.
type State struct {
	name   string
	logger *zap.Logger

	mu      sync.Mutex
	lastErr error // last ErrorCallback error since the last subscribe
	down    bool
	failure string // the failure logged last while down
	delay   time.Duration
}

// New returns the State of the subscription called name ("neighbour",
// "link", ...), which the log lines carry.
func New(logger *zap.Logger, name string) *State {
	return &State{name: name, logger: logger}
}

// OnError is the subscription's ErrorCallback. The error is kept for the
// warning if the subscription then ends, and logged at debug level: by
// itself it may only be a skipped message.
func (s *State) OnError(err error) {
	s.mu.Lock()
	s.lastErr = err
	s.mu.Unlock()
	s.logger.Debug("netlink subscription: error", zap.String("subscription", s.name), zap.Error(err))
}

// Ended records that the subscription's channel closed while its owner
// still wanted it, logs it with the error that ended it, and returns how
// long to wait before subscribing again.
func (s *State) Ended() time.Duration {
	s.mu.Lock()
	err := s.lastErr
	s.lastErr = nil
	s.down = true
	s.failure = ""
	s.delay = MinDelay
	d := s.delay
	s.mu.Unlock()
	s.logger.Warn("netlink subscription ended; subscribing again; events until then are recovered by a full resync",
		zap.String("subscription", s.name), zap.Error(err))
	return d
}

// Failed records an attempt to subscribe (again) that failed and returns
// how long to wait before the next one. The failure is logged when it
// differs from the previous one.
func (s *State) Failed(err error) time.Duration {
	s.mu.Lock()
	text := ""
	if err != nil {
		text = err.Error()
	}
	logIt := text != s.failure
	s.failure = text
	s.down = true
	s.delay = min(2*max(s.delay, MinDelay), MaxDelay)
	d := s.delay
	s.mu.Unlock()
	if logIt {
		s.logger.Warn("netlink subscription: cannot subscribe; retrying",
			zap.String("subscription", s.name), zap.Duration("retry_in", d), zap.Error(err))
	}
	return d
}

// Restored records a successful subscribe, logged when one had ended.
func (s *State) Restored() {
	s.mu.Lock()
	was := s.down
	s.down = false
	s.failure = ""
	s.lastErr = nil
	s.mu.Unlock()
	if was {
		s.logger.Info("netlink subscription restored; resyncing", zap.String("subscription", s.name))
	}
}

// Wait waits d and reports true, or false when stop is closed first.
func Wait(stop <-chan struct{}, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-stop:
		return false
	case <-t.C:
		return true
	}
}

// Again is the loop of an owner that has nothing else to do while its
// subscription is down: it records the end, then calls subscribe after each
// wait until it succeeds (true) or stop is closed (false).
func (s *State) Again(stop <-chan struct{}, subscribe func() error) bool {
	d := s.Ended()
	for {
		if !Wait(stop, d) {
			return false
		}
		if err := subscribe(); err != nil {
			d = s.Failed(err)
			continue
		}
		s.Restored()
		return true
	}
}

// Listing follows a listing of the existing state that a (re)subscribe is
// followed by: one that fails, or returns only part of the state (a dump the
// kernel interrupted), is tried again after the same waits as a subscribe,
// and its failure is logged when it changes.
type Listing struct {
	name   string
	logger *zap.Logger

	failure string
	delay   time.Duration
}

// NewListing returns the Listing called name ("FDB", ...), which the log
// lines carry.
func NewListing(logger *zap.Logger, name string) *Listing {
	return &Listing{name: name, logger: logger}
}

// Result records the outcome of a listing and returns the channel that
// fires for the next attempt, or nil when it succeeded. It is called from
// the owner's loop only.
func (l *Listing) Result(err error) <-chan time.Time {
	if err == nil {
		if l.failure != "" {
			l.logger.Info("netlink listing complete after a retry", zap.String("listing", l.name))
		}
		l.failure, l.delay = "", 0
		return nil
	}
	if l.delay == 0 {
		l.delay = MinDelay
	} else {
		l.delay = min(2*l.delay, MaxDelay)
	}
	if text := err.Error(); text != l.failure {
		l.failure = text
		l.logger.Warn("netlink listing incomplete; retrying",
			zap.String("listing", l.name), zap.Duration("retry_in", l.delay), zap.Error(err))
	}
	return time.After(l.delay)
}
