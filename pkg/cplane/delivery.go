package cplane

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

// deliveryQueueDepth is how many event batches may wait for one plugin.
//
// It is small on purpose. A plugin that cannot keep up is not helped by a
// deep queue: it just falls further behind while holding stale routes.
// Dropping and recording is the honest failure, and a level-triggered
// consumer recovers on the next snapshot rather than from the backlog.
const deliveryQueueDepth = 256

// retryInterval is how often a worker repeats the work owed to its plugin
// when no event is arriving to carry it.
//
// Slow on purpose: it does nothing at all in the ordinary case, and what
// it repairs -- a declaration whose locator did not exist yet -- is
// something an operator has just created by hand. Seconds of delay there
// are not worth a busy timer on every plugin.
const retryInterval = 15 * time.Second

// maxDrainRounds bounds how long releasing a snapshot's hold will chase
// events that keep arriving before it forces the hold shut.
const maxDrainRounds = 8

// worker owns all delivery to one plugin.
//
// It exists because guest calls must not happen on the BGP watch
// goroutine. That goroutine's contract is that it never blocks, and a call
// into a plugin can take up to the call budget -- two seconds by default.
// Running one there would stall every other consumer of the demux, the
// built-in applier included, and turn one slow plugin into a daemon-wide
// convergence problem. So dispatch hands the batch over and returns.
//
// One worker per plugin also serializes delivery, which the guest requires
// anyway: a WebAssembly instance has a single linear memory and a single
// allocator behind it.
type worker struct {
	name     string
	logger   *zap.Logger
	queue    chan *v1.PluginEventBatch
	stop     chan struct{}
	done     chan struct{}
	handler  func(ctx context.Context, batch []byte) ([]byte, error)
	onFail   func(err error)
	onStatus func(*v1.PluginEventStatus)
	// tick fires the plugin's periodic callback. It runs on this
	// goroutine like everything else, so a tick can never overlap an event
	// batch inside the guest.
	tick     func() error
	interval time.Duration

	mu      sync.Mutex
	dropped uint64
	// submitted and processed count batches accepted and finished. They
	// exist so a caller can tell when delivery has caught up, which
	// otherwise has no observable moment now that it is asynchronous.
	// submitted is incremented before the send, so a batch is never
	// invisible to a caller waiting for delivery to finish.
	submitted uint64
	processed uint64
	// owesSnapshot records that a drop left the plugin's view incomplete.
	owesSnapshot bool
	// holding is set while a snapshot is being delivered, and pending
	// holds the live events that arrived meanwhile.
	//
	// Both go into one queue, so without this a live update can land
	// between two snapshot events and be overtaken by the stale copy that
	// follows it: a withdraw delivered first and the snapshot's older
	// advertise for the same NLRI second leaves the plugin holding a
	// route that no longer exists. Holding the live events until the
	// snapshot finishes makes the snapshot a prefix of the stream, which
	// is the order the plugin is entitled to assume.
	holding bool
	pending []*v1.PluginEventBatch

	// beforeBatch runs on this goroutine ahead of each delivery, and on a
	// slow timer of its own. It is where work that has to happen off the
	// BGP watch goroutine, but before the plugin declares anything, goes.
	//
	// The timer matters because a plugin may legitimately receive nothing:
	// one that only allocates a local SID and advertises it has no route
	// to wait for, so work deferred to "the next event" would wait
	// forever.
	beforeBatch func()
	// completions run on the worker after the named batch returns. Replay
	// publication must follow delivery, not merely admission to the queue.
	completions map[*v1.PluginEventBatch]func()
}

// newWorker starts the delivery goroutine for one plugin.
func newWorker(
	name string,
	logger *zap.Logger,
	handler func(ctx context.Context, batch []byte) ([]byte, error),
	onFail func(err error),
	onStatus func(*v1.PluginEventStatus),
	tick func() error,
	interval time.Duration,
	beforeBatch func(),
) *worker {
	w := &worker{
		name:        name,
		logger:      logger,
		queue:       make(chan *v1.PluginEventBatch, deliveryQueueDepth),
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
		handler:     handler,
		onFail:      onFail,
		onStatus:    onStatus,
		tick:        tick,
		interval:    interval,
		beforeBatch: beforeBatch,
	}
	go w.run()
	return w
}

// submit queues a live batch, dropping it if the plugin is too far behind.
//
// It never blocks: the caller is the BGP watch goroutine, and making it
// wait on a plugin is the thing this whole type exists to prevent.
//
// A drop leaves the plugin's view with a hole in it, which for a consumer
// that declares desired sets is worse than a delay -- the next declaration
// prunes the state it can no longer see. So a drop is recorded as owing a
// snapshot, and the manager rebuilds the view from the rib rather than
// letting the plugin act on a partial one.
// It reports whether the batch was accepted. Most callers have nothing to
// do with the answer -- a dropped route is repaired by the snapshot the
// drop owes -- but an event the snapshot cannot regenerate has to know.
func (w *worker) submit(batch *v1.PluginEventBatch) bool {
	w.mu.Lock()
	w.submitted++
	if w.holding {
		// A snapshot is in flight. Hold this until it finishes rather
		// than letting it be overtaken by an older copy of the same NLRI.
		if len(w.pending) < deliveryQueueDepth {
			w.pending = append(w.pending, batch)
			w.mu.Unlock()
			return true
		}
		// Too far behind to hold any more. Drop, and owe another
		// snapshot: the view this one is building is already stale.
		w.dropped++
		w.processed++
		w.owesSnapshot = true
		w.mu.Unlock()
		return false
	}
	select {
	case w.queue <- batch:
		w.mu.Unlock()
		return true
	default:
		w.dropped++
		w.processed++ // it will never be delivered; do not wait for it
		w.owesSnapshot = true
		dropped := w.dropped
		w.mu.Unlock()
		// Logged at intervals rather than per drop: a plugin that has
		// fallen behind drops continuously, and a line each would bury
		// everything else in the log.
		if dropped == 1 || dropped%1000 == 0 {
			w.logger.Warn("dropping events for a plugin that cannot keep up",
				zap.String("plugin", w.name),
				zap.Uint64("dropped_total", dropped))
		}
		return false
	}
}

// run consumes the queue, and fires the periodic callback, until stopped.
func (w *worker) run() {
	defer close(w.done)

	var ticks <-chan time.Time
	if w.tick != nil && w.interval > 0 {
		t := time.NewTicker(w.interval)
		defer t.Stop()
		ticks = t.C
	}

	var retries <-chan time.Time
	if w.beforeBatch != nil {
		t := time.NewTicker(retryInterval)
		defer t.Stop()
		retries = t.C
	}

	for {
		select {
		case <-w.stop:
			return
		case batch := <-w.queue:
			if w.beforeBatch != nil {
				w.beforeBatch()
			}
			ok := w.deliver(batch)
			w.mu.Lock()
			complete := w.completions[batch]
			delete(w.completions, batch)
			w.mu.Unlock()
			if ok && complete != nil {
				complete()
			}
			w.mu.Lock()
			w.processed++
			w.mu.Unlock()
		case <-retries:
			// Nothing to do in the ordinary case; this exists for the
			// plugin that is owed work and has no traffic to carry it.
			w.beforeBatch()
		case <-ticks:
			// A tick that fails costs the instance, like any other call
			// into the guest, so it goes through the same handler.
			if err := w.tick(); err != nil {
				w.onFail(err)
			}
		}
	}
}

// deliver hands one batch to the guest and acts on what comes back.
func (w *worker) deliver(batch *v1.PluginEventBatch) bool {
	raw, err := proto.Marshal(batch)
	if err != nil {
		w.logger.Error("encoding a plugin event batch",
			zap.String("plugin", w.name), zap.Error(err))
		return false
	}
	status, err := w.handler(context.Background(), raw)
	if err != nil {
		w.onFail(err)
		return false
	}
	if len(status) == 0 {
		w.onStatus(&v1.PluginEventStatus{})
		return true
	}
	var msg v1.PluginEventStatus
	if err := proto.Unmarshal(status, &msg); err != nil {
		w.logger.Warn("plugin returned an undecodable status",
			zap.String("plugin", w.name), zap.Error(err))
		return false
	}
	w.onStatus(&msg)
	return true
}

// close stops the worker and waits for the in-flight batch to finish, so a
// caller that then closes the instance cannot pull it out from under a
// call already inside the guest.
func (w *worker) close() {
	select {
	case <-w.stop:
	default:
		close(w.stop)
	}
	<-w.done
}

// droppedCount is how many batches were discarded, for tests and
// diagnostics.
func (w *worker) droppedCount() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.dropped
}

// caughtUp reports whether every accepted batch has been delivered.
func (w *worker) caughtUp() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.submitted == w.processed
}

// takeSnapshotDebt reports whether a drop has left the plugin's view
// incomplete, clearing the flag. The caller is expected to deliver a
// snapshot; if that fails it should hand the debt back with owe.
func (w *worker) takeSnapshotDebt() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	owed := w.owesSnapshot
	w.owesSnapshot = false
	return owed
}

// owe records that the plugin still needs a snapshot.
func (w *worker) owe() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.owesSnapshot = true
}

// beginSnapshot starts holding live events, so a snapshot is delivered as
// an uninterrupted prefix of the stream.
func (w *worker) beginSnapshot() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.holding = true
}

// endSnapshot releases the live events that arrived during the snapshot,
// in the order they arrived.
func (w *worker) endSnapshot() {
	// Held events are drained while holding is still set, so an event
	// arriving mid-drain queues behind them rather than overtaking them:
	// holding A and B, a C arriving then must not be delivered A, C, B.
	//
	// The rounds are bounded because arrivals do not stop. A plugin slower
	// than its traffic would keep the hold populated forever, and the hold
	// is released by whoever took the snapshot -- on a register, that is
	// the RPC, which would never return.
	for round := 0; round < maxDrainRounds; round++ {
		w.mu.Lock()
		if len(w.pending) == 0 {
			w.holding = false
			w.mu.Unlock()
			return
		}
		held := w.pending
		w.pending = nil
		w.mu.Unlock()

		for _, batch := range held {
			select {
			case w.queue <- batch:
			case <-w.stop:
				w.mu.Lock()
				w.processed++
				w.mu.Unlock()
			}
		}
	}

	// The last round runs under the lock, so nothing can arrive between
	// the final hand-off and the release. That means the sends cannot
	// block, so what does not fit is dropped -- which is the same thing
	// that happens to a live event when the queue is full, and it owes the
	// same snapshot.
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, batch := range w.pending {
		select {
		case w.queue <- batch:
		default:
			w.dropped++
			w.processed++
			w.owesSnapshot = true
		}
	}
	w.pending = nil
	w.holding = false
}

// submitBlocking queues a batch, waiting for room rather than dropping.
//
// It is for a snapshot, where the caller is rebuilding the plugin's whole
// view and dropping part of it would defeat the purpose. Blocking is safe
// here precisely because the caller is not the BGP watch goroutine: a
// snapshot runs on whoever asked for it.
//
// Going through the queue rather than calling the guest directly keeps
// the guest's calls serialized. Live events are held while a snapshot is
// in flight (see beginSnapshot), so a plugin cannot see a route from the
// snapshot after the update that superseded it.
//
// It reports false if the worker stopped before the batch was accepted.
func (w *worker) submitBlocking(batch *v1.PluginEventBatch) bool {
	w.mu.Lock()
	w.submitted++
	w.mu.Unlock()
	select {
	case w.queue <- batch:
		return true
	case <-w.stop:
		w.mu.Lock()
		w.processed++ // nobody will deliver it
		w.mu.Unlock()
		return false
	}
}

func (w *worker) submitCompletion(batch *v1.PluginEventBatch, complete func()) bool {
	w.mu.Lock()
	if w.completions == nil {
		w.completions = make(map[*v1.PluginEventBatch]func())
	}
	w.completions[batch] = complete
	w.mu.Unlock()
	if w.submitBlocking(batch) {
		return true
	}
	w.mu.Lock()
	delete(w.completions, batch)
	w.mu.Unlock()
	return false
}
