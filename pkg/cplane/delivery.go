package cplane

import (
	"context"
	"sync"

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

	mu      sync.Mutex
	dropped uint64
	// submitted and processed count batches accepted and finished. They
	// exist so a caller can tell when delivery has caught up, which
	// otherwise has no observable moment now that it is asynchronous.
	submitted uint64
	processed uint64
}

// newWorker starts the delivery goroutine for one plugin.
func newWorker(
	name string,
	logger *zap.Logger,
	handler func(ctx context.Context, batch []byte) ([]byte, error),
	onFail func(err error),
	onStatus func(*v1.PluginEventStatus),
) *worker {
	w := &worker{
		name:     name,
		logger:   logger,
		queue:    make(chan *v1.PluginEventBatch, deliveryQueueDepth),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
		handler:  handler,
		onFail:   onFail,
		onStatus: onStatus,
	}
	go w.run()
	return w
}

// submit queues a batch, dropping it if the plugin is too far behind.
//
// It never blocks: the caller is the BGP watch goroutine, and making it
// wait on a plugin is the thing this whole type exists to prevent.
func (w *worker) submit(batch *v1.PluginEventBatch) {
	select {
	case w.queue <- batch:
		w.mu.Lock()
		w.submitted++
		w.mu.Unlock()
	default:
		w.mu.Lock()
		w.dropped++
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
	}
}

// run consumes the queue until stopped.
func (w *worker) run() {
	defer close(w.done)
	for {
		select {
		case <-w.stop:
			return
		case batch := <-w.queue:
			w.deliver(batch)
			w.mu.Lock()
			w.processed++
			w.mu.Unlock()
		}
	}
}

// deliver hands one batch to the guest and acts on what comes back.
func (w *worker) deliver(batch *v1.PluginEventBatch) {
	raw, err := proto.Marshal(batch)
	if err != nil {
		w.logger.Error("encoding a plugin event batch",
			zap.String("plugin", w.name), zap.Error(err))
		return
	}
	status, err := w.handler(context.Background(), raw)
	if err != nil {
		w.onFail(err)
		return
	}
	if len(status) == 0 {
		return
	}
	var msg v1.PluginEventStatus
	if err := proto.Unmarshal(status, &msg); err != nil {
		w.logger.Warn("plugin returned an undecodable status",
			zap.String("plugin", w.name), zap.Error(err))
		return
	}
	w.onStatus(&msg)
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
