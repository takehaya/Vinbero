package cplane

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
)

// EventSource is the demux a plugin subscribes to. Only what the manager
// needs is named here, so a test can drive registration without a BGP
// session.
type EventSource interface {
	Register(name string, families []bgp.Family, handler bgp.RouteHandler) (func(), error)
}

// QuietSource can add a consumer without replaying to it, for a consumer
// that takes its own snapshot instead. The manager prefers it: the replay
// a source performs on registration goes through the live path, where a
// plugin that is behind drops events, and a dropped snapshot leaves it
// declaring a set that prunes the routes it never saw.
type QuietSource interface {
	RegisterQuiet(name string, families []bgp.Family, handler bgp.RouteHandler) (func(), error)
}

// SnapshotSource can replay the current rib to one consumer. The demux
// implements it. It is separate from EventSource because a source that
// only streams live updates is still usable -- the plugin just cannot have
// its view rebuilt, which is worth knowing rather than assuming.
type SnapshotSource interface {
	SnapshotTo(families []bgp.Family, handler bgp.RouteHandler) error
}

// BehaviorClaims is the registry that records which SRv6 endpoint
// behaviors belong to a plugin. The demux's ClaimRegistry satisfies it.
type BehaviorClaims interface {
	// Replace sets a plugin's claims to exactly codepoints, atomically.
	Replace(plugin string, codepoints []uint16) error
	Release(plugin string)
	Claims(plugin string) []uint16
}

// ErrAlreadyRegistered is returned when a name is taken. A plugin is
// replaced through Register with the same name, which is an upgrade; two
// different bundles cannot share one name.
var ErrAlreadyRegistered = errors.New("cplane: plugin already registered")

// maxRestarts bounds how many times a plugin is re-instantiated before it
// is left stopped.
//
// A plugin whose instance dies is restarted rather than flushed: it comes
// back and re-declares, which is cheaper than blackholing traffic for the
// length of a restart. But a module that dies on every event would restart
// forever, so after this many consecutive failures it is left alone with
// its state intact, for an operator to look at.
const maxRestarts = 5

// Registration describes a plugin to run.
type Registration struct {
	// Name identifies the plugin. It becomes the owner tag its writes
	// carry, so it must survive the fixed-width owner buffer.
	Name string
	// Module is the WebAssembly binary.
	Module []byte
	// Config is the operator's configuration blob, opaque to the host.
	Config []byte
	// Families restricts which BGP families the plugin is delivered.
	// Empty means every family.
	Families []bgp.Family
	// Behaviors are the SRv6 endpoint behavior codepoints the plugin
	// claims. Routes naming one are withheld from the built-in appliers.
	Behaviors []uint16
	// Capabilities are what the plugin is allowed to do. An empty set
	// leaves it able to observe and to log, which is a real way to run a
	// plugin and the safe default for one that asked for nothing.
	Capabilities wasm.Capabilities
	// Limits bound the instance; zero fields take defaults.
	Limits wasm.Limits
	// TickInterval asks for the plugin's periodic callback to be driven at
	// this rate. Zero leaves it undriven, which is right for a purely
	// event-driven plugin. The manager clamps it up to MinTickInterval: a
	// plugin cannot ask to be woken faster than the daemon is willing to
	// call into a sandbox.
	TickInterval time.Duration
}

// MinTickInterval is the fastest a plugin's periodic callback is driven.
// A tick is a call into the guest under the same budget as an event, so a
// plugin asking for a millisecond would spend the daemon's time rather
// than its own.
const MinTickInterval = 100 * time.Millisecond

// Manager owns the running control-plane plugins.
type Manager struct {
	source      EventSource
	snapshots   SnapshotSource
	claims      BehaviorClaims
	headend     HeadendMapOps
	quotas      Quotas
	store       *Store
	leases      *Leases
	advertise   *AdvertiseSet
	localSIDs   *LocalSIDSet
	encapSource func() (netip.Addr, error)
	logger      *zap.Logger

	// applyMu serializes reconciles across every plugin this manager runs.
	applyMu sync.Mutex
	// registerMu serializes registration against unregistration.
	//
	// The two touch the same owner tag from opposite ends: unregister
	// flushes everything under it after removing the plugin, and a
	// registration landing in that window would publish a new instance
	// whose state the older call then wipes.
	registerMu sync.Mutex

	// started is the epoch the monotonic clock a plugin sees counts from.
	// It is per daemon rather than per instance so a plugin's readings
	// stay comparable across a restart.
	started time.Time

	mu      sync.Mutex
	plugins map[string]*plugin
	seq     atomic.Uint64
}

// plugin is one registered and running module.
//
// Everything mutable on it is guarded by the manager's lock: registration,
// unregistration and a restart can all touch the same plugin from
// different goroutines.
type plugin struct {
	name     string
	reg      Registration
	inst     *wasm.Instance
	ops      *PluginOps
	worker   *worker
	cancel   func()
	restarts int
	// dead marks an instance that failed and was not restarted, so events
	// stop being handed to a module that cannot take them.
	dead bool
	// counters holds this plugin's observable statistics.
	counters *counters
	// snapshotting is set while a rib replay is in flight for this plugin.
	//
	// Replays must not overlap. Two of them push into one queue with no
	// order between them, so an older copy of a route can land after the
	// newer one and leave the plugin holding the stale value -- and a
	// plugin that is dropping events is by definition slow, so a replay
	// per drop would pile up without bound.
	snapshotting bool
}

// ManagerConfig builds a Manager.
type ManagerConfig struct {
	// Source delivers route events. May be nil, in which case plugins run
	// but receive nothing -- useful for a daemon started without BGP.
	Source EventSource
	// Claims records behavior claims. May be nil when there is no demux.
	Claims BehaviorClaims
	// Headend is the map surface plugin declarations reconcile into.
	Headend HeadendMapOps
	// Advertiser is the send side a plugin originates through. Nil leaves
	// plugins unable to advertise, which is honest on a daemon with no
	// BGP session.
	Advertiser Advertiser
	// Locators allocates the SIDs a plugin points at its data-plane half.
	Locators SIDAllocator
	// SIDFunctions installs the dispatch entries for those SIDs.
	SIDFunctions SIDFunctionOps
	// Quotas bound how much any one plugin may hold. Zero fields take the
	// defaults.
	Quotas Quotas
	// Store keeps registrations across a daemon restart. Nil runs the
	// daemon without one, which means every plugin has to be registered
	// again after a restart -- and the state a plugin wrote outlives the
	// process, so that state comes back owned by nobody until it does.
	Store *Store
	// EncapSource resolves the daemon's encap source when a plugin
	// declares an entry that names none. Called at apply time, because a
	// locator registered over RPC after startup is the common case.
	EncapSource func() (netip.Addr, error)
	Logger      *zap.Logger
}

// NewManager builds an empty manager.
func NewManager(cfg ManagerConfig) (*Manager, error) {
	if cfg.Headend == nil {
		return nil, fmt.Errorf("cplane manager: nil headend map ops")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	leases := NewLeases()
	snapshots, _ := cfg.Source.(SnapshotSource)
	return &Manager{
		advertise:   NewAdvertiseSet(cfg.Advertiser, leases),
		localSIDs:   NewLocalSIDSet(cfg.Locators, cfg.SIDFunctions),
		source:      cfg.Source,
		snapshots:   snapshots,
		claims:      cfg.Claims,
		headend:     cfg.Headend,
		quotas:      cfg.Quotas.withDefaults(),
		store:       cfg.Store,
		leases:      leases,
		encapSource: cfg.EncapSource,
		logger:      logger,
		started:     time.Now(),
		plugins:     make(map[string]*plugin),
	}, nil
}

// Register starts a plugin.
//
// Registering a name that is already running replaces it in place: the old
// instance is stopped and the new one starts against the same owner tag,
// keeping the state the old one wrote. That is what makes an upgrade
// non-disruptive -- the new module re-declares its desired set and the
// reconcile absorbs any difference, rather than the data plane going empty
// between the two.
func (m *Manager) Register(ctx context.Context, reg Registration) error {
	if err := bpf.ValidatePluginBundleName(reg.Name); err != nil {
		return err
	}
	m.registerMu.Lock()
	defer m.registerMu.Unlock()

	// Claims are set before anything is instantiated, so a behavior another
	// plugin holds stops the registration early. The previous set is kept
	// so a failure can put it back: releasing the claims of a plugin that
	// is still running would hand its routes straight to the built-in
	// appliers, which is worse than the failed upgrade.
	var previousClaims []uint16
	if m.claims != nil {
		previousClaims = m.claims.Claims(reg.Name)
		// Replace rather than release-then-claim: an upgrade that drops a
		// behavior must give it up, and doing that as two steps leaves a
		// window where another plugin can take a codepoint this one still
		// holds, which restoreClaims could then not put back.
		if err := m.claims.Replace(reg.Name, reg.Behaviors); err != nil {
			return err
		}
	} else if len(reg.Behaviors) > 0 {
		return fmt.Errorf("cplane: plugin %q claims behaviors but no claim registry is configured", reg.Name)
	}

	p, err := m.build(ctx, reg)
	if err != nil {
		m.restoreClaims(reg.Name, previousClaims)
		return err
	}

	m.mu.Lock()
	old, existed := m.plugins[reg.Name]
	m.plugins[reg.Name] = p
	m.mu.Unlock()

	if existed {
		// Stop the old instance without flushing: the new one inherits the
		// owner tag and re-declares over the same state.
		m.teardown(ctx, old)
	}

	// Anything the plugin declared from configure was held until now, so a
	// failed instantiation could not leave state behind. It is live, so
	// let it through.
	if err := p.ops.Publish(); err != nil {
		m.logger.Warn("applying what a plugin declared before it was live",
			zap.String("plugin", reg.Name), zap.Error(err))
	}

	if m.source != nil {
		subscribe := m.source.Register
		quiet := false
		if qs, ok := m.source.(QuietSource); ok {
			subscribe = qs.RegisterQuiet
			quiet = true
		}
		cancel, err := subscribe(reg.Name, reg.Families, m.handlerFor(reg.Name))
		if err != nil {
			// Undo without flushing: the operator asked for a plugin, not
			// for its predecessor's entries to be deleted. On an upgrade
			// the state under this owner belongs to the version that was
			// running a moment ago, and blackholing it because the new
			// one could not subscribe would be worse than the failure.
			m.mu.Lock()
			if current, ok := m.plugins[reg.Name]; ok && current == p {
				delete(m.plugins, reg.Name)
			}
			m.mu.Unlock()
			m.teardown(ctx, p)
			m.restoreClaims(reg.Name, previousClaims)
			return fmt.Errorf("cplane: subscribe plugin %q: %w", reg.Name, err)
		}
		// The plugin may already have been unregistered while we were
		// subscribing. Cancel immediately in that case, or the demux keeps
		// dispatching to a name that no longer resolves.
		m.mu.Lock()
		current, stillThere := m.plugins[reg.Name]
		if stillThere && current == p {
			p.cancel = cancel
			cancel = nil
		}
		m.mu.Unlock()
		if cancel != nil {
			cancel()
		}

		// Take the snapshot here rather than letting the source replay
		// through the live path, so nothing of it can be dropped. A
		// source that cannot register quietly has already replayed, and
		// this repairs whatever that dropped.
		if quiet || p.worker.takeSnapshotDebt() {
			m.snapshot(p)
		}
	}

	// Recorded only once it is actually running, so a module that could
	// not start is not something a restart tries again forever.
	if err := m.store.Save(reg); err != nil {
		m.logger.Warn("could not persist a plugin registration; it will not survive a restart",
			zap.String("plugin", reg.Name), zap.Error(err))
	}

	m.logger.Info("control-plane plugin registered",
		zap.String("plugin", reg.Name),
		zap.Bool("replaced", existed),
		zap.Int("behaviors", len(reg.Behaviors)),
		zap.Strings("capabilities", reg.Capabilities.Names()))
	return nil
}

// Restore brings back the plugins a previous run registered.
//
// It is deliberately not fatal when one fails: a daemon that refuses to
// finish starting because a plugin is broken has turned a plugin problem
// into an outage. The failure is logged with the name, and the rest come
// up.
func (m *Manager) Restore(ctx context.Context) error {
	if m.store == nil {
		return nil
	}
	regs, err := m.store.List()
	if err != nil {
		return err
	}
	for _, reg := range regs {
		if err := m.Register(ctx, reg); err != nil {
			m.logger.Error("could not restore a plugin from the store",
				zap.String("plugin", reg.Name), zap.Error(err))
			continue
		}
		m.logger.Info("restored a control-plane plugin from the store",
			zap.String("plugin", reg.Name))
	}
	return nil
}

// build instantiates a plugin and its delivery worker without publishing
// it.
func (m *Manager) build(ctx context.Context, reg Registration) (*plugin, error) {
	// A plugin may declare local SIDs from configure, which runs during
	// instantiation -- before there is a worker to deliver the reply
	// through. Buffer those until there is one rather than dropping them:
	// a plugin that is never told the address it was given cannot
	// advertise it, and would sit there waiting for an event that already
	// happened.
	var (
		pendingMu   sync.Mutex
		pendingSIDs []AllocatedSID
		built       *plugin
	)
	onLocalSIDs := func(sids []AllocatedSID) {
		pendingMu.Lock()
		if built == nil {
			pendingSIDs = append(pendingSIDs, sids...)
			pendingMu.Unlock()
			return
		}
		p := built
		pendingMu.Unlock()
		m.deliverLocalSIDs(p, sids)
	}

	ops, err := NewPluginOps(PluginOpsConfig{
		Owner:        bpf.OwnerPluginBundle(reg.Name),
		Headend:      m.headend,
		Leases:       m.leases,
		EncapSource:  m.encapSource,
		Logger:       m.logger.Named("plugin." + reg.Name),
		ApplyMutex:   &m.applyMu,
		Capabilities: reg.Capabilities,
		Advertise:    m.advertise,
		LocalSIDs:    m.localSIDs,
		OnLocalSIDs:  onLocalSIDs,
	})
	if err != nil {
		return nil, err
	}
	inst, err := wasm.Instantiate(ctx, wasm.Config{
		Name:         reg.Name,
		Module:       reg.Module,
		ConfigBlob:   reg.Config,
		Limits:       reg.Limits,
		Ops:          ops,
		Capabilities: reg.Capabilities,
		Logger:       m.logger,
	})
	if err != nil {
		return nil, err
	}
	p := &plugin{name: reg.Name, reg: reg, inst: inst, ops: ops, counters: newCounters()}
	interval := reg.TickInterval
	if interval > 0 && interval < MinTickInterval {
		interval = MinTickInterval
	}
	p.worker = newWorker(reg.Name, m.logger, inst.HandleEvents,
		func(err error) { m.instanceFailed(p, err) },
		func(status *v1.PluginEventStatus) { m.delivered(p, status) },
		func() error { return m.tick(p) },
		interval)

	pendingMu.Lock()
	built = p
	held := pendingSIDs
	pendingSIDs = nil
	pendingMu.Unlock()
	if len(held) > 0 {
		m.deliverLocalSIDs(p, held)
	}
	return p, nil
}

// restoreClaims puts a plugin's previous behaviors back after a failed
// registration.
func (m *Manager) restoreClaims(name string, behaviors []uint16) {
	if m.claims == nil {
		return
	}
	if err := m.claims.Replace(name, behaviors); err != nil {
		// Nothing else can hold them -- they were this plugin's a moment
		// ago -- so this should not happen; say so loudly if it does,
		// because the running instance is now unprotected.
		m.logger.Error("could not restore the behavior claims of a running plugin",
			zap.String("plugin", name), zap.Error(err))
	}
}

// Unregister stops a plugin and removes the state it owns.
//
// Unlike a crash, this is deliberate: the operator is taking the plugin
// away, so its entries go with it rather than being left for a restart to
// reclaim.
func (m *Manager) Unregister(ctx context.Context, name string) error {
	m.registerMu.Lock()
	defer m.registerMu.Unlock()
	m.mu.Lock()
	p, ok := m.plugins[name]
	delete(m.plugins, name)
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("cplane: plugin %q is not registered", name)
	}

	// Order matters. Stop delivery first so nothing new is declared, then
	// close the instance, then remove what it owns. Removing state while
	// the plugin can still write would race with a declaration already in
	// flight.
	m.teardown(ctx, p)
	if m.claims != nil {
		m.claims.Release(name)
	}
	if err := m.store.Remove(name); err != nil {
		m.logger.Warn("could not remove a plugin from the store; a restart would bring it back",
			zap.String("plugin", name), zap.Error(err))
	}
	if err := p.ops.Flush(); err != nil {
		return fmt.Errorf("cplane: flush plugin %q: %w", name, err)
	}
	m.logger.Info("control-plane plugin unregistered", zap.String("plugin", name))
	return nil
}

// teardown stops delivery and closes an instance without touching the
// state it wrote.
func (m *Manager) teardown(ctx context.Context, p *plugin) {
	m.mu.Lock()
	cancel := p.cancel
	p.cancel = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if p.worker != nil {
		// Waits for the batch already inside the guest, so the instance is
		// not closed out from under a running call.
		p.worker.close()
	}
	if err := p.inst.Close(ctx); err != nil {
		m.logger.Warn("closing plugin instance", zap.String("plugin", p.name), zap.Error(err))
	}
	p.ops.DiscardTransactions()
}

// Close stops every plugin. It does not flush: a daemon shutting down
// leaves the data plane as it stands, and only an explicit unregister
// means the state should go away.
func (m *Manager) Close(ctx context.Context) {
	m.mu.Lock()
	plugins := make([]*plugin, 0, len(m.plugins))
	for _, p := range m.plugins {
		plugins = append(plugins, p)
	}
	m.plugins = make(map[string]*plugin)
	m.mu.Unlock()

	for _, p := range plugins {
		m.teardown(ctx, p)
	}
}

// List returns the registered plugin names.
func (m *Manager) List() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.plugins))
	for name := range m.plugins {
		out = append(out, name)
	}
	return out
}

// instanceFailed handles a call into the guest that did not return
// normally: a trap, or a budget overrun.
//
// Either way the instance is gone -- wazero closes the module when its
// context is cancelled, and a trap leaves it unusable -- so the plugin is
// re-instantiated rather than left in place. Its state is kept: the
// replacement re-declares over it, which is why a crash costs nothing but
// the events in flight.
func (m *Manager) instanceFailed(p *plugin, cause error) {
	m.mu.Lock()
	current, ok := m.plugins[p.name]
	if !ok || current != p || p.dead {
		// Already replaced or removed; nothing to restart.
		m.mu.Unlock()
		return
	}
	p.restarts++
	restarts := p.restarts
	reg := p.reg
	m.mu.Unlock()

	p.ops.DiscardTransactions()

	if restarts > maxRestarts {
		m.mu.Lock()
		p.dead = true
		m.mu.Unlock()
		m.logger.Error("control-plane plugin stopped after repeated failures; "+
			"its data-plane state is left in place for inspection",
			zap.String("plugin", p.name),
			zap.Int("restarts", restarts-1),
			zap.Error(cause))
		return
	}

	m.logger.Warn("restarting a control-plane plugin after a failed call",
		zap.String("plugin", p.name),
		zap.Int("restart", restarts),
		zap.Error(cause))

	ctx := context.Background()
	inst, err := wasm.Instantiate(ctx, wasm.Config{
		Name:         reg.Name,
		Module:       reg.Module,
		ConfigBlob:   reg.Config,
		Limits:       reg.Limits,
		Ops:          p.ops,
		Capabilities: reg.Capabilities,
		Logger:       m.logger,
	})
	if err != nil {
		m.mu.Lock()
		p.dead = true
		m.mu.Unlock()
		m.logger.Error("could not re-instantiate a control-plane plugin",
			zap.String("plugin", p.name), zap.Error(err))
		return
	}

	m.mu.Lock()
	if current, ok := m.plugins[p.name]; !ok || current != p {
		// Replaced while we were rebuilding; drop what we just made.
		m.mu.Unlock()
		_ = inst.Close(ctx)
		return
	}
	old := p.inst
	p.inst = inst
	p.worker.handler = inst.HandleEvents
	m.mu.Unlock()
	p.counters.restarted()

	if err := old.Close(ctx); err != nil {
		m.logger.Debug("closing the failed instance", zap.String("plugin", p.name), zap.Error(err))
	}

	// The replacement remembers nothing, so it has to be told what the
	// network looks like. Without this its first declaration describes
	// only the events that happened to arrive after the restart, and the
	// reconcile prunes everything else the plugin owned.
	//
	// It runs on a goroutine of its own because this is the worker
	// goroutine: the snapshot is delivered through the same queue and
	// would deadlock against itself.
	go m.snapshot(p)
}

// snapshot rebuilds a plugin's view from the rib.
//
// A plugin that declares desired sets cannot work from a partial view: its
// next declaration is a statement about the whole set, so a route it never
// saw is a route it prunes. Anything that leaves a hole -- a restart, a
// dropped batch -- therefore has to be followed by this rather than by the
// next live update.
//
// Delivery blocks rather than dropping, which is safe because this does
// not run on the BGP watch goroutine.
func (m *Manager) snapshot(p *plugin) {
	m.mu.Lock()
	if p.snapshotting {
		// One is already running. Ask for another afterwards rather than
		// starting a second alongside it.
		m.mu.Unlock()
		p.worker.owe()
		return
	}
	p.snapshotting = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		p.snapshotting = false
		m.mu.Unlock()
		// A drop while this one was running left the view incomplete
		// again. Repay it now rather than waiting for an event that may
		// not come.
		if p.worker.takeSnapshotDebt() {
			go m.snapshot(p)
		}
	}()

	if m.snapshots == nil {
		// Without a rib to read there is nothing to rebuild from. Say so:
		// the plugin's view stays incomplete and that is worth knowing.
		m.logger.Warn("cannot rebuild a plugin's view: the event source serves no snapshot",
			zap.String("plugin", p.name))
		return
	}
	var count int
	err := m.snapshots.SnapshotTo(p.reg.Families, func(ev bgp.RouteEvent) {
		if p.worker.submitBlocking(m.routeBatch(ev)) {
			count++
		}
	})
	if err != nil {
		// The view is still incomplete; ask for another one on the next
		// opportunity rather than leaving the plugin to prune what it
		// could not see.
		p.worker.owe()
		m.logger.Warn("replaying the rib to a plugin failed",
			zap.String("plugin", p.name), zap.Error(err))
		return
	}
	p.worker.submitBlocking(m.endOfReplayBatch(ReplaySourceBGP))
	p.counters.addSnapshot()
	m.logger.Info("replayed the rib to a plugin",
		zap.String("plugin", p.name), zap.Int("routes", count))
}

// snapshotFor rebuilds one plugin's view on the calling goroutine,
// reporting why it could not when it could not.
//
// The background paths log and move on -- there is nobody to return an
// error to on a worker goroutine -- so this exists for a caller that can
// act on the outcome.
func (m *Manager) snapshotFor(name string) error {
	m.mu.Lock()
	p, ok := m.plugins[name]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("cplane: plugin %q is not registered", name)
	}
	if m.snapshots == nil {
		return fmt.Errorf("cplane: the event source serves no snapshot")
	}
	if err := m.snapshots.SnapshotTo(p.reg.Families, func(ev bgp.RouteEvent) {
		p.worker.submitBlocking(m.routeBatch(ev))
	}); err != nil {
		return err
	}
	p.worker.submitBlocking(m.endOfReplayBatch(ReplaySourceBGP))
	return nil
}

// tick fires the plugin's periodic callback with the host's monotonic
// clock, reading the instance under the lock because a restart may have
// replaced it since the worker started.
func (m *Manager) tick(p *plugin) error {
	m.mu.Lock()
	inst := p.inst
	dead := p.dead
	m.mu.Unlock()
	if dead {
		return nil
	}
	return inst.Tick(context.Background(), int64(time.Since(m.started)))
}

// ReplaySourceBGP names the BGP rib in an end-of-replay event. Sources are
// named rather than counted so a plugin subscribing to more of them later
// does not have to guess which one finished.
const ReplaySourceBGP = "bgp"

// endOfReplayBatch tells a plugin that one source has finished replaying.
//
// A plugin that makes aggregate decisions -- composing a SID list from
// several routes, withdrawing on a health signal -- has to know when it
// has seen enough to decide. Without this it draws its first conclusions
// from a partial view, and the churn is visible to its peers.
func (m *Manager) endOfReplayBatch(source string) *v1.PluginEventBatch {
	return &v1.PluginEventBatch{Events: []*v1.PluginEvent{{
		Kind:         v1.PluginEventKind_PLUGIN_EVENT_KIND_END_OF_REPLAY,
		Sequence:     m.seq.Add(1),
		ReplaySource: source,
	}}}
}

// deliverLocalSIDs tells a plugin the addresses its declared local SIDs
// were given.
//
// The plugin chose the names and the host chose the addresses, so this is
// the only way it learns what to advertise. Delivery is queued like any
// other event, which keeps it in order behind whatever else the plugin is
// being told.
func (m *Manager) deliverLocalSIDs(p *plugin, sids []AllocatedSID) {
	events := make([]*v1.PluginEvent, 0, len(sids))
	for _, s := range sids {
		events = append(events, &v1.PluginEvent{
			Kind:     v1.PluginEventKind_PLUGIN_EVENT_KIND_LOCAL_SID,
			Sequence: m.seq.Add(1),
			LocalSid: &v1.PluginLocalSidAllocated{
				Name:    s.Name,
				Sid:     s.SID.String(),
				Locator: s.Locator,
			},
		})
	}
	if len(events) == 0 {
		return
	}
	// Queued without blocking: this runs inside the guest call that
	// declared the set, and waiting on the queue the same worker drains
	// would deadlock.
	p.worker.submit(&v1.PluginEventBatch{Events: events})
}

// routeBatch wraps one route event as a batch for delivery.
func (m *Manager) routeBatch(ev bgp.RouteEvent) *v1.PluginEventBatch {
	return &v1.PluginEventBatch{Events: []*v1.PluginEvent{{
		Kind:     v1.PluginEventKind_PLUGIN_EVENT_KIND_ROUTE,
		Sequence: m.seq.Add(1),
		Route:    EncodeRouteEvent(ev),
	}}}
}

// delivered runs after a batch the plugin handled without failing.
//
// It resets the restart counter, so maxRestarts bounds consecutive
// failures rather than a plugin's lifetime total: a plugin that recovers
// and then fails again months later should not be treated as one that
// cannot start.
func (m *Manager) delivered(p *plugin, status *v1.PluginEventStatus) {
	m.mu.Lock()
	p.restarts = 0
	m.mu.Unlock()
	m.reportStatus(p, status)
}

// reportStatus records what a plugin said about the events it was given.
func (m *Manager) reportStatus(p *plugin, status *v1.PluginEventStatus) {
	for _, r := range status.GetResults() {
		if r.GetDisposition() == v1.PluginEventDisposition_PLUGIN_EVENT_DISPOSITION_QUARANTINE {
			// The plugin declined this event on purpose. Recording it is
			// the whole value of having a polite refusal: the alternative
			// signal is a trap, which costs the instance and repeats.
			p.counters.addQuarantined(1)
			m.logger.Warn("plugin quarantined an event",
				zap.String("plugin", p.name),
				zap.Uint64("sequence", r.GetSequence()),
				zap.String("reason", r.GetReason()))
		}
	}
}

// handlerFor builds the demux handler that carries route events to one
// plugin.
//
// It only queues: the call into the guest happens on the plugin's own
// worker. This handler runs on the BGP watch goroutine, which must never
// block.
func (m *Manager) handlerFor(name string) bgp.RouteHandler {
	return func(ev bgp.RouteEvent) {
		m.mu.Lock()
		p, ok := m.plugins[name]
		dead := ok && p.dead
		m.mu.Unlock()
		if !ok || dead {
			return
		}
		p.worker.submit(m.routeBatch(ev))

		// A drop leaves the plugin's view with a hole. Rebuild it rather
		// than letting the next declaration prune what it never saw. This
		// runs on the BGP watch goroutine, so the snapshot itself is
		// handed to a goroutine of its own.
		if p.worker.takeSnapshotDebt() {
			go m.snapshot(p)
		}
	}
}

// WaitIdle blocks until every event accepted for the named plugin has been
// delivered, or the timeout elapses. It reports whether delivery caught up.
//
// Delivery is asynchronous -- a plugin call must not run on the BGP watch
// goroutine -- which leaves callers that need to observe the result of an
// event with no moment to look at. Tests are the obvious user; an operator
// tool that pushes a config and then reads back the data plane is another.
func (m *Manager) WaitIdle(name string, timeout time.Duration) bool {
	m.mu.Lock()
	p, ok := m.plugins[name]
	m.mu.Unlock()
	if !ok {
		return true
	}
	deadline := time.Now().Add(timeout)
	for {
		if p.worker.caughtUp() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Millisecond)
	}
}

// DroppedEvents is how many event batches were discarded because the named
// plugin could not keep up.
//
// A plugin falling behind is otherwise invisible: its declarations simply
// stop reflecting the routes it never saw, which looks like a plugin bug
// rather than a plugin that is too slow. Reporting the count is what tells
// the two apart.
func (m *Manager) DroppedEvents(name string) uint64 {
	m.mu.Lock()
	p, ok := m.plugins[name]
	m.mu.Unlock()
	if !ok {
		return 0
	}
	return p.worker.droppedCount()
}
