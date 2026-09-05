package cplane

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
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

// BuiltinRetractor is a source that can tell Vinbero's own appliers to let
// go of routes whose behavior a plugin has claimed. *demux.Demux provides
// it.
//
// A claim only decides where later routes go. One that arrived first has
// already been installed by the built-in appliers as an ordinary service
// SID, under their owner, so the plugin's write to that prefix is refused
// and the entry with the wrong meaning is the one carrying traffic.
type BuiltinRetractor interface {
	RetractClaimedFromBuiltins()
}

// BuiltinClaimRefresher restores the current built-in view when a registration
// rolls back claims that live updates may already have observed.
type BuiltinClaimRefresher interface {
	RefreshBuiltinClaims()
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
	// Scope bounds which keys those capabilities may be exercised on. A
	// capability says what kind of thing may be declared and the scope
	// says which ones, and both are needed to write anything: the zero
	// value permits nothing.
	Scope Scope
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
	// locatorInfo and vrfBindings are what a scope is stated in terms of.
	locatorInfo LocatorSource
	vrfBindings VRFBindingSource
	// limits are what a plugin costs to run when its registration is
	// silent about it.
	limits wasm.Limits
	logger *zap.Logger

	// unrestored holds the plugins the store had but that would not come
	// back, keyed by name.
	//
	// They are kept because the daemon is still holding something of
	// theirs: the state they wrote is pinned in the maps, and their
	// behaviors stay claimed so nothing installs those routes with the
	// wrong meaning. Neither is visible from the running set, so without
	// this an operator sees a plugin that is simply absent, with routes
	// going nowhere and nothing saying why.
	unrestoredMu sync.Mutex
	unrestored   map[string]UnrestoredPlugin

	// applyMu serializes reconciles across every plugin this manager runs.
	applyMu sync.Mutex
	// endtVRFGrantLease serializes a plugin's decap-grant install against a
	// concurrent VrfDelete. The LocalSIDSet holds it while resolving a VRF and
	// writing the grant; VrfServer takes the same instance while checking for
	// grants and tearing the device down. It is exposed so the server can wire
	// it into the VRF handler. It is a leaf lock (see LocalSIDSet.grantLease).
	endtVRFGrantLease sync.Mutex
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
	//
	Advertiser Advertiser
	// AdvertiserFor names each plugin's send side, so the BGP session can
	// tell one plugin's routes from another's. Optional: without it every
	// plugin shares one identity.
	//
	// The lease is the first barrier between two plugins originating one
	// NLRI; the producer name is the second, and the two fail differently.
	// A lease conflict is refused before anything is sent. A producer
	// conflict is what stops one plugin's withdraw from deleting a route
	// another plugin still wants -- which matters exactly when the lease
	// has been given up by mistake.
	AdvertiserFor func(producer string) Advertiser
	// Locators allocates the SIDs a plugin points at its data-plane half.
	Locators SIDAllocator
	// LocatorInfo and VRFBindings are what a plugin's scope is stated in
	// terms of. Both are resolved when a declaration is applied rather
	// than captured here, because an operator registers locators and VRF
	// bindings over RPC after the daemon is up. Nil leaves declarations
	// that would need them refused rather than waved through.
	LocatorInfo LocatorSource
	VRFBindings VRFBindingSource
	// SIDFunctions installs the dispatch entries for those SIDs.
	SIDFunctions SIDFunctionOps
	// EndtVRFGrants records the VRF a plugin-dispatched End.DT4/DT6/DT46 may
	// decapsulate into, and ResolveVRF turns a scoped VRF name into the
	// kernel ifindex it records. Both nil leaves a DecapVRF local SID refused
	// rather than installed as one the data plane drops on.
	EndtVRFGrants EndtVRFGrantOps
	ResolveVRF    func(vrfName string) (uint32, error)
	// Quotas bound how much any one plugin may hold. Zero fields take the
	// defaults.
	Quotas Quotas
	// DefaultLimits bound what a plugin costs to run when its registration
	// does not say. The registration wins where it sets a field, so an
	// operator can raise one plugin without loosening the rest.
	DefaultLimits wasm.Limits
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
	m := &Manager{
		advertise:   newNamedAdvertiseSet(cfg, leases),
		localSIDs:   NewLocalSIDSet(cfg.Locators, cfg.SIDFunctions, cfg.EndtVRFGrants, cfg.ResolveVRF),
		source:      cfg.Source,
		snapshots:   snapshots,
		claims:      cfg.Claims,
		headend:     cfg.Headend,
		quotas:      cfg.Quotas.withDefaults(),
		limits:      cfg.DefaultLimits,
		store:       cfg.Store,
		leases:      leases,
		encapSource: cfg.EncapSource,
		locatorInfo: cfg.LocatorInfo,
		vrfBindings: cfg.VRFBindings,
		logger:      logger,
		started:     time.Now(),
		plugins:     make(map[string]*plugin),
		unrestored:  make(map[string]UnrestoredPlugin),
	}
	// Share the grant lease with the local-SID tracker so install serializes
	// against VrfDelete on the same lock the server also takes.
	m.localSIDs.grantLease = &m.endtVRFGrantLease
	return m, nil
}

// EndtVRFGrantLease is the lock a plugin's decap-grant install and a VrfDelete
// share so a grant can never be written for an ifindex being freed. The server
// wires it into the VRF delete handler.
func (m *Manager) EndtVRFGrantLease() *sync.Mutex {
	return &m.endtVRFGrantLease
}

// newNamedAdvertiseSet builds the advertise tracker, naming each owner's
// send side when the daemon supplied a way to.
func newNamedAdvertiseSet(cfg ManagerConfig, leases *Leases) *AdvertiseSet {
	set := NewAdvertiseSet(cfg.Advertiser, leases)
	if cfg.AdvertiserFor != nil {
		set.NameProducers(cfg.AdvertiserFor)
	}
	return set
}

// ReconcileAdvertised re-derives what every plugin originates.
//
// A plugin names a VRF and the host fills in the route distinguisher, the
// route targets and the cap from that VRF's binding. Those are stamped
// when the declaration is applied, so an operator editing a binding
// afterwards would otherwise leave the plugin's paths on the wire carrying
// what the binding used to say -- until the plugin next happened to
// redeclare, which an event-driven plugin may not do for a long time.
//
// The daemon calls it after a binding changes. Failures are logged per
// plugin rather than returned: one plugin that cannot reconcile must not
// stop the others from following the edit.
func (m *Manager) ReconcileAdvertised(ctx context.Context) {
	m.mu.Lock()
	plugins := make([]*plugin, 0, len(m.plugins))
	for _, p := range m.plugins {
		plugins = append(plugins, p)
	}
	m.mu.Unlock()
	sort.Slice(plugins, func(i, j int) bool { return plugins[i].name < plugins[j].name })

	for _, p := range plugins {
		withdrawn, err := p.ops.ReconcileAdvertised(ctx)
		if err != nil {
			m.logger.Error("could not re-derive what a plugin advertises after a VRF binding changed",
				zap.String("plugin", p.name), zap.Error(err))
			continue
		}
		if withdrawn > 0 {
			m.logger.Info("withdrew plugin routes a changed VRF binding no longer covers",
				zap.String("plugin", p.name), zap.Int("withdrawn", withdrawn))
		}
	}
}

// ErrPluginNotRegistered is a name the manager does not hold. It is the
// caller's to fix, so callers can tell it from a daemon failure.
var ErrPluginNotRegistered = errors.New("plugin is not registered")

// ErrGrantHeld is a data-plane slot or a locator another plugin already
// holds. Like a behavior claim, it is the caller's to resolve, so the RPC
// boundary maps it to a failed-precondition code.
var ErrGrantHeld = errors.New("scope grant is held by another plugin")

// checkGrantsExclusive refuses reg's slots and locators if another
// registered plugin already holds any of them. Slots must be exclusive
// because one PROG_ARRAY slot is one program; locators must be exclusive
// because a locator is the plugin's SID space, and advertising a SID is
// bounded to it -- two plugins sharing a locator would let one advertise a
// prefix pointing at a SID the other allocated there. Registering the same
// name again is an upgrade and does not conflict with itself. Called with
// registerMu held.
func (m *Manager) checkGrantsExclusive(name string, scope Scope) error {
	type heldGrants struct {
		owner    string
		v4, v6   map[uint32]struct{}
		ep       map[uint32]struct{}
		locators map[string]struct{}
	}
	grantsOf := func(owner string, s Scope) heldGrants {
		return heldGrants{
			owner:    owner,
			v4:       slotSet(s.HeadendV4Slots),
			v6:       slotSet(s.HeadendV6Slots),
			ep:       slotSet(s.EndpointSlots),
			locators: stringSet(s.Locators),
		}
	}
	m.mu.Lock()
	held := make([]heldGrants, 0, len(m.plugins))
	for other, p := range m.plugins {
		if other == name {
			continue
		}
		held = append(held, grantsOf(other, p.reg.Scope))
	}
	m.mu.Unlock()

	// A plugin whose prune or restore failed is out of m.plugins but still
	// holds its state and claim in the maps until an operator forgets it, so
	// its slots and locators stay reserved. Otherwise another plugin could
	// take the same grant and collide with that residual state. Reusing the
	// same name is the upgrade path and does not conflict with itself.
	m.unrestoredMu.Lock()
	for other, u := range m.unrestored {
		if other == name {
			continue
		}
		held = append(held, grantsOf(other+" (unrestored)", u.scope))
	}
	m.unrestoredMu.Unlock()

	for _, h := range held {
		for _, s := range scope.HeadendV4Slots {
			if _, ok := h.v4[s]; ok {
				return fmt.Errorf("cplane: %w: headend v4 slot %d is held by plugin %q", ErrGrantHeld, s, h.owner)
			}
		}
		for _, s := range scope.HeadendV6Slots {
			if _, ok := h.v6[s]; ok {
				return fmt.Errorf("cplane: %w: headend v6 slot %d is held by plugin %q", ErrGrantHeld, s, h.owner)
			}
		}
		for _, s := range scope.EndpointSlots {
			if _, ok := h.ep[s]; ok {
				return fmt.Errorf("cplane: %w: endpoint slot %d is held by plugin %q", ErrGrantHeld, s, h.owner)
			}
		}
		for _, loc := range scope.Locators {
			if _, ok := h.locators[loc]; ok {
				return fmt.Errorf("cplane: %w: locator %q is held by plugin %q", ErrGrantHeld, loc, h.owner)
			}
		}
	}
	return nil
}

// stringSet indexes a string list for membership tests.
func stringSet(items []string) map[string]struct{} {
	out := make(map[string]struct{}, len(items))
	for _, s := range items {
		out[s] = struct{}{}
	}
	return out
}

// slotSet indexes a slot list for membership tests.
func slotSet(slots []uint32) map[uint32]struct{} {
	out := make(map[uint32]struct{}, len(slots))
	for _, s := range slots {
		out[s] = struct{}{}
	}
	return out
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
	// A capability with nothing in the scope to exercise it on is an inert
	// registration: it runs, declares, and has every declaration refused,
	// which reads as a broken plugin. Refused here rather than at the RPC
	// so the restore path is held to it too -- a stored registration gone
	// incoherent is refused instead of restored into that state.
	if err := ScopeCoversCapabilities(reg.Capabilities, reg.Scope); err != nil {
		return err
	}
	m.registerMu.Lock()
	defer m.registerMu.Unlock()

	// Slots and locators are exclusive across plugins. A slot holds one
	// program, so two plugins granted one slot would have one's SID dispatch
	// into the other's program and read its aux under the wrong layout. A
	// locator is a plugin's SID space, and advertising a SID is bounded to
	// it, so two plugins sharing a locator would let one advertise a prefix
	// pointing at the other's SID. Refused here, the same way a behavior
	// claim another plugin holds is, so a region granted twice is caught
	// before anything is installed.
	if err := m.checkGrantsExclusive(reg.Name, reg.Scope); err != nil {
		return err
	}

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

	reg.Limits = m.limits.Merge(reg.Limits)

	p, err := m.build(ctx, reg)
	if err != nil {
		m.restoreClaims(reg.Name, previousClaims)
		return err
	}

	// Everything that can still fail happens before the running plugin is
	// touched. Subscribing is the last of those, and on an upgrade it used
	// to run after the old instance had already been stopped -- so a
	// subscription the demux refused left the operator with neither
	// version registered, the old one closed and unrecoverable, and its
	// state sitting in the maps.
	var cancel func()
	if m.source != nil {
		subscribe := m.source.Register
		if qs, ok := m.source.(QuietSource); ok {
			subscribe = qs.RegisterQuiet
		}
		var err error
		// The handler resolves the plugin by name at delivery time, so
		// until the swap below it still reaches the version that is
		// running. The overlap costs a duplicate event, which a consumer
		// declaring desired sets absorbs.
		cancel, err = subscribe(reg.Name, reg.Families, m.handlerFor(reg.Name))
		if err != nil {
			// Nothing has been published, so tearing the new one down
			// leaves no trace of it, and the version that was running is
			// still running.
			m.teardown(ctx, p)
			m.restoreClaims(reg.Name, previousClaims)
			return fmt.Errorf("cplane: subscribe plugin %q: %w", reg.Name, err)
		}
	}

	m.mu.Lock()
	old, existed := m.plugins[reg.Name]
	m.plugins[reg.Name] = p
	p.cancel = cancel
	inst := p.inst
	m.mu.Unlock()

	if existed {
		// Stop the old instance without flushing: the new one inherits the
		// owner tag and re-declares over the same state. This also cancels
		// its subscription, ending the overlap.
		m.teardown(ctx, old)
	}

	// The state under this owner is inherited whether it came from the
	// instance just torn down or from before a daemon restart, and a
	// registration whose scope does not cover all of it must not keep the
	// rest. The plugin cannot do this itself: its own declaration of that
	// state is now refused, and refused whole, so it would simply stop
	// reconciling with the old entries still installed.
	//
	// Not gated on having replaced something: a restore goes through here
	// with nothing in the registry and its predecessor's writes still
	// pinned in the maps, which is the same situation.
	if removed, err := p.ops.PruneOutOfScope(ctx); err != nil {
		return m.failPrune(ctx, reg, p, removed, err)
	} else if removed > 0 {
		m.logger.Info("removed the state a plugin held outside its new scope",
			zap.String("plugin", reg.Name), zap.Int("removed", removed))
	}

	// The claim reaches back over routes that arrived before it, now that
	// nothing else can fail. Retracting them from the built-in appliers is
	// not undoable, so it waits until the plugin that is meant to take
	// them over is built and subscribed: a module refused at admission
	// would otherwise leave those routes removed from the appliers with
	// nothing left implementing them.
	if m.claims != nil && len(reg.Behaviors) > 0 {
		if r, ok := m.source.(BuiltinRetractor); ok {
			r.RetractClaimedFromBuiltins()
		}
	}

	if m.snapshots != nil {
		// The snapshot comes before publication. What the plugin declared
		// from configure is held either way, and holding it across the
		// replay means its first applied declaration describes the whole
		// network rather than the events that happened to be in the queue
		// -- which, on a plugin that declares a desired set, is the
		// difference between converging and pruning everything it owns.
		//
		// Registration replay has no completion barrier and can arrive
		// before the new plugin is visible. Always take our own snapshot.
		m.snapshot(p)
	}

	// A replay publishes on the worker after end-of-replay is handled.
	// A source without snapshots has no such barrier to wait for.
	if m.snapshots == nil {
		m.publish(p, inst)
	}

	// Recorded only once it is actually running, so a module that could
	// not start is not something a restart tries again forever.
	//
	// A failure here is reported rather than logged past. The plugin is
	// running, so it is not undone, but "registered" means it survives a
	// restart: an operator told it succeeded would find it gone, or find
	// the version it replaced, with nothing having said so.
	if err := m.store.Save(reg); err != nil {
		m.logger.Error("a plugin is running but could not be persisted; "+
			"it will not survive a restart",
			zap.String("plugin", reg.Name), zap.Error(err))
		return fmt.Errorf("cplane: plugin %q is running but could not be persisted, "+
			"so it will not survive a restart: %w", reg.Name, err)
	}

	// A successful registration is, by definition, not unrestored. Clearing
	// any stale record here is what keeps Forget from later deleting this now
	// running plugin from the registry without tearing it down: Forget acts
	// only on names still recorded unrestored.
	m.clearUnrestored(reg.Name)

	m.logger.Info("control-plane plugin registered",
		zap.String("plugin", reg.Name),
		zap.Bool("replaced", existed),
		zap.Int("behaviors", len(reg.Behaviors)),
		zap.Strings("capabilities", reg.Capabilities.Names()))
	return nil
}

// failPrune handles a registration whose out-of-scope prune could not be
// applied: some state the new scope forbids is still installed and the
// plugin cannot clear it itself, because its own declaration of that state
// is now refused whole.
//
// Reporting success here would claim an authorization boundary is in force
// when it is not, so it returns an error. But it first makes the store, the
// claims and the registry agree on one outcome rather than three, which the
// earlier version did not:
//
//   - The new registration is persisted. It is what the operator asked for,
//     and a restore replays it and re-runs the prune, so a
//     persisted-but-not-pruned scope self-repairs on the next boot instead
//     of reverting to the old wider one.
//   - The behavior claims stay as the new set. The plugin is dead but its
//     leftover state is still in the maps, so routes carrying its codepoint
//     must keep being withheld from the built-in appliers rather than
//     installed over that state with the wrong meaning.
//   - The plugin is removed from the running registry and recorded as
//     unrestored with this reason, so it is reported once, not as both
//     running and unrestored, and Forget is the operator's way to give up
//     on it.
func (m *Manager) failPrune(ctx context.Context, reg Registration, p *plugin, removed int, cause error) error {
	m.teardown(ctx, p)
	m.mu.Lock()
	// Only drop the entry this call installed; a concurrent re-register
	// that already replaced it must win.
	if cur, ok := m.plugins[reg.Name]; ok && cur == p {
		delete(m.plugins, reg.Name)
	}
	m.mu.Unlock()

	// Persist the narrowing so a restart retries the prune rather than
	// bringing back the wider scope. A store failure here is logged, not
	// returned over the prune error: the prune failure is the one the
	// operator has to act on.
	if err := m.store.Save(reg); err != nil {
		m.logger.Error("could not persist the narrowed scope of a plugin whose prune failed; "+
			"a restart may bring back the wider scope",
			zap.String("plugin", reg.Name), zap.Error(err))
	}

	m.recordUnrestored(reg, fmt.Errorf("scope narrowing could not be applied: %w", cause))
	m.logger.Error("could not remove the state a plugin held outside its new scope; "+
		"the plugin is stopped and that state is still installed",
		zap.String("plugin", reg.Name), zap.Int("removed", removed), zap.Error(cause))
	return fmt.Errorf("cplane: plugin %q holds state outside its new scope that could not be removed, "+
		"so the plugin was stopped rather than run under a scope that is not in force: %w",
		reg.Name, cause)
}

// ReserveClaims takes the behavior claims of every stored plugin, before
// any route has been delivered.
//
// The daemon starts the demux -- and with it the built-in appliers and the
// replay of everything already in the rib -- before it restores plugins.
// A route carrying a stored plugin's behavior would therefore reach the
// built-in appliers first, which read a codepoint they do not know as an
// ordinary service SID and install an entry with the wrong meaning under
// their own owner; the plugin's own write to that prefix then collides
// with it. Claiming first closes that window, because the claim is what
// the demux consults, not the plugin's existence.
//
// A plugin that then fails to restore has its reservation released, in
// Restore.
func (m *Manager) ReserveClaims() error {
	return ReserveStoredClaims(m.store, m.claims, m.logger)
}

// ReserveStoredClaims is ReserveClaims for a daemon that has not built its
// manager yet, which is the ordering that matters: the reservation has to
// happen before the demux starts, and the manager is built after it.
func ReserveStoredClaims(store *Store, claims BehaviorClaims, logger *zap.Logger) error {
	if store == nil || claims == nil {
		return nil
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	// Read from the manifests alone. A registration whose module is
	// missing or corrupt will fail to restore, and its codepoints are
	// precisely the ones that must stay claimed -- reading the modules
	// here would drop it from the list and reserve nothing for it.
	stored, listErr := store.ListClaims()
	for _, claim := range stored {
		if err := claims.Replace(claim.Name, claim.Behaviors); err != nil {
			logger.Error("could not reserve the behaviors of a stored plugin",
				zap.String("plugin", claim.Name), zap.Error(err))
		}
	}
	return listErr
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
	// List returns what it could read alongside the error, and that
	// partial list is the point: one unreadable manifest must not stop
	// every other plugin from coming back, or a single bad file leaves
	// the daemon holding their pinned state under owners nothing can
	// reconcile.
	regs, listErr := m.store.List()
	for _, reg := range regs {
		if err := m.Register(ctx, reg); err != nil {
			m.logger.Error("could not restore a plugin from the store",
				zap.String("plugin", reg.Name), zap.Error(err))
			// Its behaviors are re-reserved. Register rolls its own claim
			// back when it fails -- which is right for an operator's
			// registration, where nothing was reserved before it -- but a
			// restore is the other case: the reservation was taken before
			// the demux started, precisely so routes carrying a codepoint
			// nothing implements are withheld from the built-in appliers.
			// Letting the rollback stand would hand them over to be
			// installed as ordinary service SIDs, which is forwarding that
			// is silently wrong rather than visibly absent.
			if len(reg.Behaviors) > 0 && m.claims != nil {
				if err := m.claims.Replace(reg.Name, reg.Behaviors); err != nil {
					m.logger.Error("could not keep the behaviors of a plugin that failed to restore; "+
						"routes carrying them will be installed with the wrong meaning",
						zap.String("plugin", reg.Name), zap.Error(err))
				} else {
					m.logger.Warn("keeping the behaviors of a plugin that could not be restored; "+
						"routes carrying them are not installed until it is registered again",
						zap.String("plugin", reg.Name), zap.Uint16s("behaviors", reg.Behaviors))
				}
			}
			// Recorded so it is visible. The daemon is still holding its
			// state and its claim; an operator who cannot see that has no
			// way to connect the routes going nowhere to the plugin that
			// failed to start.
			m.recordUnrestored(reg, err)
			continue
		}
		m.clearUnrestored(reg.Name)
		m.logger.Info("restored a control-plane plugin from the store",
			zap.String("plugin", reg.Name))
	}

	// A manifest that would not even load -- an older format, most often --
	// is recorded as unrestored too, so it is visible in stats rather than
	// only in a startup log line, and its state stays pinned. Its claims
	// were already reserved by ListClaims, which reads behaviors regardless
	// of version, so routes carrying its codepoint are still withheld from
	// the built-in appliers.
	for _, u := range m.store.Unloadable() {
		m.logger.Warn("a stored plugin could not be restored; its state is left in place",
			zap.String("plugin", u.Name), zap.Error(u.Reason))
		m.recordUnrestored(Registration{Name: u.Name, Behaviors: u.Behaviors, Scope: u.Scope}, u.Reason)
	}
	return listErr
}

// UnrestoredPlugin is a plugin the store held that would not start.
type UnrestoredPlugin struct {
	Name string
	// Behaviors are the codepoints still claimed on its behalf, which is
	// why routes carrying them reach nothing.
	Behaviors []uint16
	// Reason is why it would not start, in the operator's words.
	Reason string
	// Since is when the attempt failed.
	Since time.Time
	// scope is the grant the failed registration held. Its slots and
	// locators stay reserved against another plugin taking them while this
	// one's state is still pinned in the maps. Empty for a manifest that
	// would not even load, since its scope was never parsed.
	scope Scope
}

func (m *Manager) recordUnrestored(reg Registration, cause error) {
	m.unrestoredMu.Lock()
	defer m.unrestoredMu.Unlock()
	m.unrestored[reg.Name] = UnrestoredPlugin{
		Name:      reg.Name,
		Behaviors: append([]uint16(nil), reg.Behaviors...),
		Reason:    cause.Error(),
		Since:     time.Now(),
		scope:     reg.Scope,
	}
}

func (m *Manager) clearUnrestored(name string) {
	m.unrestoredMu.Lock()
	defer m.unrestoredMu.Unlock()
	delete(m.unrestored, name)
}

// Unrestored lists the plugins the store held that would not start,
// sorted by name.
func (m *Manager) Unrestored() []UnrestoredPlugin {
	m.unrestoredMu.Lock()
	out := make([]UnrestoredPlugin, 0, len(m.unrestored))
	for _, u := range m.unrestored {
		out = append(out, u)
	}
	m.unrestoredMu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Forget removes a plugin that would not start: it releases the claim it
// was holding, drops it from the store, and stops reporting it.
//
// It is the counterpart of Unregister for something that never ran. The
// state it left in the maps is not touched, because nothing here knows
// what that state was for; releasing the claim is what an operator does
// once they have decided the plugin is not coming back.
func (m *Manager) Forget(name string) error {
	m.registerMu.Lock()
	defer m.registerMu.Unlock()

	m.unrestoredMu.Lock()
	_, held := m.unrestored[name]
	m.unrestoredMu.Unlock()
	if !held {
		return fmt.Errorf("cplane: %w: %q is not one that failed to restore",
			ErrPluginNotRegistered, name)
	}
	// A plugin can be both unrestored and running: a re-registration that
	// published the new instance but then failed to persist it returns before
	// clearing the old unrestored record. Forgetting it here would release its
	// claim and store entry and drop it from the registry without tearing the
	// worker down, leaking a running instance. Refuse and send the operator to
	// Unregister, which stops it cleanly.
	m.mu.Lock()
	_, running := m.plugins[name]
	m.mu.Unlock()
	if running {
		return fmt.Errorf("cplane: plugin %q is running; Unregister it rather than Forget", name)
	}
	if m.claims != nil {
		m.claims.Release(name)
	}
	if err := m.store.Remove(name); err != nil {
		return fmt.Errorf("cplane: remove plugin %q from the store: %w", name, err)
	}
	m.clearUnrestored(name)
	// Belt and suspenders: a plugin recorded as unrestored should not also be
	// in the running registry (the guard above refuses that), and failPrune
	// removes the dead entry before recording. This delete covers any residual
	// path that left a dead entry behind, so Forget cannot leave one reporting
	// the plugin through List.
	m.mu.Lock()
	delete(m.plugins, name)
	m.mu.Unlock()
	m.logger.Info("forgot a control-plane plugin that could not be restored",
		zap.String("plugin", name))
	return nil
}

// build instantiates a plugin and its delivery worker without publishing
// it.
func (m *Manager) build(ctx context.Context, reg Registration) (*plugin, error) {
	// Local SIDs declared from configure are answered through the worker
	// like any other event. configure runs during instantiation, before
	// there is a worker, but nothing it declares is applied until
	// publication -- which happens after the worker exists -- so the reply
	// is queued rather than lost.
	var built *plugin
	onLocalSIDs := func(sids []AllocatedSID) bool {
		if built == nil {
			return false
		}
		return m.deliverLocalSIDs(built, sids)
	}

	ops, err := NewPluginOps(PluginOpsConfig{
		Owner:        bpf.OwnerPluginBundle(reg.Name),
		Headend:      m.headend,
		Leases:       m.leases,
		EncapSource:  m.encapSource,
		Logger:       m.logger.Named("plugin." + reg.Name),
		ApplyMutex:   &m.applyMu,
		Capabilities: reg.Capabilities,
		Guard:        NewGuard(reg.Scope, m.locatorInfo, m.vrfBindings),
		Quotas:       m.quotas,
		Advertise:    m.advertise,
		LocalSIDs:    m.localSIDs,
		OnLocalSIDs:  onLocalSIDs,
	})
	if err != nil {
		return nil, err
	}
	inst, err := wasm.Instantiate(ctx, wasm.Config{
		NowMonotonic: m.nowMonotonic,
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
		interval,
		// Declarations that could not be applied when the plugin went live
		// are retried here, on the worker rather than the watch goroutine.
		// A restored plugin declares from configure, before an operator
		// has registered the locator it names; this is what lets the first
		// event afterwards repair that instead of leaving it lost.
		ops.RetryPending)

	built = p
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
		return
	}
	if source, ok := m.source.(BuiltinClaimRefresher); ok {
		source.RefreshBuiltinClaims()
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
		return fmt.Errorf("cplane: %w: %q", ErrPluginNotRegistered, name)
	}

	// Order matters. Delivery stops first so nothing new is declared, then
	// the instance closes, then what it owns is removed. Removing state
	// while the plugin can still write would race with a declaration
	// already in flight.
	m.teardown(ctx, p)

	// The flush comes before anything is given up, because a failed flush
	// has to stay retryable. Releasing the claim first would hand the
	// routes back to the built-in appliers while the plugin's state is
	// still installed, and removing it from the store first would mean a
	// restart does not even bring back the plugin whose state was left
	// behind.
	if err := p.ops.Flush(); err != nil {
		// It is out of the registry and its instance is closed, so it is
		// no longer running; the state it could not remove is what is left
		// to deal with. Put it back so the operator can retry.
		m.mu.Lock()
		if _, taken := m.plugins[name]; !taken {
			// Marked dead: the instance is closed and the worker stopped,
			// so nothing about it is running. It is back in the registry
			// only so the operator can see the state it could not remove
			// and retry the removal.
			p.dead = true
			m.plugins[name] = p
		}
		m.mu.Unlock()
		return fmt.Errorf("cplane: flush plugin %q: %w", name, err)
	}

	if m.claims != nil {
		// The claim goes, but the routes are not handed to the built-in
		// appliers. Nothing here can implement the behavior the plugin
		// implemented: to the built-in a private codepoint is just a
		// service SID, and installing it as one is the wrong-meaning
		// install the claim existed to prevent. Those routes stop being
		// forwarded, which is the honest outcome of removing the only
		// thing that understood them, and they will be picked up with
		// built-in semantics only if their originator readvertises.
		m.claims.Release(name)
	}
	if err := m.store.Remove(name); err != nil {
		m.logger.Warn("could not remove a plugin from the store; a restart would bring it back",
			zap.String("plugin", name), zap.Error(err))
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

	// The ops outlive the instance -- the owner tag and the state under it
	// belong to the registration -- but two things do not, and this is
	// where they are reset.
	//
	// The record of which SID addresses the plugin has been told is one:
	// the replacement knows nothing, and suppressing the notification
	// because its predecessor had it would leave it holding SIDs it cannot
	// advertise. Publication is the other: what the replacement declares
	// from configure is held until it is running, so an instantiation that
	// fails halfway cannot prune the state its predecessor left behind on
	// its way out.
	p.ops.BeginInstance()

	ctx := context.Background()
	inst, err := wasm.Instantiate(ctx, wasm.Config{
		NowMonotonic: m.nowMonotonic,
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
	// network looks like before anything it declares is applied. Its
	// declarations stay held until then: the queue still holds events
	// meant for the instance that died, and a set built from those alone
	// would prune everything else this plugin owns before the replay could
	// restate it.
	//
	// It runs on a goroutine of its own because this is the worker
	// goroutine: the snapshot is delivered through the same queue and
	// would deadlock against itself.
	go func() {
		m.snapshot(p)
		if m.snapshots == nil {
			m.publish(p, inst)
		}
	}()
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
	if current := m.plugins[p.name]; current != p || p.dead {
		m.mu.Unlock()
		return
	}
	if p.snapshotting {
		// One is already running. Ask for another afterwards rather than
		// starting a second alongside it.
		m.mu.Unlock()
		p.worker.owe()
		return
	}
	p.snapshotting = true
	inst := p.inst
	m.mu.Unlock()
	// Live events are held until this finishes, so the snapshot arrives as
	// an uninterrupted prefix rather than interleaved with updates that
	// supersede parts of it.
	epoch := p.worker.beginSnapshot()
	// Only worker callbacks touch replayOK. The publication barrier follows
	// both the EOR and all held live events, so an incomplete drain cannot
	// prune inherited state through an earlier EOR completion.
	replayOK := false
	defer func() {
		p.worker.endSnapshot()
		p.worker.submitBarrier(func() {
			if replayOK && p.worker.snapshotCurrent(epoch) {
				m.publish(p, inst)
			}
		})
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
	// The reset goes first. What follows is the whole of the source, so
	// anything the plugin still holds from before is either restated here
	// or was withdrawn while it was not listening -- and a replay cannot
	// tell it about the second kind.
	p.worker.submitBlocking(m.startOfReplayBatch(ReplaySourceBGP))
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
	p.worker.submitCompletion(m.endOfReplayBatch(ReplaySourceBGP), func() {
		replayOK = true
	})
	p.counters.addSnapshot()
	m.logger.Info("replayed the rib to a plugin",
		zap.String("plugin", p.name), zap.Int("routes", count))
}

// publish is called on the worker after its replay barrier. An end marker
// queued for a failed instance must never publish its replacement's state.
func (m *Manager) publish(p *plugin, inst *wasm.Instance) {
	m.mu.Lock()
	live := m.plugins[p.name] == p && p.inst == inst && !p.dead
	m.mu.Unlock()
	if !live {
		return
	}
	if err := p.ops.Publish(); err != nil {
		m.logger.Warn("applying what a plugin declared before replay completed",
			zap.String("plugin", p.name), zap.Error(err))
	}
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
		return fmt.Errorf("cplane: %w: %q", ErrPluginNotRegistered, name)
	}
	if m.snapshots == nil {
		return fmt.Errorf("cplane: the event source serves no snapshot")
	}
	p.worker.submitBlocking(m.startOfReplayBatch(ReplaySourceBGP))
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
	return inst.Tick(context.Background(), m.nowMonotonic())
}

func (m *Manager) nowMonotonic() int64 { return int64(time.Since(m.started)) }

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
// startOfReplayBatch tells a plugin to discard what it knows from one
// source, because a full replay of it follows.
func (m *Manager) startOfReplayBatch(source string) *v1.PluginEventBatch {
	return &v1.PluginEventBatch{Events: []*v1.PluginEvent{{
		Kind:         v1.PluginEventKind_PLUGIN_EVENT_KIND_START_OF_REPLAY,
		Sequence:     m.seq.Add(1),
		ReplaySource: source,
	}}}
}

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
// It reports whether the batch was queued. A dropped one is not repaired
// by a later snapshot -- the rib replays routes, not SID allocations -- so
// the caller has to know not to record these as delivered.
func (m *Manager) deliverLocalSIDs(p *plugin, sids []AllocatedSID) bool {
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
		return true
	}
	// Queued without blocking: this runs inside the guest call that
	// declared the set, and waiting on the queue the same worker drains
	// would deadlock.
	return p.worker.submit(&v1.PluginEventBatch{Events: events})
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
