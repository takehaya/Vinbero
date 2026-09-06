// Package cplaneharness runs a control-plane plugin without a daemon.
//
// A plugin author otherwise has to deploy into a live vinberod with BGP
// peers to find out whether their module works at all, and the failures
// that matter most -- a runtime that traps before it is initialized, a
// declaration the host refuses, a module that dies on one poisoned event
// -- are exactly the ones that are painful to reproduce that way.
//
// So this drives the same runtime the daemon uses, with a recording stand
// -in for the capability surface. What a plugin declares comes back as
// ordinary Go values to assert on, and the sequences a plugin has to
// survive in production (a replay, a restart, a refused commit) are
// methods here rather than situations to engineer.
package cplaneharness

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/cplane"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
)

// Declaration is one desired set a plugin committed. Which field is
// populated follows from Kind.
type Declaration struct {
	// Kind says which set was declared.
	Kind v1.PluginApplyKind
	// Entries are the headend entries the plugin asked for, in the order
	// it declared them.
	Entries []*v1.PluginHeadendEntry
	// Routes are the routes it asked to have originated.
	Routes []*v1.PluginAdvertisedRoute
	// LocalSIDs are the SIDs it asked the host to allocate.
	LocalSIDs []*v1.PluginLocalSid
}

// Harness runs one plugin instance.
type Harness struct {
	tb     testing.TB
	module []byte
	config []byte
	limits wasm.Limits
	caps   wasm.Capabilities
	now    atomic.Int64

	mu sync.Mutex
	// inst is replaced by Restart, so a test can check that a plugin
	// converges after losing its memory.
	inst *wasm.Instance
	ops  *recorder
	seq  uint64
}

// Options configure a harness.
type Options struct {
	// Config is the operator config blob handed to the plugin.
	Config []byte
	// Limits bound the instance; zero fields take the runtime's defaults.
	Limits wasm.Limits
	// DenyCommits makes every commit fail as though another owner held a
	// declared key, so a test can check what the plugin does when the host
	// refuses it.
	DenyCommits bool
	// Capabilities are what the plugin is granted. Empty grants everything
	// the host defines, which is what a plugin author testing their own
	// module wants by default; narrow it to check that a plugin degrades
	// the way it should when an operator grants it less.
	Capabilities []string
	// Scope is where those capabilities may be exercised, as the
	// registration will state it. It is given in the operator-facing form
	// -- the same strings the CLI and the wire carry -- and parsed through
	// ParseScope, so a scope the daemon would refuse (a 4-in-6 prefix, a
	// slot outside the plugin range) is refused here too. Taking a raw
	// cplane.Scope would let a plugin pass conformance under a scope that
	// cannot be registered, which is the divergence this harness exists to
	// close.
	//
	// The zero value skips the check rather than denying everything, which
	// is the one place this harness is deliberately more forgiving than
	// the daemon: the scope is the operator's decision and a plugin author
	// writing a module does not always know it yet. A daemon registration
	// with no scope refuses every declaration, so a plugin that is meant
	// to write anything should be exercised here with the scope it will be
	// given.
	//
	// The parts that need a running daemon -- whether a locator actually
	// contains a prefix, whether a VRF has a binding -- stay the daemon's
	// either way.
	Scope cplane.ScopeSpec
}

// New starts a plugin from a compiled module. It fails the test if the
// module does not pass admission, which is the check most plugin bugs show
// up in first.
func New(tb testing.TB, module []byte, opts Options) *Harness {
	tb.Helper()
	caps, err := capabilitiesFor(opts.Capabilities)
	if err != nil {
		tb.Fatalf("capabilities: %v", err)
	}
	scope, err := cplane.ParseScope(opts.Scope)
	if err != nil {
		tb.Fatalf("scope: %v", err)
	}
	// The scope must cover the capabilities, the same check the daemon's
	// Register makes: a plugin whose non-empty scope names nothing a granted
	// capability can act on would start here but be refused in production. The
	// check itself exempts the empty scope (the startable deny-all case), so
	// this is unconditional.
	if err := cplane.ScopeCoversCapabilities(caps, scope); err != nil {
		tb.Fatalf("scope does not cover the capabilities: %v", err)
	}
	h := &Harness{tb: tb, module: module, config: opts.Config, limits: opts.Limits, caps: caps}
	// The recorder is given the same capabilities as the instance, because
	// the daemon checks the declaration kind against them when a
	// transaction is opened. Without that here, a plugin granted only
	// advertise could open a headend transaction, pass conformance, and
	// be refused in production.
	h.ops = &recorder{denyCommits: opts.DenyCommits, caps: caps, scope: scope}
	inst, err := wasm.Instantiate(context.Background(), wasm.Config{
		NowMonotonic: h.now.Load,
		Name:         "harness",
		Module:       module,
		ConfigBlob:   opts.Config,
		Limits:       opts.Limits,
		Ops:          h.ops,
		Capabilities: caps,
		Logger:       zap.NewNop(),
	})
	if err != nil {
		tb.Fatalf("plugin was refused: %v", err)
	}
	h.inst = inst
	tb.Cleanup(func() { _ = inst.Close(context.Background()) })
	// A plugin may declare local SIDs from configure. Answer those before
	// the test does anything else, as the daemon does once the plugin is
	// live.
	if err := h.flushAllocated(); err != nil {
		tb.Fatalf("plugin declared local SIDs during configure: %v", err)
	}
	return h
}

// Deliver hands the plugin a batch of events and returns what it reported.
func (h *Harness) Deliver(events ...*v1.PluginEvent) (*v1.PluginEventStatus, error) {
	h.tb.Helper()
	h.mu.Lock()
	for _, ev := range events {
		if ev.GetSequence() == 0 {
			h.seq++
			ev.Sequence = h.seq
		}
	}
	inst := h.inst
	h.mu.Unlock()

	raw, err := proto.Marshal(&v1.PluginEventBatch{Events: events})
	if err != nil {
		return nil, fmt.Errorf("encode batch: %w", err)
	}
	out, err := inst.HandleEvents(context.Background(), raw)
	if err != nil {
		return nil, err
	}
	if err := h.flushAllocated(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return &v1.PluginEventStatus{}, nil
	}
	var status v1.PluginEventStatus
	if err := proto.Unmarshal(out, &status); err != nil {
		return nil, fmt.Errorf("plugin returned an undecodable status: %w", err)
	}
	return &status, nil
}

// flushAllocated delivers the addresses the host chose for local SIDs the
// plugin declared, as an event, which is how the daemon answers too.
func (h *Harness) flushAllocated() error {
	for {
		allocated := h.ops.takeAllocated()
		if len(allocated) == 0 {
			return nil
		}
		events := make([]*v1.PluginEvent, 0, len(allocated))
		for _, a := range allocated {
			h.mu.Lock()
			h.seq++
			seq := h.seq
			inst := h.inst
			h.mu.Unlock()
			events = append(events, &v1.PluginEvent{
				Kind:     v1.PluginEventKind_PLUGIN_EVENT_KIND_LOCAL_SID,
				Sequence: seq,
				LocalSid: a,
			})
			_ = inst
		}
		raw, err := proto.Marshal(&v1.PluginEventBatch{Events: events})
		if err != nil {
			return fmt.Errorf("encode local-SID batch: %w", err)
		}
		h.mu.Lock()
		inst := h.inst
		h.mu.Unlock()
		if _, err := inst.HandleEvents(context.Background(), raw); err != nil {
			return fmt.Errorf("delivering local-SID answers: %w", err)
		}
	}
}

// Route is shorthand for delivering one route event.
func (h *Harness) Route(route *v1.PluginRoute) (*v1.PluginEventStatus, error) {
	return h.Deliver(&v1.PluginEvent{
		Kind:  v1.PluginEventKind_PLUGIN_EVENT_KIND_ROUTE,
		Route: route,
	})
}

// Tick invokes the plugin's periodic callback.
func (h *Harness) Tick(elapsed time.Duration) error {
	h.now.Store(int64(elapsed))
	h.mu.Lock()
	inst := h.inst
	h.mu.Unlock()
	if err := inst.Tick(context.Background(), int64(elapsed)); err != nil {
		return err
	}
	return h.flushAllocated()
}

// SetDenyCommits changes the simulated refusal without replacing the instance,
// so a test can verify recovery when a transient conflict disappears.
func (h *Harness) SetDenyCommits(deny bool) {
	h.ops.mu.Lock()
	defer h.ops.mu.Unlock()
	h.ops.denyCommits = deny
}

// Restart replaces the instance with a fresh one, as the daemon does after
// a plugin traps or overruns its budget.
//
// It is the sequence worth testing most: the new instance has no memory of
// anything, so whatever the plugin declares afterwards has to come from
// the events it is replayed. A plugin that quietly depends on state from
// before the restart passes every other test and fails here.
func (h *Harness) Restart() {
	h.tb.Helper()
	h.mu.Lock()
	old := h.inst
	h.mu.Unlock()

	// The addresses it holds survive the restart; being told about them
	// does not, which is what the daemon does when it replaces an
	// instance.
	h.ops.beginInstance()

	inst, err := wasm.Instantiate(context.Background(), wasm.Config{
		NowMonotonic: h.now.Load,
		Name:         "harness",
		Capabilities: h.caps,
		Module:       h.module,
		// The config goes back in: the daemon re-instantiates with it too,
		// and a harness that dropped it would model a restart the daemon
		// never performs -- a plugin coming back on defaults, or refusing
		// an empty blob it never received the first time.
		ConfigBlob: h.config,
		Limits:     h.limits,
		Ops:        h.ops,
		Logger:     zap.NewNop(),
	})
	if err != nil {
		h.tb.Fatalf("plugin could not be restarted: %v", err)
	}
	_ = old.Close(context.Background())

	h.mu.Lock()
	h.inst = inst
	h.mu.Unlock()
	h.tb.Cleanup(func() { _ = inst.Close(context.Background()) })
	if err := h.flushAllocated(); err != nil {
		h.tb.Fatalf("plugin declared local SIDs during configure: %v", err)
	}
}

// Reconfigure replaces the instance with new configuration while retaining its
// owner state and grants, as a same-name module upgrade does.
func (h *Harness) Reconfigure(config []byte) {
	h.config = append([]byte(nil), config...)
	h.Restart()
}

// Declarations returns every set the plugin has committed, oldest first.
func (h *Harness) Declarations() []Declaration {
	return h.ops.declarations()
}

// LastDeclaration returns the most recent committed set, and whether there
// was one.
func (h *Harness) LastDeclaration() (Declaration, bool) {
	all := h.ops.declarations()
	if len(all) == 0 {
		return Declaration{}, false
	}
	return all[len(all)-1], true
}

// Logs returns the lines the plugin wrote through the log host function.
func (h *Harness) Logs() []string { return h.ops.logLines() }

// Aborted is how many transactions the plugin opened and then abandoned.
// A plugin that aborts when the host refuses a chunk is behaving well; one
// that leaves transactions open is leaking them.
func (h *Harness) Aborted() int { return h.ops.abortCount() }

// capabilitiesFor turns the option into a granted set, defaulting to
// everything the host defines.
func capabilitiesFor(names []string) (wasm.Capabilities, error) {
	if len(names) == 0 {
		return wasm.ParseCapabilities([]string{
			string(wasm.CapHeadend), string(wasm.CapAdvertise), string(wasm.CapLocalSID),
		})
	}
	return wasm.ParseCapabilities(names)
}

// recorder stands in for the daemon's capability surface, keeping what the
// plugin asked for instead of applying it.
type recorder struct {
	denyCommits bool

	mu        sync.Mutex
	logs      []string
	open      map[uint64]*v1.PluginApplyChunk
	openKinds map[uint64]v1.PluginApplyKind
	committed []Declaration
	aborts    int
	nextGen   uint64
	// allocated holds the local-SID answers a commit produced, waiting to
	// be handed to the plugin.
	allocated []*v1.PluginLocalSidAllocated
	// sidByName is the address each declared name holds, so a name keeps
	// the address it was given. The daemon answers a redeclaration with the
	// address it already allocated; a harness that handed out a new one
	// every time would let a plugin pass here and then, against the real
	// daemon, advertise an address that had moved under it.
	sidByName map[string]string
	// sidDeclarations tracks the locator associated with each live address.
	// Moving a name to another locator requires a new allocation, as on the host.
	sidDeclarations map[string]*v1.PluginLocalSid
	// notifiedSIDs is which allocations the running instance has been told
	// about. The addresses outlive an instance; being told does not. The
	// daemon resets this when it replaces an instance, so a harness that
	// carried it over would let a plugin that cannot re-advertise after a
	// restart pass -- which is the failure this harness exists to catch.
	notifiedSIDs map[string]struct{}
	nextSID      int
	caps         wasm.Capabilities
	scope        cplane.Scope
}

// beginInstance puts the recorder back into the state a fresh instance
// starts from, matching the daemon.
func (r *recorder) beginInstance() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.notifiedSIDs = nil
}

func (r *recorder) Log(level int32, msg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logs = append(r.logs, fmt.Sprintf("%d: %s", level, msg))
}

func (r *recorder) ApplyBegin(kind uint32) (uint64, error) {
	applyKind := v1.PluginApplyKind(kind)
	// One apply_begin serves every kind, so the capability that covers the
	// kind is checked here -- exactly as the daemon does, or a plugin
	// declaring something it was not granted passes conformance and is
	// refused in production.
	switch applyKind {
	case v1.PluginApplyKind_PLUGIN_APPLY_KIND_HEADEND_V4,
		v1.PluginApplyKind_PLUGIN_APPLY_KIND_HEADEND_V6:
		if !r.caps.Has(wasm.CapHeadend) {
			return 0, fmt.Errorf("apply begin: plugin was not granted the %q capability", wasm.CapHeadend)
		}
	case v1.PluginApplyKind_PLUGIN_APPLY_KIND_ADVERTISE:
		if !r.caps.Has(wasm.CapAdvertise) {
			return 0, fmt.Errorf("apply begin: plugin was not granted the %q capability", wasm.CapAdvertise)
		}
	case v1.PluginApplyKind_PLUGIN_APPLY_KIND_LOCAL_SID:
		if !r.caps.Has(wasm.CapLocalSID) {
			return 0, fmt.Errorf("apply begin: plugin was not granted the %q capability", wasm.CapLocalSID)
		}
	default:
		return 0, fmt.Errorf("unknown apply kind %d", kind)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.open == nil {
		r.open = map[uint64]*v1.PluginApplyChunk{}
		r.openKinds = map[uint64]v1.PluginApplyKind{}
	}
	r.nextGen++
	r.open[r.nextGen] = &v1.PluginApplyChunk{}
	r.openKinds[r.nextGen] = applyKind
	return r.nextGen, nil
}

func (r *recorder) ApplyPut(generation uint64, chunk []byte) error {
	var msg v1.PluginApplyChunk
	if err := proto.Unmarshal(chunk, &msg); err != nil {
		return fmt.Errorf("undecodable chunk: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	acc, ok := r.open[generation]
	if !ok {
		return fmt.Errorf("no open transaction %d", generation)
	}
	// The daemon's own checks, not a second copy of them. What a plugin
	// declares is refused here for the same reasons and with the same
	// words it would be refused in production -- a missing next hop, a
	// mode with nothing behind it, a prefix in the wrong family. A harness
	// more forgiving than the daemon passes plugins that then go silent,
	// which is the one thing it exists to prevent.
	kind := r.openKinds[generation]
	validate := cplane.ValidateChunk
	if !r.scope.Empty() {
		validate = func(k v1.PluginApplyKind, m *v1.PluginApplyChunk) error {
			return cplane.ValidateChunkInScope(k, m, r.scope)
		}
	}
	if err := validate(kind, &msg); err != nil {
		return err
	}
	acc.HeadendEntries = append(acc.HeadendEntries, msg.GetHeadendEntries()...)
	acc.AdvertisedRoutes = append(acc.AdvertisedRoutes, msg.GetAdvertisedRoutes()...)
	acc.LocalSids = append(acc.LocalSids, msg.GetLocalSids()...)
	return nil
}

func (r *recorder) ApplyCommit(generation uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	acc, ok := r.open[generation]
	if !ok {
		return fmt.Errorf("no open transaction %d", generation)
	}
	delete(r.open, generation)
	kind := r.openKinds[generation]
	delete(r.openKinds, generation)
	if r.denyCommits {
		return deniedError{}
	}
	decl := Declaration{
		Kind:      kind,
		Entries:   acc.GetHeadendEntries(),
		Routes:    acc.GetAdvertisedRoutes(),
		LocalSIDs: acc.GetLocalSids(),
	}
	r.committed = append(r.committed, decl)

	// A declared local SID is answered with an address, as the daemon
	// does: the plugin named it, the host chose the value, and a plugin
	// that is never told cannot advertise it. Without this the harness
	// could not exercise the half of a plugin that originates anything.
	if kind == v1.PluginApplyKind_PLUGIN_APPLY_KIND_LOCAL_SID {
		if r.sidByName == nil {
			r.sidByName = map[string]string{}
		}
		if r.sidDeclarations == nil {
			r.sidDeclarations = map[string]*v1.PluginLocalSid{}
		}
		// A declaration is the whole set, so a name it stopped naming has
		// been given up and its address goes back -- exactly as the daemon
		// releases a SID the owner no longer declares.
		declared := make(map[string]struct{}, len(acc.GetLocalSids()))
		for _, sid := range acc.GetLocalSids() {
			declared[sid.GetName()] = struct{}{}
		}
		for name := range r.sidByName {
			if _, still := declared[name]; !still {
				delete(r.sidByName, name)
				delete(r.sidDeclarations, name)
				delete(r.notifiedSIDs, name)
			}
		}
		// Only what this instance has not been told produces an event, as
		// the daemon does. A plugin that redeclares its set in response to
		// a local-SID event -- which the desired-set model invites --
		// would otherwise be answered with another event, redeclare again,
		// and never stop. A replacement instance has been told nothing, so
		// it hears every address it holds.
		if r.notifiedSIDs == nil {
			r.notifiedSIDs = map[string]struct{}{}
		}
		for _, sid := range acc.GetLocalSids() {
			name := sid.GetName()
			addr, held := r.sidByName[name]
			if !held || r.sidDeclarations[name].GetLocator() != sid.GetLocator() {
				r.nextSID++
				addr = fmt.Sprintf("fd00:%d::%d", 0xbb, r.nextSID)
				r.sidByName[name] = addr
				delete(r.notifiedSIDs, name)
			}
			r.sidDeclarations[name] = proto.Clone(sid).(*v1.PluginLocalSid)
			if _, told := r.notifiedSIDs[name]; told {
				continue
			}
			r.notifiedSIDs[name] = struct{}{}
			r.allocated = append(r.allocated, &v1.PluginLocalSidAllocated{
				Name:    name,
				Sid:     addr,
				Locator: sid.GetLocator(),
			})
		}
	}
	return nil
}

// takeAllocated returns the local-SID answers owed to the plugin.
func (r *recorder) takeAllocated() []*v1.PluginLocalSidAllocated {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.allocated
	r.allocated = nil
	return out
}

func (r *recorder) ApplyAbort(generation uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.open[generation]; ok {
		r.aborts++
	}
	delete(r.open, generation)
	delete(r.openKinds, generation)
}

func (r *recorder) declarations() []Declaration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Declaration(nil), r.committed...)
}

func (r *recorder) logLines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.logs...)
}

func (r *recorder) abortCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.aborts
}

// deniedError is a policy refusal, which the runtime distinguishes from a
// host failure by behavior rather than by identity.
type deniedError struct{}

func (deniedError) Error() string { return "denied: a key is held by another owner" }
func (deniedError) Denied() bool  { return true }
