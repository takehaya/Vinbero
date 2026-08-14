package cplane

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

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

// BehaviorClaims is the registry that records which SRv6 endpoint
// behaviors belong to a plugin. The demux's ClaimRegistry satisfies it.
type BehaviorClaims interface {
	Claim(plugin string, codepoints []uint16) error
	Release(plugin string)
}

// ErrAlreadyRegistered is returned when a name is taken. A plugin is
// replaced through Register with the same name, which is an upgrade; two
// different bundles cannot share one name.
var ErrAlreadyRegistered = errors.New("cplane: plugin already registered")

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
	// Limits bound the instance; zero fields take defaults.
	Limits wasm.Limits
}

// Manager owns the running control-plane plugins.
type Manager struct {
	source     EventSource
	claims     BehaviorClaims
	headend    HeadendMapOps
	leases     *Leases
	defaultSrc netip.Addr
	logger     *zap.Logger

	mu      sync.Mutex
	plugins map[string]*plugin
	seq     atomic.Uint64
}

// plugin is one registered and running module.
type plugin struct {
	name      string
	inst      *wasm.Instance
	ops       *PluginOps
	unsubscri func()
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
	// DefaultEncapSource fills in declared entries that name no source.
	DefaultEncapSource netip.Addr
	Logger             *zap.Logger
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
	return &Manager{
		source:     cfg.Source,
		claims:     cfg.Claims,
		headend:    cfg.Headend,
		leases:     NewLeases(),
		defaultSrc: cfg.DefaultEncapSource,
		logger:     logger,
		plugins:    make(map[string]*plugin),
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
	owner := bpf.OwnerPluginBundle(reg.Name)

	// Claim first: a behavior another plugin holds must stop the
	// registration before anything is instantiated.
	if len(reg.Behaviors) > 0 {
		if m.claims == nil {
			return fmt.Errorf("cplane: plugin %q claims behaviors but no claim registry is configured", reg.Name)
		}
		if err := m.claims.Claim(reg.Name, reg.Behaviors); err != nil {
			return err
		}
	}

	ops, err := NewPluginOps(PluginOpsConfig{
		Owner:              owner,
		Headend:            m.headend,
		Leases:             m.leases,
		DefaultEncapSource: m.defaultSrc,
		Logger:             m.logger.Named("plugin." + reg.Name),
	})
	if err != nil {
		return err
	}

	inst, err := wasm.Instantiate(ctx, wasm.Config{
		Name:       reg.Name,
		Module:     reg.Module,
		ConfigBlob: reg.Config,
		Limits:     reg.Limits,
		Ops:        ops,
		Logger:     m.logger,
	})
	if err != nil {
		if len(reg.Behaviors) > 0 && m.claims != nil {
			// The claim was taken for a plugin that never started.
			m.claims.Release(reg.Name)
		}
		return err
	}

	// Swap under the lock so two registrations of one name cannot both
	// think they won.
	m.mu.Lock()
	old, existed := m.plugins[reg.Name]
	m.plugins[reg.Name] = &plugin{name: reg.Name, inst: inst, ops: ops}
	m.mu.Unlock()

	if existed {
		// Stop the old instance without flushing: the new one inherits the
		// owner tag and re-declares over the same state.
		old.stopDelivery()
		if err := old.inst.Close(ctx); err != nil {
			m.logger.Warn("closing the replaced plugin instance",
				zap.String("plugin", reg.Name), zap.Error(err))
		}
		old.ops.DiscardTransactions()
	}

	if m.source != nil {
		cancel, err := m.source.Register(reg.Name, reg.Families, m.handlerFor(reg.Name))
		if err != nil {
			// Undo: the plugin cannot do its job without events.
			_ = m.Unregister(ctx, reg.Name)
			return fmt.Errorf("cplane: subscribe plugin %q: %w", reg.Name, err)
		}
		m.mu.Lock()
		if p, ok := m.plugins[reg.Name]; ok {
			p.unsubscri = cancel
		}
		m.mu.Unlock()
	}

	m.logger.Info("control-plane plugin registered",
		zap.String("plugin", reg.Name),
		zap.Bool("replaced", existed),
		zap.Int("behaviors", len(reg.Behaviors)))
	return nil
}

// Unregister stops a plugin and removes the state it owns.
//
// Unlike a trap, this is deliberate: the operator is taking the plugin
// away, so its entries go with it rather than being left for a restart to
// reclaim.
func (m *Manager) Unregister(ctx context.Context, name string) error {
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
	p.stopDelivery()
	if err := p.inst.Close(ctx); err != nil {
		m.logger.Warn("closing plugin instance", zap.String("plugin", name), zap.Error(err))
	}
	p.ops.DiscardTransactions()
	if m.claims != nil {
		m.claims.Release(name)
	}
	if err := p.ops.Flush(); err != nil {
		return fmt.Errorf("cplane: flush plugin %q: %w", name, err)
	}
	m.logger.Info("control-plane plugin unregistered", zap.String("plugin", name))
	return nil
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
		p.stopDelivery()
		if err := p.inst.Close(ctx); err != nil {
			m.logger.Warn("closing plugin instance", zap.String("plugin", p.name), zap.Error(err))
		}
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

// handlerFor builds the demux handler that carries route events to one
// plugin.
func (m *Manager) handlerFor(name string) bgp.RouteHandler {
	return func(ev bgp.RouteEvent) {
		m.mu.Lock()
		p, ok := m.plugins[name]
		m.mu.Unlock()
		if !ok {
			return
		}
		batch := &v1.PluginEventBatch{Events: []*v1.PluginEvent{{
			Kind:     v1.PluginEventKind_PLUGIN_EVENT_KIND_ROUTE,
			Sequence: m.seq.Add(1),
			Route:    EncodeRouteEvent(ev),
		}}}
		m.deliver(p, batch)
	}
}

// deliver hands a batch to a plugin and acts on what it reports.
//
// A failure here is the instance's problem, not the daemon's: the error is
// logged and the plugin's open transactions are discarded, so a
// half-declared set cannot be committed later by a call that thinks it is
// still in the same conversation.
func (m *Manager) deliver(p *plugin, batch *v1.PluginEventBatch) {
	raw, err := proto.Marshal(batch)
	if err != nil {
		m.logger.Error("encoding plugin event batch",
			zap.String("plugin", p.name), zap.Error(err))
		return
	}
	status, err := p.inst.HandleEvents(context.Background(), raw)
	if err != nil {
		p.ops.DiscardTransactions()
		m.logger.Warn("plugin failed to handle events",
			zap.String("plugin", p.name), zap.Error(err))
		return
	}
	if len(status) == 0 {
		return
	}
	var msg v1.PluginEventStatus
	if err := proto.Unmarshal(status, &msg); err != nil {
		m.logger.Warn("plugin returned an undecodable status",
			zap.String("plugin", p.name), zap.Error(err))
		return
	}
	for _, r := range msg.GetResults() {
		if r.GetDisposition() == v1.PluginEventDisposition_PLUGIN_EVENT_DISPOSITION_QUARANTINE {
			// The plugin declined this event on purpose. Recording it is
			// the whole value of having a polite refusal: the alternative
			// signal is a trap, which costs the instance and repeats.
			m.logger.Warn("plugin quarantined an event",
				zap.String("plugin", p.name),
				zap.Uint64("sequence", r.GetSequence()),
				zap.String("reason", r.GetReason()))
		}
	}
}

// stopDelivery detaches the plugin from the event source.
func (p *plugin) stopDelivery() {
	if p.unsubscri != nil {
		p.unsubscri()
		p.unsubscri = nil
	}
}
