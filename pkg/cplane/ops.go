package cplane

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// PluginOps is the capability surface behind one plugin's host functions.
//
// It is built per plugin and closed over that plugin's owner tag, so the
// identity a write is attributed to is fixed when the plugin is
// registered. A plugin cannot name an owner in a call, which is what keeps
// one plugin from writing as another.
type PluginOps struct {
	owner       bpf.OwnerTag
	headend     HeadendMapOps
	leases      *Leases
	advertise   *AdvertiseSet
	localSIDs   *LocalSIDSet
	onLocalSIDs func([]AllocatedSID)
	defaultSrc  netip.Addr
	logger      *zap.Logger
	// applyMu is shared by every plugin under one manager, and is held for
	// the whole of a reconcile.
	//
	// A reconcile is a read-then-write sequence: it lists the map to work
	// out what this owner holds, diffs, and writes. Two plugins doing that
	// at once would have one of them list a map the other is halfway
	// through changing. Leases keep them off each other's keys, but not
	// out of each other's view of the map, and commits are rare enough
	// that serializing them costs nothing worth measuring.
	applyMu *sync.Mutex

	mu sync.Mutex
	// open holds the transactions the plugin has begun but not finished.
	open map[uint64]*applyTxn
	// nextGen numbers transactions. It never restarts within an instance,
	// so a stale generation from before a re-instantiation cannot be
	// mistaken for a live one.
	nextGen uint64
	// maxOpen caps concurrent transactions so a plugin that begins without
	// ever committing cannot grow the host's memory without bound.
	maxOpen int
	// maxEntries caps how much one transaction may accumulate.
	maxEntries int
	// staged holds commits made before the plugin is published.
	//
	// A plugin may declare state from configure, which runs during
	// instantiation. Applying it there would be wrong twice over: an
	// instantiation that then fails would leave state behind that no
	// registered plugin can remove, and on an upgrade the failed new
	// instance shares its owner tag with the old one that is still
	// running, so its declaration would prune the live plugin's entries.
	// So commits are held until the manager publishes the plugin, and
	// discarded if it never does.
	staged    []*applyTxn
	published bool
}

// applyTxn is one open desired-set declaration.
type applyTxn struct {
	kind    v1.PluginApplyKind
	entries []HeadendDesired
	routes  []AdvertisedRoute
	sids    []LocalSID
}

// PluginOpsConfig builds a PluginOps.
type PluginOpsConfig struct {
	// Owner is the tag every write by this plugin carries.
	Owner bpf.OwnerTag
	// Headend is the map surface the plugin's declarations reconcile into.
	Headend HeadendMapOps
	// Leases arbitrates keys across owners.
	Leases *Leases
	// Advertise is the send side. Nil leaves a plugin unable to originate,
	// which is what a daemon without BGP can honestly offer.
	Advertise *AdvertiseSet
	// LocalSIDs allocates the SIDs a plugin points at its data-plane half.
	LocalSIDs *LocalSIDSet
	// OnLocalSIDs is called with what a local-SID declaration resolved to,
	// so the plugin can be told the addresses it was given.
	OnLocalSIDs func([]AllocatedSID)
	// DefaultEncapSource fills in a declared entry that names no source.
	DefaultEncapSource netip.Addr
	// Logger receives the plugin's own log lines.
	Logger *zap.Logger
	// MaxOpenTransactions and MaxEntriesPerTransaction bound what one
	// plugin can accumulate; zero takes a default.
	MaxOpenTransactions      int
	MaxEntriesPerTransaction int
	// ApplyMutex serializes reconciles across the plugins that share a
	// data plane. Nil gives this plugin one of its own, which is only
	// right when it is the sole writer.
	ApplyMutex *sync.Mutex
}

// NewPluginOps builds the capability surface for one plugin.
func NewPluginOps(cfg PluginOpsConfig) (*PluginOps, error) {
	if cfg.Owner == "" {
		return nil, bpf.ErrEmptyOwner
	}
	if cfg.Headend == nil {
		return nil, fmt.Errorf("plugin ops: nil headend map ops")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	maxOpen := cfg.MaxOpenTransactions
	if maxOpen <= 0 {
		maxOpen = 4
	}
	maxEntries := cfg.MaxEntriesPerTransaction
	if maxEntries <= 0 {
		maxEntries = 4096
	}
	applyMu := cfg.ApplyMutex
	if applyMu == nil {
		applyMu = &sync.Mutex{}
	}
	return &PluginOps{
		owner:       cfg.Owner,
		applyMu:     applyMu,
		advertise:   cfg.Advertise,
		localSIDs:   cfg.LocalSIDs,
		onLocalSIDs: cfg.OnLocalSIDs,
		headend:     cfg.Headend,
		leases:      cfg.Leases,
		defaultSrc:  cfg.DefaultEncapSource,
		logger:      logger,
		open:        make(map[uint64]*applyTxn),
		maxOpen:     maxOpen,
		maxEntries:  maxEntries,
	}, nil
}

// Owner is the tag this plugin's writes carry.
func (p *PluginOps) Owner() bpf.OwnerTag { return p.owner }

// Log records a message the plugin emitted. Levels outside the known range
// are treated as info: a plugin that miscounts its log levels should not
// lose the message.
func (p *PluginOps) Log(level int32, msg string) {
	switch level {
	case 0:
		p.logger.Debug(msg)
	case 2:
		p.logger.Warn(msg)
	case 3:
		p.logger.Error(msg)
	default:
		p.logger.Info(msg)
	}
}

// ApplyBegin opens a desired-set transaction.
func (p *PluginOps) ApplyBegin(kind uint32) (uint64, error) {
	applyKind := v1.PluginApplyKind(kind)
	switch applyKind {
	case v1.PluginApplyKind_PLUGIN_APPLY_KIND_HEADEND_V4,
		v1.PluginApplyKind_PLUGIN_APPLY_KIND_HEADEND_V6:
	case v1.PluginApplyKind_PLUGIN_APPLY_KIND_ADVERTISE:
		if p.advertise == nil {
			return 0, fmt.Errorf("apply begin: this daemon cannot originate routes")
		}
	case v1.PluginApplyKind_PLUGIN_APPLY_KIND_LOCAL_SID:
		if p.localSIDs == nil {
			return 0, fmt.Errorf("apply begin: this daemon cannot allocate SIDs")
		}
	default:
		return 0, fmt.Errorf("apply begin: unknown kind %d", kind)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.open) >= p.maxOpen {
		return 0, fmt.Errorf("apply begin: %d transactions already open, limit %d", len(p.open), p.maxOpen)
	}
	p.nextGen++
	gen := p.nextGen
	p.open[gen] = &applyTxn{kind: applyKind}
	return gen, nil
}

// ApplyPut accumulates a chunk into an open transaction. Nothing reaches
// the data plane here: a chunk that arrives and is then followed by a trap
// must leave no trace.
func (p *PluginOps) ApplyPut(generation uint64, chunk []byte) error {
	var msg v1.PluginApplyChunk
	if err := proto.Unmarshal(chunk, &msg); err != nil {
		return fmt.Errorf("apply put: decode chunk: %w", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	txn, ok := p.open[generation]
	if !ok {
		return fmt.Errorf("apply put: no open transaction %d", generation)
	}
	declared := len(msg.GetHeadendEntries()) + len(msg.GetAdvertisedRoutes()) + len(msg.GetLocalSids())
	if len(txn.entries)+len(txn.routes)+len(txn.sids)+declared > p.maxEntries {
		return fmt.Errorf("apply put: transaction %d would hold %d entries, limit %d",
			generation, len(txn.entries)+len(txn.routes)+len(txn.sids)+declared, p.maxEntries)
	}
	for _, e := range msg.GetHeadendEntries() {
		prefix, entry, err := DecodeHeadendEntry(e, p.defaultSrc)
		if err != nil {
			return fmt.Errorf("apply put: %w", err)
		}
		txn.entries = append(txn.entries, HeadendDesired{TriggerPrefix: prefix, Entry: entry})
	}
	for _, r := range msg.GetAdvertisedRoutes() {
		route, err := DecodeAdvertisedRoute(r)
		if err != nil {
			return fmt.Errorf("apply put: %w", err)
		}
		txn.routes = append(txn.routes, route)
	}
	for _, s := range msg.GetLocalSids() {
		sid, err := DecodeLocalSID(s)
		if err != nil {
			return fmt.Errorf("apply put: %w", err)
		}
		txn.sids = append(txn.sids, sid)
	}
	return nil
}

// Publish applies whatever the plugin declared before it was registered,
// and lets later commits through directly.
//
// The manager calls it once the plugin is live. Until then a declaration
// is only recorded: see the staged field.
func (p *PluginOps) Publish() error {
	p.mu.Lock()
	if p.published {
		p.mu.Unlock()
		return nil
	}
	p.published = true
	staged := p.staged
	p.staged = nil
	p.mu.Unlock()

	for _, txn := range staged {
		if err := p.applyTransaction(txn); err != nil {
			return err
		}
	}
	return nil
}

// ApplyCommit reconciles what the transaction accumulated. This is the
// only point at which a plugin's declaration reaches the data plane.
//
// The transaction is closed whatever the outcome: a failed commit leaves
// the plugin to declare the set again rather than to retry a
// half-consumed one, which is the same convergence path a restart takes.
func (p *PluginOps) ApplyCommit(generation uint64) error {
	p.mu.Lock()
	txn, ok := p.open[generation]
	if ok {
		delete(p.open, generation)
	}
	published := p.published
	if ok && !published {
		// Declared before the plugin is live: hold it rather than apply
		// it, so an instantiation that fails leaves nothing behind.
		p.staged = append(p.staged, txn)
	}
	p.mu.Unlock()
	if !ok {
		return fmt.Errorf("apply commit: no open transaction %d", generation)
	}
	if !published {
		return nil
	}
	return p.applyTransaction(txn)
}

// applyTransaction is the reconcile itself, shared by a live commit and by
// one replayed at publication.
func (p *PluginOps) applyTransaction(txn *applyTxn) error {
	if txn.kind == v1.PluginApplyKind_PLUGIN_APPLY_KIND_LOCAL_SID {
		p.applyMu.Lock()
		allocated, res, err := p.localSIDs.Apply(p.owner, txn.sids)
		p.applyMu.Unlock()
		if err != nil {
			return fmt.Errorf("apply commit: %w", err)
		}
		p.logger.Info("plugin local SID set applied",
			zap.Int("declared", len(txn.sids)),
			zap.Int("allocated", res.Created),
			zap.Int("kept", res.Updated),
			zap.Int("released", res.Pruned))
		// The plugin picked the names; the host picked the addresses. It
		// cannot advertise what it has not been told.
		if p.onLocalSIDs != nil && len(allocated) > 0 {
			p.onLocalSIDs(allocated)
		}
		return nil
	}

	if txn.kind == v1.PluginApplyKind_PLUGIN_APPLY_KIND_ADVERTISE {
		p.applyMu.Lock()
		res, err := p.advertise.Apply(context.Background(), p.owner, txn.routes)
		p.applyMu.Unlock()
		if err != nil {
			return fmt.Errorf("apply commit: %w", err)
		}
		p.logger.Info("plugin advertisement set applied",
			zap.Int("declared", len(txn.routes)),
			zap.Int("created", res.Created),
			zap.Int("updated", res.Updated),
			zap.Int("withdrawn", res.Pruned))
		return nil
	}

	af := AFv4
	if txn.kind == v1.PluginApplyKind_PLUGIN_APPLY_KIND_HEADEND_V6 {
		af = AFv6
	}
	p.applyMu.Lock()
	res, err := ApplyHeadendSet(p.headend, p.leases, p.owner, af, txn.entries)
	p.applyMu.Unlock()
	if err != nil {
		return fmt.Errorf("apply commit: %w", err)
	}
	p.logger.Info("plugin desired set applied",
		zap.String("family", af.String()),
		zap.Int("declared", len(txn.entries)),
		zap.Int("created", res.Created),
		zap.Int("updated", res.Updated),
		zap.Int("pruned", res.Pruned))
	return nil
}

// ApplyAbort discards an open transaction.
func (p *PluginOps) ApplyAbort(generation uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.open, generation)
}

// OpenTransactions is how many declarations the plugin has begun and not
// finished, for tests and diagnostics.
func (p *PluginOps) OpenTransactions() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.open)
}

// DiscardTransactions drops every open transaction. The instance running
// them is gone -- it trapped, or its budget ran out -- so what they
// accumulated describes a declaration nobody will finish.
func (p *PluginOps) DiscardTransactions() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.open = make(map[uint64]*applyTxn)
}

// Flush removes every entry this plugin owns and releases its leases. It
// is what unregistering runs, and it is deliberately not what a trap runs:
// a plugin that dies is restarted and re-declares, so flushing there would
// blackhole traffic for the length of a restart.
func (p *PluginOps) Flush() error {
	p.applyMu.Lock()
	defer p.applyMu.Unlock()
	var firstErr error
	if p.advertise != nil {
		// Withdraw before removing the data plane behind it: a route left
		// advertised for state that is gone is a blackhole its peers keep
		// sending into.
		if err := p.advertise.WithdrawOwner(context.Background(), p.owner); err != nil {
			firstErr = err
		}
	}
	if p.localSIDs != nil {
		if err := p.localSIDs.ReleaseOwner(p.owner); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, af := range []AddressFamily{AFv4, AFv6} {
		if _, err := PruneHeadendOwner(p.headend, p.leases, p.owner, af); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if p.leases != nil {
		p.leases.ReleaseOwner(p.owner)
	}
	return firstErr
}
