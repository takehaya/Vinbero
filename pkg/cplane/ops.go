package cplane

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
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
	caps        wasm.Capabilities
	leases      *Leases
	advertise   *AdvertiseSet
	localSIDs   *LocalSIDSet
	quotas      Quotas
	onLocalSIDs func([]AllocatedSID) bool
	// notifiedSIDs remembers which allocations this instance has already
	// been told about, keyed by name and carrying the address it was given.
	notifiedSIDs map[string]netip.Addr
	encapSource  func() (netip.Addr, error)
	logger       *zap.Logger
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
	// maxEntries caps how many entries one transaction may accumulate, and
	// maxBytes caps how large they may be between them.
	maxEntries int
	maxBytes   int
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
	// pending holds the declaration of each kind that failed at
	// publication and is worth retrying, because what it depended on may
	// not have existed yet. One per kind: a newer declaration replaces the
	// one it supersedes rather than queueing behind it.
	pending map[v1.PluginApplyKind]*applyTxn
	// commits numbers transactions in commit order, and lastApplied is the
	// highest number reconciled for each kind. Together they stop an older
	// declaration from overwriting a newer one -- which a retry, or a
	// staged declaration draining alongside a live commit, would otherwise
	// do.
	commits     uint64
	lastApplied map[v1.PluginApplyKind]uint64
	// reportedPending remembers which kinds have already been reported as
	// stuck, so the log says it once instead of every retry.
	reportedPending map[v1.PluginApplyKind]struct{}
}

// applyTxn is one open desired-set declaration.
type applyTxn struct {
	kind v1.PluginApplyKind
	// seq is this transaction's position in commit order, stamped at
	// commit. A declaration is a statement about a whole set, so applying
	// an older one after a newer one of the same kind puts back a set the
	// plugin has already replaced -- which is what a retry, or a staged
	// declaration draining alongside a live commit, would otherwise do.
	seq uint64
	// bytes is what this transaction is holding, so the cap is on the
	// memory rather than only on the number of things in it.
	bytes   int
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
	// Capabilities are what this plugin was granted. The apply functions
	// are shared by every kind of declaration, so linking cannot separate
	// them: the kind is checked here instead.
	Capabilities wasm.Capabilities
	// Advertise is the send side. Nil leaves a plugin unable to originate,
	// which is what a daemon without BGP can honestly offer.
	Advertise *AdvertiseSet
	// LocalSIDs allocates the SIDs a plugin points at its data-plane half.
	LocalSIDs *LocalSIDSet
	// Quotas bound how much this plugin may hold. Zero fields take the
	// defaults.
	Quotas Quotas
	// OnLocalSIDs is called with what a local-SID declaration resolved to,
	// so the plugin can be told the addresses it was given.
	OnLocalSIDs func([]AllocatedSID) bool
	// EncapSource resolves the daemon's encap source for a declared entry
	// that names none.
	//
	// It is a function rather than a value because locators are registered
	// over RPC after the daemon starts: an address captured at startup is
	// usually the one that did not exist yet, and an entry written with a
	// zero source blackholes silently.
	EncapSource func() (netip.Addr, error)
	// Logger receives the plugin's own log lines.
	Logger *zap.Logger
	// MaxOpenTransactions, MaxEntriesPerTransaction and
	// MaxBytesPerTransaction bound what one plugin can accumulate; zero
	// takes a default.
	//
	// The byte cap exists because the entry count bounds nothing on its
	// own: the repeated and string fields inside an entry have no length
	// of their own, so a guest can respect every other limit and still
	// make the host hold gigabytes by never committing.
	MaxOpenTransactions      int
	MaxEntriesPerTransaction int
	MaxBytesPerTransaction   int
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
	// A transaction's memory is capped as well as its entry count. The
	// default is generous next to any real desired set -- a few thousand
	// routes with their attributes -- and small next to what an unbounded
	// one costs a daemon that must not be restarted to recover.
	maxBytes := cfg.MaxBytesPerTransaction
	if maxBytes <= 0 {
		maxBytes = 16 << 20
	}
	applyMu := cfg.ApplyMutex
	if applyMu == nil {
		applyMu = &sync.Mutex{}
	}
	return &PluginOps{
		owner:        cfg.Owner,
		applyMu:      applyMu,
		caps:         cfg.Capabilities,
		advertise:    cfg.Advertise,
		localSIDs:    cfg.LocalSIDs,
		quotas:       cfg.Quotas.withDefaults(),
		onLocalSIDs:  cfg.OnLocalSIDs,
		notifiedSIDs: make(map[string]netip.Addr),
		encapSource:  cfg.EncapSource,
		headend:      cfg.Headend,
		leases:       cfg.Leases,
		logger:       logger,
		open:         make(map[uint64]*applyTxn),
		maxOpen:      maxOpen,
		maxEntries:   maxEntries,
		maxBytes:     maxBytes,
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
	// The kind is checked against the granted capabilities here because
	// one apply_begin serves them all: a plugin granted only advertise
	// would otherwise open a headend transaction through the same door.
	switch applyKind {
	case v1.PluginApplyKind_PLUGIN_APPLY_KIND_HEADEND_V4,
		v1.PluginApplyKind_PLUGIN_APPLY_KIND_HEADEND_V6:
		if !p.caps.Has(wasm.CapHeadend) {
			return 0, fmt.Errorf("apply begin: plugin was not granted the %q capability", wasm.CapHeadend)
		}
	case v1.PluginApplyKind_PLUGIN_APPLY_KIND_ADVERTISE:
		if !p.caps.Has(wasm.CapAdvertise) {
			return 0, fmt.Errorf("apply begin: plugin was not granted the %q capability", wasm.CapAdvertise)
		}
		if p.advertise == nil {
			return 0, fmt.Errorf("apply begin: this daemon cannot originate routes")
		}
	case v1.PluginApplyKind_PLUGIN_APPLY_KIND_LOCAL_SID:
		if !p.caps.Has(wasm.CapLocalSID) {
			return 0, fmt.Errorf("apply begin: plugin was not granted the %q capability", wasm.CapLocalSID)
		}
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
	// Entries are counted, and so are the bytes inside them. A count alone
	// bounds nothing: the repeated and string fields of one entry have no
	// length of their own, so a guest can stay under both the entry limit
	// and the per-chunk buffer limit and still make the host hold gigabytes
	// -- by never committing, which is also why nothing here reclaims it.
	size := chunkSize(&msg)
	if txn.bytes+size > p.maxBytes {
		return fmt.Errorf("apply put: transaction %d would hold %d bytes, limit %d",
			generation, txn.bytes+size, p.maxBytes)
	}
	// A transaction is opened for one kind, and the apply reads only the
	// field that kind names. A chunk carrying any other field is a
	// declaration the plugin believes it made and the host would drop in
	// silence, so it is refused instead.
	if err := checkChunkKind(txn.kind, &msg); err != nil {
		return fmt.Errorf("apply put: %w", err)
	}

	// Decoded into locals first, and merged into the transaction only
	// once the whole chunk decodes. A guest that ignores the error this
	// returns and commits anyway would otherwise apply the surviving half
	// of a chunk the host said it had refused.
	var (
		entries []HeadendDesired
		routes  []AdvertisedRoute
		sids    []LocalSID
	)
	if len(msg.GetHeadendEntries()) > 0 {
		// Resolved here, not at startup: a locator registered over RPC
		// after the daemon came up is the common case, and an address
		// captured before that is the one that did not exist yet.
		var src netip.Addr
		if p.encapSource != nil {
			resolved, err := p.encapSource()
			if err != nil {
				p.logger.Debug("resolving the encap source for a plugin declaration", zap.Error(err))
			} else {
				src = resolved
			}
		}
		af := AFv4
		if txn.kind == v1.PluginApplyKind_PLUGIN_APPLY_KIND_HEADEND_V6 {
			af = AFv6
		}
		for _, e := range msg.GetHeadendEntries() {
			prefix, entry, err := DecodeHeadendEntry(e, af, src)
			if err != nil {
				return fmt.Errorf("apply put: %w", err)
			}
			entries = append(entries, HeadendDesired{TriggerPrefix: prefix, Entry: entry})
		}
	}
	for _, r := range msg.GetAdvertisedRoutes() {
		route, err := DecodeAdvertisedRoute(r)
		if err != nil {
			return fmt.Errorf("apply put: %w", err)
		}
		routes = append(routes, route)
	}
	for _, s := range msg.GetLocalSids() {
		sid, err := DecodeLocalSID(s)
		if err != nil {
			return fmt.Errorf("apply put: %w", err)
		}
		sids = append(sids, sid)
	}
	txn.bytes += size
	txn.entries = append(txn.entries, entries...)
	txn.routes = append(txn.routes, routes...)
	txn.sids = append(txn.sids, sids...)
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

	// Every staged declaration is applied, not just up to the first
	// failure: they are separate statements about separate sets, and
	// dropping the rest would leave a plugin live with part of what it
	// declared never applied and nothing to retry it.
	//
	// Only the newest failure of each kind is kept for retry. Two staged
	// declarations of one kind are two statements about the same set, so
	// retrying the older one after the newer succeeded would put back the
	// set the plugin had already replaced.
	var firstErr error
	for _, txn := range staged {
		if err := p.applyTransaction(txn); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			p.holdForRetry(txn)
			continue
		}
		p.dropPending(txn.kind)
	}
	return firstErr
}

// holdForRetry keeps one failed declaration, replacing any older one of
// the same kind.
func (p *PluginOps) holdForRetry(txn *applyTxn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pending == nil {
		p.pending = make(map[v1.PluginApplyKind]*applyTxn)
	}
	if held, ok := p.pending[txn.kind]; ok && held.seq > txn.seq {
		return
	}
	p.pending[txn.kind] = txn
}

// RetryPending reapplies declarations that could not be applied when the
// plugin went live.
//
// A plugin declares from configure, and a restored plugin does that while
// the daemon is still coming up: a local SID naming a locator an operator
// registers over RPC a moment later fails, and the plugin has already said
// everything it intends to say. Nothing would retry it, and the SIDs and
// the routes behind them would simply never come back from a restart.
//
// Retried before each batch, so the first event after the missing piece
// arrives is what repairs it.
func (p *PluginOps) RetryPending() {
	p.mu.Lock()
	pending := p.pending
	p.pending = nil
	p.mu.Unlock()
	for _, txn := range pending {
		if err := p.applyTransaction(txn); err != nil {
			p.holdForRetry(txn)
			// Said once at a level an operator watches, then quietly.
			// A declaration naming something that does not exist retries
			// forever; the first line is what connects the missing thing
			// to the plugin waiting on it, and repeating it every interval
			// would bury the log.
			if p.notePendingFailure(txn.kind) {
				p.logger.Warn("a plugin's declaration cannot be applied and will keep being retried",
					zap.String("kind", kindName(txn.kind)), zap.Error(err))
			} else {
				p.logger.Debug("a declaration held from before the plugin was live still cannot be applied",
					zap.Error(err))
			}
			continue
		}
		p.logger.Info("applied a declaration that was held from before the plugin was live",
			zap.String("kind", kindName(txn.kind)))
	}
}

// notePendingFailure reports whether this is the first failure of its kind
// since one last succeeded, so the log says it once rather than forever.
func (p *PluginOps) notePendingFailure(kind v1.PluginApplyKind) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.reportedPending == nil {
		p.reportedPending = make(map[v1.PluginApplyKind]struct{})
	}
	if _, said := p.reportedPending[kind]; said {
		return false
	}
	p.reportedPending[kind] = struct{}{}
	return true
}

// PendingDeclarations is how many declarations are waiting on something
// that does not exist yet.
//
// It is what tells an operator that a plugin is not idle but stuck: the
// counters that describe delivery all look healthy while a declaration
// naming a missing locator retries in the background forever.
func (p *PluginOps) PendingDeclarations() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.pending)
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
		// Numbered in commit order, which is the order the plugin meant.
		// Everything downstream -- staged drains, retries -- compares this
		// rather than trusting the order it happens to run in.
		p.commits++
		txn.seq = p.commits
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
	if err := p.applyTransaction(txn); err != nil {
		return err
	}
	// This declaration supersedes anything of the same kind still waiting
	// to be retried. Retrying it afterwards would put back a set the
	// plugin has since replaced.
	p.dropPending(txn.kind)
	return nil
}

// dropPending discards held declarations of one kind, because a newer
// declaration of that kind has been applied.
func (p *PluginOps) dropPending(kind v1.PluginApplyKind) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.pending, kind)
	// It applied, so the next time it does not is worth saying again.
	delete(p.reportedPending, kind)
}

// applyTransaction is the reconcile itself, shared by a live commit and by
// one replayed at publication.
func (p *PluginOps) applyTransaction(txn *applyTxn) error {
	// The whole reconcile runs under applyMu, and the staleness check runs
	// inside it. Checking outside would let two applies of one kind pass
	// the check together and then land in either order.
	p.applyMu.Lock()
	defer p.applyMu.Unlock()
	if p.stale(txn) {
		// A newer declaration of this kind has already been applied, so
		// this one describes a set the plugin has moved on from.
		return nil
	}

	if txn.kind == v1.PluginApplyKind_PLUGIN_APPLY_KIND_LOCAL_SID {
		allocated, res, err := p.localSIDs.Apply(p.owner, txn.sids, p.quotas.MaxLocalSIDs)
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
		//
		// Only what this instance has not already been told is sent. Apply
		// returns the whole live set, and a plugin that redeclares its set
		// on every event -- which is the model this asks for -- would
		// otherwise be handed an event for each redeclaration, redeclare in
		// response, and never stop. A fresh instance has an empty record,
		// so a restart still learns every address it holds.
		if p.onLocalSIDs != nil {
			// Recorded only once the event is queued. A dropped batch is
			// unrecoverable here: the BGP snapshot replays routes, not SID
			// allocations, so a plugin suppressed on the strength of an
			// event it never received would never hear the address again.
			if fresh := p.freshAllocations(allocated); len(fresh) > 0 {
				if p.onLocalSIDs(fresh) {
					p.recordNotified(fresh)
				}
			}
		}
		return nil
	}

	if txn.kind == v1.PluginApplyKind_PLUGIN_APPLY_KIND_ADVERTISE {
		res, err := p.advertise.Apply(context.Background(), p.owner, txn.routes, p.quotas.MaxAdvertisedRoutes)
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
	res, err := ApplyHeadendSet(p.headend, p.leases, p.owner, af, txn.entries, p.quotas.MaxHeadendEntries)
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

// ValidateChunk refuses a chunk the host would not apply.
//
// It is exported because the conformance harness runs it too: a harness
// that accepted what the daemon refuses would pass a plugin and let it go
// silent in production, and a second copy of these rules would drift from
// this one. Everything a declaration is checked against before it reaches
// a map or a peer belongs here.
func ValidateChunk(kind v1.PluginApplyKind, msg *v1.PluginApplyChunk) error {
	if err := checkChunkKind(kind, msg); err != nil {
		return err
	}
	af := AFv4
	if kind == v1.PluginApplyKind_PLUGIN_APPLY_KIND_HEADEND_V6 {
		af = AFv6
	}
	// A source address the daemon would lend is not known here, so one is
	// supplied: the entry's own source is what is being checked, and a
	// declaration that names none is valid either way.
	lent := netip.MustParseAddr("fd00::1")
	for _, e := range msg.GetHeadendEntries() {
		if _, _, err := DecodeHeadendEntry(e, af, lent); err != nil {
			return err
		}
	}
	for _, r := range msg.GetAdvertisedRoutes() {
		if _, err := DecodeAdvertisedRoute(r); err != nil {
			return err
		}
	}
	for _, sid := range msg.GetLocalSids() {
		if _, err := DecodeLocalSID(sid); err != nil {
			return err
		}
	}
	return nil
}

// checkChunkKind refuses a chunk whose contents do not match the kind the
// transaction was opened for.
func checkChunkKind(kind v1.PluginApplyKind, msg *v1.PluginApplyChunk) error {
	var unexpected []string
	if len(msg.GetHeadendEntries()) > 0 &&
		kind != v1.PluginApplyKind_PLUGIN_APPLY_KIND_HEADEND_V4 &&
		kind != v1.PluginApplyKind_PLUGIN_APPLY_KIND_HEADEND_V6 {
		unexpected = append(unexpected, "headend entries")
	}
	if len(msg.GetAdvertisedRoutes()) > 0 && kind != v1.PluginApplyKind_PLUGIN_APPLY_KIND_ADVERTISE {
		unexpected = append(unexpected, "advertised routes")
	}
	if len(msg.GetLocalSids()) > 0 && kind != v1.PluginApplyKind_PLUGIN_APPLY_KIND_LOCAL_SID {
		unexpected = append(unexpected, "local SIDs")
	}
	if len(unexpected) > 0 {
		return fmt.Errorf("a %s transaction cannot carry %s", kindName(kind), strings.Join(unexpected, " or "))
	}
	return nil
}

// kindName renders an apply kind the way a plugin author names it.
func kindName(kind v1.PluginApplyKind) string {
	switch kind {
	case v1.PluginApplyKind_PLUGIN_APPLY_KIND_HEADEND_V4:
		return "headend_v4"
	case v1.PluginApplyKind_PLUGIN_APPLY_KIND_HEADEND_V6:
		return "headend_v6"
	case v1.PluginApplyKind_PLUGIN_APPLY_KIND_ADVERTISE:
		return "advertise"
	case v1.PluginApplyKind_PLUGIN_APPLY_KIND_LOCAL_SID:
		return "local_sid"
	default:
		return kind.String()
	}
}

// chunkSize is what one chunk costs the host to keep.
//
// The wire size is the right measure: it is what the guest actually sent,
// it covers every field including the repeated and string ones a count
// ignores, and it does not depend on how the decoded form is laid out.
func chunkSize(msg *v1.PluginApplyChunk) int {
	return proto.Size(msg)
}

// stale reports whether a newer declaration of this kind has already been
// applied, and otherwise records this one as the newest.
//
// Called with applyMu held.
func (p *PluginOps) stale(txn *applyTxn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.lastApplied == nil {
		p.lastApplied = make(map[v1.PluginApplyKind]uint64)
	}
	if txn.seq != 0 && txn.seq < p.lastApplied[txn.kind] {
		return true
	}
	if txn.seq > p.lastApplied[txn.kind] {
		p.lastApplied[txn.kind] = txn.seq
	}
	return false
}

// freshAllocations returns the allocations this instance has not been told
// about yet. It does not record them: that happens in recordNotified, once
// the event carrying them has actually been queued.
//
// An address that changed under a name counts as new: the plugin is
// advertising the old one and has to hear about the replacement.
func (p *PluginOps) freshAllocations(allocated []AllocatedSID) []AllocatedSID {
	p.mu.Lock()
	defer p.mu.Unlock()
	live := make(map[string]struct{}, len(allocated))
	fresh := make([]AllocatedSID, 0, len(allocated))
	for _, got := range allocated {
		live[got.Name] = struct{}{}
		if was, told := p.notifiedSIDs[got.Name]; told && was == got.SID {
			continue
		}
		fresh = append(fresh, got)
	}
	// A name the plugin stopped declaring is forgotten, so declaring it
	// again later is reported rather than silently swallowed.
	for name := range p.notifiedSIDs {
		if _, still := live[name]; !still {
			delete(p.notifiedSIDs, name)
		}
	}
	return fresh
}

// recordNotified marks allocations as told, once they have been queued.
func (p *PluginOps) recordNotified(fresh []AllocatedSID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, got := range fresh {
		p.notifiedSIDs[got.Name] = got.SID
	}
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

// BeginInstance puts the ops back into the state a fresh instance starts
// from, and must be called before that instance runs.
//
// Two things belong to the instance rather than to the registration. The
// record of which SID addresses it has been told is one: an instance that
// replaced a trapped one knows nothing, and suppressing the notification
// because its predecessor had it would leave it holding SIDs it cannot
// advertise. The other is publication: declarations made while the
// instance is being built are held, so an instantiation that then fails
// leaves the state its predecessor wrote untouched instead of pruning it
// on the way out.
func (p *PluginOps) BeginInstance() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.open = make(map[uint64]*applyTxn)
	p.staged = nil
	p.notifiedSIDs = make(map[string]netip.Addr)
	p.published = false
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
		if firstErr != nil {
			// Something is still installed. The steps above each keep the
			// lease on whatever they could not remove, and releasing the
			// owner wholesale here would undo exactly that: a route still
			// advertised, or an entry still in the map, would be left with
			// no lease, and the next plugin to declare that key would take
			// it and overwrite state that is still live.
			return firstErr
		}
		p.leases.ReleaseOwner(p.owner)
	}
	return firstErr
}
