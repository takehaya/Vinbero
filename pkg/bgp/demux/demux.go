// Package demux fans a single BGP route subscription out to several
// consumers.
//
// gobgp's watch may only be opened once per daemon: each Subscribe opens
// its own WatchEvent with current=true, so a second one would replay the
// loc-rib -- including this node's own advertisements -- into whoever
// attached late. The daemon therefore owns exactly one subscription and
// every consumer registers here instead.
//
// Two rules make that safe, and both are this package's responsibility
// rather than each consumer's:
//
//   - Local-origin paths are dropped, on the live stream as well as on the
//     snapshot replay. Once anything in the process advertises (the
//     auto-advertise exporter today, a plugin later), the post-policy
//     stream carries the node's own paths back; a consumer acting on them
//     would install self-pointing state.
//   - A consumer only sees the families it declared, so an unrelated
//     family never reaches it.
//
// Delivery is level-triggered: a consumer that registers after Start gets
// a loc-rib snapshot before it starts seeing live updates, and may see the
// same route from both. Consumers must be idempotent per NLRI.
package demux

import (
	"errors"
	"fmt"
	"sync"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// ErrAlreadyStarted is returned by Start when the demux is already
// subscribed.
var ErrAlreadyStarted = errors.New("demux: already started")

// consumer is one registered handler and the families it asked for. A nil
// families map means every family.
type consumer struct {
	name     string
	families map[bgp.Family]struct{}
	handler  bgp.RouteHandler
	// builtin marks a consumer that implements Vinbero's own behaviors, and
	// so must not see routes whose endpoint behavior a plugin has claimed.
	// A plugin consumer sees everything its families cover, claimed or not:
	// it may well need the unclaimed routes for context.
	builtin bool
	// view reconciles delivery when claims change, including rollback.
	view *builtinView
}

// wants reports whether this consumer subscribed to fam.
func (c *consumer) wants(fam bgp.Family) bool {
	if c.families == nil {
		return true
	}
	_, ok := c.families[fam]
	return ok
}

// Demux owns the daemon's single BGP subscription and dispatches each
// received route to the registered consumers.
type Demux struct {
	sub    bgp.RouteSubscriber
	lister bgp.RouteLister
	logger *zap.Logger
	// claims decides which endpoint behaviors belong to a plugin rather
	// than to the built-in appliers. Nil until SetClaimRegistry is called,
	// in which case nothing is claimed.
	claims *ClaimRegistry
	// ledger remembers which NLRIs were advertised under a claimed
	// behavior, so a withdraw -- which carries no attributes to decide
	// from -- inherits the decision its advertise made.
	ledger *claimLedger

	mu        sync.RWMutex
	consumers []*consumer
	nextID    uint64
	ids       []uint64
	cancelSub func()
	started   bool
}

// New builds a demux over sub. lister supplies the loc-rib snapshot for
// consumers that register after Start; it may be nil, in which case such
// consumers only see live updates. Both are usually the same *gobgp.Session.
func New(sub bgp.RouteSubscriber, lister bgp.RouteLister, logger *zap.Logger) *Demux {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Demux{sub: sub, lister: lister, logger: logger, ledger: newClaimLedger()}
}

// SetClaimRegistry installs the registry that decides which endpoint
// behaviors belong to a plugin. Call before Start; a demux with no registry
// treats every behavior as the built-in appliers'.
func (d *Demux) SetClaimRegistry(claims *ClaimRegistry) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.claims = claims
}

// Register adds a plugin consumer. See RegisterBuiltin for Vinbero's own
// appliers, which are additionally shielded from plugin-claimed routes.
func (d *Demux) Register(name string, families []bgp.Family, handler bgp.RouteHandler) (func(), error) {
	return d.register(name, families, handler, false, true)
}

// RegisterQuiet adds a consumer without replaying the rib to it.
//
// It is for a consumer that pulls its own snapshot through SnapshotTo. The
// replay Register performs delivers through the same handler as a live
// update, which a consumer that queues and drops would treat the same way
// -- and a dropped snapshot is worse than a dropped update, because a
// consumer declaring desired sets prunes what it never saw. Such a
// consumer takes the snapshot itself, where it can afford to block.
func (d *Demux) RegisterQuiet(name string, families []bgp.Family, handler bgp.RouteHandler) (func(), error) {
	return d.register(name, families, handler, false, false)
}

// RegisterBuiltin adds a consumer implementing Vinbero's own behaviors. It
// is delivered every route except those whose endpoint behavior a plugin
// has claimed: acting on a claimed route would install an entry with the
// wrong semantics and collide with the plugin's own write to that prefix.
func (d *Demux) RegisterBuiltin(name string, families []bgp.Family, handler bgp.RouteHandler) (func(), error) {
	return d.register(name, families, handler, true, true)
}

// register adds a consumer. families restricts delivery; passing none
// delivers every family. The returned cancel removes the consumer and is
// safe to call more than once.
//
// Registering after Start replays the loc-rib for the declared families
// (every family the lister knows, when none were declared) so the consumer
// converges on routes that arrived before it existed.
func (d *Demux) register(name string, families []bgp.Family, handler bgp.RouteHandler, builtin, wantReplay bool) (func(), error) {
	if handler == nil {
		return nil, fmt.Errorf("demux: register %q: nil handler", name)
	}
	c := &consumer{name: name, handler: handler, builtin: builtin}
	if builtin {
		c.view = d.newBuiltinView(handler)
		c.view.withdrawUnseen = true
		c.handler = c.view.handle
	}
	if len(families) > 0 {
		c.families = make(map[bgp.Family]struct{}, len(families))
		for _, f := range families {
			if !f.Valid() {
				return nil, fmt.Errorf("demux: register %q: unknown family %q", name, f)
			}
			c.families[f] = struct{}{}
		}
	}

	d.mu.Lock()
	id := d.nextID
	d.nextID++
	d.consumers = append(d.consumers, c)
	d.ids = append(d.ids, id)
	replay := d.started && wantReplay
	d.mu.Unlock()

	d.logger.Info("BGP demux consumer registered",
		zap.String("consumer", name),
		zap.Strings("families", familyNames(families)),
		zap.Bool("replay", replay))

	// Replay after the consumer is live so an update between the two is
	// seen rather than lost; the overlap is a duplicate, which
	// level-triggered consumers absorb.
	if replay {
		d.replay(c, families)
	}

	var once sync.Once
	return func() { once.Do(func() { d.remove(id) }) }, nil
}

// remove drops the consumer registered under id.
func (d *Demux) remove(id uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i, got := range d.ids {
		if got != id {
			continue
		}
		name := d.consumers[i].name
		d.consumers = append(d.consumers[:i], d.consumers[i+1:]...)
		d.ids = append(d.ids[:i], d.ids[i+1:]...)
		d.logger.Info("BGP demux consumer removed", zap.String("consumer", name))
		return
	}
}

// Start opens the single underlying subscription. Consumers registered
// beforehand see the current=true replay of peer-learned routes; the
// daemon calls this once, after the applier is registered and before
// anything advertises.
func (d *Demux) Start() error {
	d.mu.Lock()
	if d.started {
		d.mu.Unlock()
		return ErrAlreadyStarted
	}
	d.started = true
	d.mu.Unlock()

	cancel, err := d.sub.Subscribe("", d.dispatch)
	if err != nil {
		d.mu.Lock()
		d.started = false
		d.mu.Unlock()
		return fmt.Errorf("demux: subscribe: %w", err)
	}
	d.mu.Lock()
	d.cancelSub = cancel
	d.mu.Unlock()
	return nil
}

// Stop tears the underlying subscription down. Registered consumers are
// left in place, so a later Start resumes delivery to them.
func (d *Demux) Stop() {
	d.mu.Lock()
	cancel := d.cancelSub
	d.cancelSub = nil
	d.started = false
	d.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// dispatch is the single RouteHandler handed to the subscriber. It runs on
// a gobgp-internal goroutine, so it must not block: it only filters and
// calls the consumers, which carry the same no-blocking contract.
func (d *Demux) dispatch(ev bgp.RouteEvent) {
	// Drop this node's own advertisements. The post-policy stream carries
	// them once anything in the process advertises, and a consumer acting
	// on its own route would install self-pointing state (an own EVPN RT3
	// becomes a BUM peer pointing back at this node). ListRoutes applies
	// the same rule to the snapshot.
	if ev.Source.IsLocal() {
		return
	}
	d.isClaimed(ev)

	d.mu.RLock()
	targets := make([]*consumer, 0, len(d.consumers))
	for _, c := range d.consumers {
		if !c.wants(ev.Family) {
			continue
		}
		// Built-ins see the transition through their view, which retracts
		// an earlier delivery before withholding a newly claimed path.
		targets = append(targets, c)
	}
	d.mu.RUnlock()

	// Retractions must reach built-ins before a plugin can apply the UPDATE.
	for _, builtin := range []bool{true, false} {
		for _, c := range targets {
			if c.builtin == builtin {
				c.handler(ev)
			}
		}
	}
}

// SnapshotTo replays the loc-rib for the given families to h, applying the
// same local-origin rule as live delivery. Passing no families replays
// every family the lister knows.
//
// A consumer needs this when its view has to be rebuilt rather than
// updated: a plugin that was restarted has no memory of anything, and one
// whose events were dropped has a view with holes in it. Both are wrong in
// the same way, and a snapshot is what makes them right again -- which
// matters most for a consumer that declares desired sets, where a partial
// view does not merely delay convergence but actively prunes the state it
// cannot see.
//
// Unlike the replay Register performs, this delivers on the calling
// goroutine and returns when it is done, so the caller knows the view is
// complete.
func (d *Demux) SnapshotTo(families []bgp.Family, h bgp.RouteHandler) error {
	if d == nil || h == nil {
		return nil
	}
	if d.lister == nil {
		return nil
	}
	want := families
	if len(want) == 0 {
		want = allFamilies()
	}
	for _, fam := range want {
		err := d.lister.ListRoutes(fam, func(ev bgp.RouteEvent) {
			if ev.Source.IsLocal() {
				return
			}
			h(ev)
		})
		if err != nil {
			return fmt.Errorf("demux: snapshot %s: %w", fam, err)
		}
	}
	return nil
}

// RetractClaimedFromBuiltins tells Vinbero's own appliers to drop every
// route in the rib whose behavior is now claimed.
//
// A claim only decides where later routes go. A route that arrived before
// the claim existed has already been handed to the built-in appliers,
// which read a codepoint they do not implement as an ordinary service SID
// and install it under their own owner -- so the plugin's write to that
// same prefix is then refused for owner mismatch, and the entry with the
// wrong meaning is the one left carrying traffic. The claim has to reach
// back over what already happened, and a withdrawal is how the appliers
// are told to let go: it is the same path an ordinary withdraw takes, so
// nothing here needs to know how each of them stores what it installed.
//
// Withdrawing what an applier does not hold is a no-op, so this is safe to
// call whenever the claimed set grows, including when it changes nothing.
func (d *Demux) RetractClaimedFromBuiltins() {
	d.mu.RLock()
	claims := d.claims
	d.mu.RUnlock()
	if d.lister == nil || claims == nil {
		return
	}

	d.mu.Lock()
	builtins := make([]*consumer, 0, len(d.consumers))
	for _, c := range d.consumers {
		if c.builtin {
			builtins = append(builtins, c)
		}
	}
	started := d.started
	d.mu.Unlock()
	if !started || len(builtins) == 0 {
		return
	}
	scans := make(map[*consumer]*builtinScan, len(builtins))
	for _, c := range builtins {
		scan := c.view.beginScan()
		scans[c] = scan
		defer scan.close()
	}

	var retracted int
	for _, fam := range allFamilies() {
		err := d.lister.ListRoutes(fam, func(ev bgp.RouteEvent) {
			if ev.Source.IsLocal() || ev.IsWithdraw {
				return
			}
			// Read the registry rather than isClaimed: this is not a
			// delivery, and recording it in the withdrawal ledger would
			// claim a path the appliers are being told to forget.
			if !claims.IsClaimed(ev.EndpointBehavior) {
				return
			}
			for _, c := range builtins {
				if len(c.families) > 0 {
					if _, want := c.families[ev.Family]; !want {
						continue
					}
				}
				scans[c].retract(ev)
			}
			retracted++
		})
		if err != nil {
			d.logger.Warn("listing routes to retract from the built-in appliers",
				zap.String("family", string(fam)), zap.Error(err))
		}
	}
	if retracted > 0 {
		d.logger.Info("retracted routes from the built-in appliers because their behavior is now claimed",
			zap.Int("routes", retracted))
	}
}

// RefreshBuiltinClaims restores the built-in view after tentative claims were
// rolled back. It uses retained live paths, so it cannot reintroduce a path
// withdrawn since registration began.
func (d *Demux) RefreshBuiltinClaims() {
	d.mu.RLock()
	var views []*builtinView
	for _, c := range d.consumers {
		if c.view != nil {
			views = append(views, c.view)
		}
	}
	d.mu.RUnlock()
	for _, view := range views {
		view.refresh()
	}
}

// BuiltinSnapshotHandler wraps h with the same rules the demux applies to
// its own delivery, for a snapshot a built-in consumer pulls on demand
// rather than receiving through the demux.
//
// Such a replay would otherwise be a hole in the claim rule: the applier's
// EVPN rescue re-reads the loc-rib directly when an import surface widens,
// and without this it would pick up exactly the routes dispatch withheld
// from it. A nil demux returns h unchanged, so a daemon with no demux
// behaves as it did before.
func (d *Demux) BuiltinSnapshotHandler(h bgp.RouteHandler) bgp.RouteHandler {
	if d == nil || h == nil {
		return h
	}
	return d.newBuiltinView(h).handle
}

// isClaimed decides whether a route belongs to a plugin rather than to the
// built-in appliers.
//
// An advertise is decided by its endpoint behavior and the answer is
// recorded against its NLRI. A withdraw carries no attributes at all -- BGP
// sends only the NLRI being removed -- so its behavior always decodes as 0
// and the question can only be answered from what the advertise recorded.
// Without that, every withdraw of a claimed route would reach the built-in
// applier as a delete for state it never installed.
func (d *Demux) isClaimed(ev bgp.RouteEvent) bool {
	key := nlriKey(ev)
	if ev.IsWithdraw {
		if d.ledger.isClaimed(key) {
			// This path is going away; stop tracking it so the ledger
			// follows the live routes rather than growing forever. The
			// NLRI stays claimed while another peer still advertises it,
			// so that peer's own withdraw is recognized too.
			d.ledger.forget(key, ev.Source)
			return true
		}
		return false
	}

	d.mu.RLock()
	claims := d.claims
	d.mu.RUnlock()
	if claims.IsClaimed(ev.EndpointBehavior) {
		d.ledger.recordAdvertise(key, ev.Source)
		return true
	}
	// A path can be re-advertised under a different behavior; drop any
	// stale record so a later withdraw is not diverted on old information.
	d.ledger.forget(key, ev.Source)
	return false
}

// replay feeds c a loc-rib snapshot of the given families, or of every
// family c subscribed to when the list is empty. Failures are logged, not
// returned: a consumer that misses the snapshot still converges from live
// updates, and before the session is up there is nothing to replay.
func (d *Demux) replay(c *consumer, families []bgp.Family) {
	if d.lister == nil {
		return
	}
	want := families
	if len(want) == 0 {
		want = allFamilies()
	}
	for _, fam := range want {
		err := d.lister.ListRoutes(fam, func(ev bgp.RouteEvent) {
			if ev.Source.IsLocal() {
				return // defense in depth; ListRoutes already skips these
			}
			// The snapshot applies the same claim rule as the live stream:
			// a built-in consumer registering after a plugin claimed a
			// behavior must not pick those routes up from the replay.
			d.isClaimed(ev)
			c.handler(ev)
		})
		if err != nil {
			d.logger.Warn("BGP demux replay failed",
				zap.String("consumer", c.name),
				zap.String("family", fam.String()),
				zap.Error(err))
		}
	}
}

// allFamilies lists the families a snapshot replay covers when a consumer
// did not narrow its subscription.
func allFamilies() []bgp.Family {
	return []bgp.Family{
		bgp.FamilyVPNv4,
		bgp.FamilyVPNv6,
		bgp.FamilyIPv6Unicast,
		bgp.FamilySRPolicyIPv6,
		bgp.FamilyEVPN,
		bgp.FamilyMUPIPv4,
		bgp.FamilyMUPIPv6,
	}
}

// familyNames renders families for a log field, reporting the empty list
// as "all".
func familyNames(families []bgp.Family) []string {
	if len(families) == 0 {
		return []string{"all"}
	}
	out := make([]string, 0, len(families))
	for _, f := range families {
		out = append(out, f.String())
	}
	return out
}
