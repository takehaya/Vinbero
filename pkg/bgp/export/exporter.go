// Package export is the advertise-direction counterpart of pkg/bgp/apply:
// it turns Vinbero's VRF-local state into BGP VPNv4 / VPNv6 advertisements
// without an operator running an explicit BgpRouteService call. This is the
// VRF-export driven "automatic advertise" path (docs/plan/bgp-auto-advertise.md).
//
// The flow mirrors apply.applyVPN in reverse. Where the receive path takes a
// VPN route, resolves its route targets to a VRF, and installs a headend
// encap entry, the export path takes a VRF-local prefix, composes the VRF's
// export route targets and its End.DT4/DT6 service SID, and advertises a VPN
// route. The exporter also auto-advertises main-table IPv6 prefixes as IPv6
// unicast (underlay reachability). It owns its RouteWatcher: Start enables
// every VRF binding that lists a redistribute set and begins watching, so the
// daemon wiring is a single Start / Stop pair (mirroring vinbero.StartFDBWatcher).
package export

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/locator"
	"github.com/takehaya/vinbero/pkg/netlinkwatch"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// Endpoint behaviors advertised for a VRF's local prefixes: End.DT4 for the
// VPNv4 service SID, End.DT6 for VPNv6 (RFC 9252 §6). These are constant
// expressions so they fold at compile time.
const (
	endpointActionDT4 = uint8(v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT4)
	endpointActionDT6 = uint8(v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT6)
)

// SidOps is the subset of bpf.MapOperations the exporter needs to install
// and remove the per-VRF Endpoint SID. Narrowing it to an interface keeps
// the exporter unit-testable without a live BPF collection.
type SidOps interface {
	CreateSidFunction(triggerPrefix string, entry *bpf.SidFunctionEntry, aux *bpf.SidAuxEntry, owner bpf.OwnerTag) error
	DeleteSidFunction(triggerPrefix string, requester bpf.OwnerTag) error
}

// VRFResolver maps a VRF name to the kernel ifindex of its l3mdev device and
// the routing table id that device owns. The export path needs the ifindex to
// build the End.DT4/DT6 aux entry and the table id to match incoming route
// events to a VRF. The netlink-backed implementation lives in this package
// (NetlinkVRFResolver); tests supply a fake.
type VRFResolver interface {
	Resolve(vrfName string) (ifindex uint32, table uint32, err error)
}

// UnderlayConfig configures IPv6 unicast underlay advertisement.
type UnderlayConfig struct {
	// Redistribute lists the main-table route protocols ("connected"/"static")
	// whose IPv6 prefixes are advertised as IPv6 unicast. Empty = disabled.
	Redistribute []string
	// MaxPrefixes caps how many underlay prefixes are advertised (0 = unlimited).
	MaxPrefixes uint32
}

// vrfState is the per-VRF export bookkeeping: the binding, the resolved table,
// the two Endpoint SIDs minted from the binding's locator, and the set of
// prefixes currently advertised (so DisableVRF can withdraw them all and a
// per-prefix withdraw can drop exactly one).
type vrfState struct {
	binding    vrfbgp.Binding
	table      uint32
	v4SID      netip.Addr
	v6SID      netip.Addr
	advertised map[bgp.RouteKey]struct{}
	// atLimit is set once the VRF crosses into the MaxPrefixes-capped state, so
	// the cap-reached warning logs once per crossing instead of once per dropped
	// prefix. A withdraw that frees headroom clears it.
	atLimit bool
}

// underlayState tracks the IPv6 unicast underlay prefixes advertised from the
// main routing table.
type underlayState struct {
	advertised map[bgp.RouteKey]struct{}
	// atLimit mirrors vrfState.atLimit for the underlay MaxPrefixes cap.
	atLimit bool
}

// Exporter advertises VRF-local prefixes as VPNv4 / VPNv6 routes and main-table
// IPv6 prefixes as IPv6 unicast. It is safe for concurrent use: OnRoute runs on
// the RouteWatcher goroutine while EnableVRF / DisableVRF run on the daemon's
// setup / teardown path, so one mutex guards all state.
type Exporter struct {
	mu sync.Mutex
	// opMu serializes the exporter's own runtime mutators AddVRF / RemoveVRF so
	// their remove-then-enable steps cannot interleave for the same VRF, and it
	// guards stopped. It does NOT span vrfbgp.Manager: the manager/exporter
	// agreement under concurrent binds is the handler's responsibility
	// (server.VrfBgpServer serializes that). mu guards the in-memory maps for the
	// brief windows EnableVRF / OnRoute hold it; opMu spans a whole runtime mutate.
	opMu sync.Mutex
	// stopped is set under opMu when Stop begins, so AddVRF stops launching replay
	// dumps. Without it a VrfBgpBind racing shutdown could dumpWG.Go (Add from a
	// zero counter) after Stop's dumpWG.Wait -- a sync.WaitGroup misuse.
	stopped     bool
	advertiser  bgp.RouteAdvertiser
	sidOps      SidOps
	locators    *locator.Manager
	vrfBindings *vrfbgp.Manager
	resolver    VRFResolver
	watcher     *netlinkwatch.RouteWatcher
	// nextHop is the BGP next hop stamped on every advertised route: the
	// advertising PE's own reachable IPv6 address (typically its loopback). It
	// is deliberately NOT the locator base -- a locator prefix's subnet-router
	// anycast address (e.g. fd00:100::) is treated as a local address by a
	// receiving PE, which then fails to forward the SRv6-encapsulated traffic.
	// Validated once in Start.
	nextHop     string
	underlayCfg UnderlayConfig
	logger      *zap.Logger
	vrfs        map[string]*vrfState
	byTable     map[uint32]*vrfState
	underlay    *underlayState // non-nil once Start enables underlay advertise
	// dumpWG tracks in-flight asynchronous replay dumps: AddVRF kicks DumpTable
	// on a goroutine so the RPC handler does not block on a large table walk, and
	// Stop waits on this before withdrawing so a late dump cannot re-advertise
	// after Close.
	dumpWG sync.WaitGroup
}

// New wires an Exporter and its RouteWatcher. nextHop is the advertising PE's
// reachable IPv6 address (its loopback), stamped as the BGP next hop on every
// advertised route. underlay configures IPv6 unicast underlay advertisement.
// vrfBindings is the shared binding registry the applier also reads, so the
// advertise and receive directions agree on which VRFs exist.
func New(advertiser bgp.RouteAdvertiser, sidOps SidOps, locators *locator.Manager, vrfBindings *vrfbgp.Manager, resolver VRFResolver, nextHop string, underlay UnderlayConfig, logger *zap.Logger) *Exporter {
	e := &Exporter{
		advertiser:  advertiser,
		sidOps:      sidOps,
		locators:    locators,
		vrfBindings: vrfBindings,
		resolver:    resolver,
		nextHop:     nextHop,
		underlayCfg: underlay,
		logger:      logger.Named("bgp.export"),
		vrfs:        make(map[string]*vrfState),
		byTable:     make(map[uint32]*vrfState),
	}
	// Nest the watcher's logger under bgp.export so its lines are attributable.
	e.watcher = netlinkwatch.NewRouteWatcher(e, e.logger)
	return e
}

// validateIPv6NextHop checks the BGP next hop: a non-empty IPv6 (not v4-mapped)
// address. SRv6 VPN / unicast / EVPN transport is IPv6-only; an empty / IPv4 /
// malformed next hop serializes into a route no PE can forward toward. Shared by
// the L3VPN exporter's Start-time check and the EVPN exporter's per-EnableBD/ES
// check (the EVPN path has no Start).
func validateIPv6NextHop(nextHop string) error {
	if nextHop == "" {
		return fmt.Errorf("bgp.global.next_hop is required for auto advertise")
	}
	a, err := netip.ParseAddr(nextHop)
	if err != nil {
		return fmt.Errorf("bgp.global.next_hop %q is invalid: %w", nextHop, err)
	}
	if !a.Is6() || a.Is4In6() {
		return fmt.Errorf("bgp.global.next_hop %q must be an IPv6 address", nextHop)
	}
	return nil
}

// Start validates the next hop, enables every VRF binding that lists a
// redistribute set, enables the IPv6 unicast underlay if configured, and begins
// watching the kernel routing tables. EnableVRF mints each VRF's End.DT4/DT6
// service SID and returns the table the watcher must observe; the watcher's
// ListExisting replay then advertises prefixes already present at boot. A
// binding with no redistribute set is left receive-only. If any step fails, the
// VRFs already enabled in this call are unwound so a partial startup leaves no
// orphaned SID.
func (e *Exporter) Start(ctx context.Context) error {
	if err := validateIPv6NextHop(e.nextHop); err != nil {
		return err
	}
	enabled := make([]string, 0)
	for _, b := range e.vrfBindings.List() {
		if len(b.Redistribute) == 0 {
			continue
		}
		// enableAndWatch disables the VRF itself on a RegisterTable failure, so
		// nothing for this binding leaks; unwind cleans up the earlier ones.
		if err := e.enableAndWatch(b, false); err != nil {
			e.unwind(enabled)
			return fmt.Errorf("auto-advertise vrf %q: %w", b.VRFName, err)
		}
		enabled = append(enabled, b.VRFName)
	}
	if len(e.underlayCfg.Redistribute) > 0 {
		e.mu.Lock()
		e.underlay = &underlayState{advertised: make(map[bgp.RouteKey]struct{})}
		e.mu.Unlock()
		if err := e.watcher.RegisterTable(unix.RT_TABLE_MAIN, e.underlayCfg.Redistribute); err != nil {
			e.unwind(enabled)
			return fmt.Errorf("underlay redistribute: %w", err)
		}
	}
	if err := e.watcher.Start(ctx); err != nil {
		e.unwind(enabled)
		return err
	}
	return nil
}

// unwind disables the VRFs already enabled in a Start that then failed, so a
// partial startup leaves no Endpoint SID installed and no orphaned state. It is
// the transactional counterpart of EnableVRF's own DT4-rollback-on-DT6-failure.
func (e *Exporter) unwind(names []string) {
	for _, name := range names {
		e.DisableVRF(name)
	}
	// Roll the underlay registration back too, so a failure after the underlay
	// was enabled leaves no RT_TABLE_MAIN watch or underlay state behind.
	e.mu.Lock()
	if e.underlay != nil {
		e.watcher.UnregisterTable(unix.RT_TABLE_MAIN)
		e.underlay = nil
	}
	e.mu.Unlock()
}

// Stop halts the route watcher and withdraws every advertised route. It is
// meant for graceful shutdown: the watcher stops first so no new advertisement
// races the withdraw, then Close drains the advertised state.
func (e *Exporter) Stop() {
	// Flip stopped under opMu first so no AddVRF can launch a new replay dump
	// after this point: every dumpWG.Go runs while opMu is held, and AddVRF
	// rechecks stopped under the same opMu, so dumpWG.Wait below cannot race a
	// dumpWG.Go.
	e.opMu.Lock()
	e.stopped = true
	e.opMu.Unlock()
	e.watcher.Stop()
	// Wait for any in-flight runtime replay dumps to finish before withdrawing,
	// so a late DumpTable cannot re-advertise a prefix after Close drains it.
	e.dumpWG.Wait()
	e.Close()
}

// EnableVRF makes b's local prefixes eligible for auto advertise and returns
// the routing table id the watcher should observe. It resolves the VRF device,
// mints an End.DT4 and an End.DT6 service SID from the binding's default
// locator, and installs them into sid_function_map so a remote PE's receive
// side can decapsulate toward this node. A binding without an RD or a default
// locator is rejected because it cannot form a VPN route. EnableVRF does not
// itself advertise anything; advertisements follow from OnRoute as prefixes
// appear.
func (e *Exporter) EnableVRF(b vrfbgp.Binding) (uint32, error) {
	if b.RD == "" {
		return 0, fmt.Errorf("vrf %q: rd is required for auto advertise", b.VRFName)
	}
	if b.DefaultLocator == "" {
		return 0, fmt.Errorf("vrf %q: default_locator is required for auto advertise", b.VRFName)
	}

	ifindex, table, err := e.resolver.Resolve(b.VRFName)
	if err != nil {
		return 0, fmt.Errorf("resolve vrf %q: %w", b.VRFName, err)
	}
	// A VRF must own a dedicated table. The reserved main/local/default tables
	// belong to the underlay path (RT_TABLE_MAIN) and the rest of the system; a
	// VRF resolving to one of them would mis-dispatch in OnRoute.
	if table == unix.RT_TABLE_MAIN || table == unix.RT_TABLE_LOCAL || table == unix.RT_TABLE_DEFAULT {
		return 0, fmt.Errorf("vrf %q: routing table %d is reserved", b.VRFName, table)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.vrfs[b.VRFName]; ok {
		return 0, fmt.Errorf("vrf %q: already enabled", b.VRFName)
	}
	// Two VRFs resolving to the same routing table would collide in byTable,
	// silently mis-attributing one VRF's prefixes to the other's RD/RT/SID.
	// Reject the second one instead.
	if existing, ok := e.byTable[table]; ok {
		return 0, fmt.Errorf("vrf %q: routing table %d is already exported by vrf %q",
			b.VRFName, table, existing.binding.VRFName)
	}

	v4SID, err := e.installEndpointSID(b.DefaultLocator, ifindex, endpointActionDT4)
	if err != nil {
		return 0, fmt.Errorf("vrf %q: install End.DT4 SID: %w", b.VRFName, err)
	}
	v6SID, err := e.installEndpointSID(b.DefaultLocator, ifindex, endpointActionDT6)
	if err != nil {
		// Roll the End.DT4 SID back so a half-enabled VRF leaves no orphan.
		e.removeEndpointSID(v4SID)
		return 0, fmt.Errorf("vrf %q: install End.DT6 SID: %w", b.VRFName, err)
	}

	st := &vrfState{
		binding:    b,
		table:      table,
		v4SID:      v4SID,
		v6SID:      v6SID,
		advertised: make(map[bgp.RouteKey]struct{}),
	}
	e.vrfs[b.VRFName] = st
	e.byTable[table] = st
	e.logger.Info("VRF enabled for auto advertise",
		zap.String("vrf", b.VRFName), zap.String("rd", b.RD),
		zap.Uint32("table", table),
		zap.String("dt4_sid", v4SID.String()), zap.String("dt6_sid", v6SID.String()))
	return table, nil
}

// DisableVRF withdraws every prefix advertised for vrfName and releases its
// Endpoint SIDs back to the locator pool. It returns the routing table the VRF
// used (so a caller can unregister it) and ok=false for an unknown VRF.
func (e *Exporter) DisableVRF(vrfName string) (uint32, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st, ok := e.vrfs[vrfName]
	if !ok {
		return 0, false
	}
	for key := range st.advertised {
		if err := e.advertiser.Withdraw(context.Background(), key); err != nil {
			e.logger.Warn("withdraw on disable",
				zap.String("vrf", vrfName), zap.String("prefix", key.Prefix), zap.Error(err))
		}
	}
	e.removeEndpointSID(st.v4SID)
	e.removeEndpointSID(st.v6SID)
	delete(e.byTable, st.table)
	delete(e.vrfs, vrfName)
	e.logger.Info("VRF disabled for auto advertise", zap.String("vrf", vrfName))
	return st.table, true
}

// Close disables every enabled VRF and withdraws the underlay prefixes. It is
// the withdraw half of Stop; the route watcher must already be stopped so no
// advertisement races it.
func (e *Exporter) Close() {
	e.mu.Lock()
	names := make([]string, 0, len(e.vrfs))
	for name := range e.vrfs {
		names = append(names, name)
	}
	e.mu.Unlock()
	for _, name := range names {
		e.DisableVRF(name)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.underlay != nil {
		for key := range e.underlay.advertised {
			if err := e.advertiser.Withdraw(context.Background(), key); err != nil {
				e.logger.Warn("withdraw underlay on close",
					zap.String("prefix", key.Prefix), zap.Error(err))
			}
		}
		e.underlay = nil
	}
}

// AddVRF enables a VRF binding at runtime (e.g. from a VrfBgpBind RPC) after
// Start has begun watching. A binding with no redistribute set is a no-op.
// next_hop is assumed already validated by Start.
func (e *Exporter) AddVRF(b vrfbgp.Binding) error {
	e.opMu.Lock()
	defer e.opMu.Unlock()
	if e.stopped {
		// Stop has begun; refuse new enablement so no dumpWG.Go races dumpWG.Wait.
		return fmt.Errorf("exporter is shutting down")
	}
	// Replace any existing enablement so a re-bind updates cleanly instead of
	// hitting EnableVRF's already-enabled check, which would leave the exporter
	// advertising while the handler rolls the manager binding back (desync).
	// Holding opMu across the remove-then-enable makes this atomic against a
	// concurrent AddVRF / RemoveVRF for the same VRF.
	e.removeVRFLocked(b.VRFName)
	if len(b.Redistribute) == 0 {
		return nil
	}
	return e.enableAndWatch(b, true)
}

// enableAndWatch enables one VRF binding and registers its table with the
// watcher, disabling the VRF on a RegisterTable failure so no SID leaks. With
// replay=true it also dumps the table's existing routes -- needed for a runtime
// add, where the subscription's ListExisting (which only fires at Start) did not
// cover a table registered now. The boot path (Start) passes replay=false: its
// ListExisting already covers every table registered before Start.
func (e *Exporter) enableAndWatch(b vrfbgp.Binding, replay bool) error {
	table, err := e.EnableVRF(b)
	if err != nil {
		return err
	}
	if err := e.watcher.RegisterTable(table, b.Redistribute); err != nil {
		e.DisableVRF(b.VRFName)
		return err
	}
	if replay {
		// Replay the table's existing routes on a goroutine so a VrfBgpBind RPC
		// returns without blocking on a full table walk. The live watch already
		// covers anything that changes after RegisterTable, so the dump only
		// backfills pre-existing routes (eventual consistency, like the boot
		// path's ListExisting). A dump failure is non-fatal; Stop waits on
		// dumpWG so a late dump cannot outlive Close.
		//
		// A narrow window remains: a route present in the RouteListFiltered
		// snapshot but deleted before the dump delivers it can be re-advertised
		// stale if its live RTM_DELROUTE was processed before the replay add. The
		// common case is covered -- the live delete withdraws it and OnRoute's
		// dedup stops a concurrent live add and the replay add from
		// double-advertising -- so this is left as a benign Low; closing it fully
		// would need per-route generation tracking, not worth the complexity.
		e.dumpWG.Go(func() {
			if err := e.watcher.DumpTable(table); err != nil {
				e.logger.Warn("dump existing routes for runtime VRF",
					zap.String("vrf", b.VRFName), zap.Uint32("table", table), zap.Error(err))
			}
		})
	}
	return nil
}

// RemoveVRF disables a VRF binding at runtime (e.g. from a VrfBgpUnbind RPC):
// it withdraws the VRF's advertised prefixes, releases its Endpoint SIDs, and
// unregisters the table from the watcher. A no-op for an unknown VRF.
func (e *Exporter) RemoveVRF(vrfName string) {
	e.opMu.Lock()
	defer e.opMu.Unlock()
	e.removeVRFLocked(vrfName)
}

// removeVRFLocked disables the VRF and unregisters its table. The caller holds
// opMu: AddVRF's replace step and RemoveVRF both go through here, so a runtime
// add and a runtime remove for the same VRF cannot race.
func (e *Exporter) removeVRFLocked(vrfName string) {
	if table, ok := e.DisableVRF(vrfName); ok {
		e.watcher.UnregisterTable(table)
	}
}

// OnRoute reacts to a prefix appearing (added=true) or being removed
// (added=false) in a routing table. It is the RouteWatcher (RouteSink)
// callback. A main-table prefix is advertised as IPv6 unicast underlay; a
// prefix in a VRF table is advertised as a VPN route; a prefix in any other
// table is ignored.
func (e *Exporter) OnRoute(table uint32, prefix netip.Prefix, added bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.underlay != nil && table == unix.RT_TABLE_MAIN {
		e.applyUnderlay(prefix, added)
		return
	}
	st, ok := e.byTable[table]
	if !ok {
		return
	}
	vr := e.buildVPNRoute(st, prefix)
	key := vr.Key()
	if added {
		if _, dup := st.advertised[key]; dup {
			// Already advertised (a ListExisting refresh or a duplicate
			// RTM_NEWROUTE); the gobgp path is unchanged, so skip the redundant
			// AddPath and log.
			return
		}
		if st.binding.MaxPrefixes > 0 && uint32(len(st.advertised)) >= st.binding.MaxPrefixes {
			// Per-VRF prefix cap reached: do not originate more, bounding the
			// blast radius of a flood of VRF-local routes. max_prefixes is a
			// nondeterministic admission cap, not a deterministic selection: which
			// prefixes land under the cap follows dump/event order. Log once per
			// crossing into the capped state so a flood does not also flood the
			// log; atLimit clears when a withdraw frees headroom.
			if !st.atLimit {
				e.logger.Warn("VRF prefix limit reached; capping auto-advertise",
					zap.String("vrf", st.binding.VRFName),
					zap.Uint32("max", st.binding.MaxPrefixes))
				st.atLimit = true
			}
			return
		}
		if err := e.advertiser.Advertise(context.Background(), vr); err != nil {
			e.logger.Error("advertise VRF-local prefix",
				zap.String("vrf", st.binding.VRFName), zap.String("prefix", vr.Prefix), zap.Error(err))
			return
		}
		st.advertised[key] = struct{}{}
		e.logger.Info("auto-advertised VRF-local prefix",
			zap.String("vrf", st.binding.VRFName), zap.String("prefix", vr.Prefix),
			zap.String("sid", vr.SRv6SID))
		return
	}
	if _, ok := st.advertised[key]; !ok {
		// We never advertised this prefix (skipped by max-prefix, or a failed
		// initial Advertise): do not withdraw -- the same NLRI could belong to
		// another owner in the gobgp tracking map.
		return
	}
	if err := e.advertiser.Withdraw(context.Background(), key); err != nil {
		e.logger.Error("withdraw VRF-local prefix",
			zap.String("vrf", st.binding.VRFName), zap.String("prefix", vr.Prefix), zap.Error(err))
		return
	}
	delete(st.advertised, key)
	// Headroom freed: allow the cap-reached warning to fire again if it refills.
	st.atLimit = false
}

// applyUnderlay advertises or withdraws a main-table prefix as an IPv6 unicast
// route. Only global IPv6 prefixes are eligible: link-local, the unspecified
// address, the default route, and IPv4 are never valid SRv6 underlay
// advertisements. The MaxPrefixes cap bounds the blast radius of a main-table
// route flood. The caller holds e.mu.
func (e *Exporter) applyUnderlay(prefix netip.Prefix, added bool) {
	addr := prefix.Addr().Unmap()
	if !addr.Is6() {
		return
	}
	if addr.IsLinkLocalUnicast() || addr.IsUnspecified() || prefix.Bits() == 0 {
		return
	}
	ur := bgp.UnicastRoute{Prefix: prefix.String(), NextHop: e.nextHop}
	key := bgp.RouteKey{Family: bgp.FamilyIPv6Unicast, Prefix: ur.Prefix}
	if added {
		if _, dup := e.underlay.advertised[key]; dup {
			return
		}
		if e.underlayCfg.MaxPrefixes > 0 && uint32(len(e.underlay.advertised)) >= e.underlayCfg.MaxPrefixes {
			// Same nondeterministic admission cap as the VRF path; log once per
			// crossing so an underlay route flood does not flood the log.
			if !e.underlay.atLimit {
				e.logger.Warn("underlay prefix limit reached; capping auto-advertise",
					zap.String("prefix", ur.Prefix), zap.Uint32("max", e.underlayCfg.MaxPrefixes))
				e.underlay.atLimit = true
			}
			return
		}
		if err := e.advertiser.AdvertiseUnicast(context.Background(), ur); err != nil {
			e.logger.Error("advertise underlay prefix",
				zap.String("prefix", ur.Prefix), zap.Error(err))
			return
		}
		e.underlay.advertised[key] = struct{}{}
		e.logger.Info("auto-advertised underlay prefix", zap.String("prefix", ur.Prefix))
		return
	}
	if _, ok := e.underlay.advertised[key]; !ok {
		// Never advertised (filtered, or a failed AdvertiseUnicast); skip the
		// withdraw so we don't touch another owner's same-NLRI path.
		return
	}
	if err := e.advertiser.Withdraw(context.Background(), key); err != nil {
		e.logger.Error("withdraw underlay prefix",
			zap.String("prefix", ur.Prefix), zap.Error(err))
		return
	}
	delete(e.underlay.advertised, key)
	// Headroom freed: allow the cap-reached warning to fire again if it refills.
	e.underlay.atLimit = false
}

// buildVPNRoute composes the VPNv4 / VPNv6 advertisement for a VRF-local
// prefix: the family and Endpoint SID follow the prefix's address family, the
// route targets and RD come from the binding, and the next hop is the
// configured PE address. The caller holds e.mu. It performs no I/O so it is the
// natural unit-test seam.
func (e *Exporter) buildVPNRoute(st *vrfState, prefix netip.Prefix) bgp.VPNRoute {
	addr := prefix.Addr().Unmap()
	family := bgp.FamilyVPNv6
	sid := st.v6SID
	if addr.Is4() {
		family = bgp.FamilyVPNv4
		sid = st.v4SID
	}
	// Normalize so a 4-in-6 address renders as a plain IPv4 prefix string.
	norm := netip.PrefixFrom(addr, prefix.Bits())
	return bgp.VPNRoute{
		Family:  family,
		Prefix:  norm.String(),
		RD:      st.binding.RD,
		RTs:     st.binding.ExportRTs,
		SRv6SID: sid.String(),
		NextHop: e.nextHop,
	}
}

// installEndpointSID mints a function from locatorName, builds the SID, and
// installs it into sid_function_map as an l3vrf endpoint owned by Vinbero
// (OwnerBuiltin). On any failure the function is returned to the pool so a
// failed install leaks nothing. The caller holds e.mu.
func (e *Exporter) installEndpointSID(locatorName string, ifindex uint32, action uint8) (netip.Addr, error) {
	sid, _, err := e.locators.AllocateSID(locatorName, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	entry := &bpf.SidFunctionEntry{Action: action}
	aux := bpf.NewSidAuxL3Vrf(ifindex)
	if err := e.sidOps.CreateSidFunction(sid.String()+"/128", entry, aux, bpf.OwnerBuiltin); err != nil {
		e.locators.ReleaseSID(sid)
		return netip.Addr{}, err
	}
	return sid, nil
}

// removeEndpointSID deletes the Endpoint SID from sid_function_map and returns
// its function to the locator pool. Best-effort: a delete failure is logged,
// not propagated, so teardown of the rest of the VRF still proceeds. The
// caller holds e.mu.
func (e *Exporter) removeEndpointSID(sid netip.Addr) {
	if err := e.sidOps.DeleteSidFunction(sid.String()+"/128", bpf.OwnerBuiltin); err != nil {
		e.logger.Warn("delete Endpoint SID", zap.String("sid", sid.String()), zap.Error(err))
	}
	e.locators.ReleaseSID(sid)
}
