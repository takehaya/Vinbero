// Package export is the advertise-direction counterpart of pkg/bgp/apply:
// it turns Vinbero's VRF-local state into BGP VPNv4 / VPNv6 advertisements
// without an operator running an explicit BgpRouteService call. This is the
// VRF-export driven "automatic advertise" path (docs/plan/bgp-auto-advertise.md).
//
// The flow mirrors apply.applyVPN in reverse. Where the receive path takes a
// VPN route, resolves its route targets to a VRF, and installs a headend
// encap entry, the export path takes a VRF-local prefix, composes the VRF's
// export route targets and its End.DT4/DT6 service SID, and advertises a VPN
// route. The exporter owns its RouteWatcher: Start enables every VRF binding
// that lists a redistribute set and begins watching, so the daemon wiring is a
// single Start / Stop pair (mirroring vinbero.StartFDBWatcher).
package export

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"go.uber.org/zap"

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
}

// Exporter advertises VRF-local prefixes as VPNv4 / VPNv6 routes. It is safe
// for concurrent use: OnRoute runs on the RouteWatcher goroutine while
// EnableVRF / DisableVRF run on the daemon's setup / teardown path, so one
// mutex guards all state.
type Exporter struct {
	mu          sync.Mutex
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
	// The next hop must be an ordinary node address.
	nextHop string
	logger  *zap.Logger
	vrfs    map[string]*vrfState
	byTable map[uint32]*vrfState
}

// New wires an Exporter and its RouteWatcher. nextHop is the advertising PE's
// reachable IPv6 address (its loopback), stamped as the BGP next hop on every
// advertised route. vrfBindings is the shared binding registry the applier
// also reads, so the advertise and receive directions agree on which VRFs
// exist.
func New(advertiser bgp.RouteAdvertiser, sidOps SidOps, locators *locator.Manager, vrfBindings *vrfbgp.Manager, resolver VRFResolver, nextHop string, logger *zap.Logger) *Exporter {
	e := &Exporter{
		advertiser:  advertiser,
		sidOps:      sidOps,
		locators:    locators,
		vrfBindings: vrfBindings,
		resolver:    resolver,
		nextHop:     nextHop,
		logger:      logger.Named("bgp.export"),
		vrfs:        make(map[string]*vrfState),
		byTable:     make(map[uint32]*vrfState),
	}
	e.watcher = netlinkwatch.NewRouteWatcher(e, logger)
	return e
}

// Start enables every VRF binding that lists a redistribute set and begins
// watching the kernel routing tables. EnableVRF mints each VRF's End.DT4/DT6
// service SID and returns the table the watcher must observe; the watcher's
// ListExisting replay then advertises prefixes already present at boot. A
// binding with no redistribute set is left receive-only. If any binding fails
// to enable, the VRFs already enabled in this call are unwound so a partial
// startup leaves no orphaned SID.
func (e *Exporter) Start(ctx context.Context) error {
	enabled := make([]string, 0)
	for _, b := range e.vrfBindings.List() {
		if len(b.Redistribute) == 0 {
			continue
		}
		table, err := e.EnableVRF(b)
		if err != nil {
			e.unwind(enabled)
			return fmt.Errorf("auto-advertise vrf %q: %w", b.VRFName, err)
		}
		if err := e.watcher.RegisterTable(table, b.Redistribute); err != nil {
			e.unwind(enabled)
			return fmt.Errorf("auto-advertise vrf %q: %w", b.VRFName, err)
		}
		enabled = append(enabled, b.VRFName)
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
}

// Stop halts the route watcher and withdraws every advertised route. It is
// meant for graceful shutdown: the watcher stops first so no new advertisement
// races the withdraw, then Close drains the advertised state.
func (e *Exporter) Stop() {
	e.watcher.Stop()
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
	if e.nextHop == "" {
		return 0, fmt.Errorf("vrf %q: bgp.global.next_hop is required for auto advertise", b.VRFName)
	}
	if _, err := netip.ParseAddr(e.nextHop); err != nil {
		return 0, fmt.Errorf("vrf %q: bgp.global.next_hop %q is invalid: %w", b.VRFName, e.nextHop, err)
	}

	ifindex, table, err := e.resolver.Resolve(b.VRFName)
	if err != nil {
		return 0, fmt.Errorf("resolve vrf %q: %w", b.VRFName, err)
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
// Endpoint SIDs back to the locator pool. It is a no-op for an unknown VRF.
func (e *Exporter) DisableVRF(vrfName string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st, ok := e.vrfs[vrfName]
	if !ok {
		return
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
}

// Close disables every enabled VRF. It is the withdraw half of Stop; the
// route watcher must already be stopped so no advertisement races it.
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
}

// OnRoute reacts to a VRF-local prefix appearing (added=true) or being removed
// (added=false) in a routing table. It is the RouteWatcher (RouteSink)
// callback. A prefix in a table no VRF owns is ignored. The underlying
// advertiser.Withdraw is a no-op for a route that was never advertised, so
// duplicate deletes are safe.
func (e *Exporter) OnRoute(table uint32, prefix netip.Prefix, added bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
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
	if err := e.advertiser.Withdraw(context.Background(), key); err != nil {
		e.logger.Error("withdraw VRF-local prefix",
			zap.String("vrf", st.binding.VRFName), zap.String("prefix", vr.Prefix), zap.Error(err))
		return
	}
	delete(st.advertised, key)
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
