package export

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"go.uber.org/zap"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/locator"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// endpointActionDT2U / endpointActionDT2M are the L2 bridge-domain endpoint
// actions: End.DT2 (FDB lookup) is the RT2 unicast service SID a remote PE
// targets to reach a local MAC; End.DT2M (BUM flood) is the RT3 service SID a
// remote PE targets to flood BUM traffic toward this node.
const (
	endpointActionDT2U = uint8(v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT2)
	endpointActionDT2M = uint8(v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT2M)
)

// EVPNAdvertiser is the subset of bgp.EVPNController the EVPN exporter drives:
// RT2 (MAC/IP) for local MACs and RT3 (Inclusive Multicast) for the bridge
// domain's BUM flood endpoint. RT4 (Ethernet Segment) is a future increment.
type EVPNAdvertiser interface {
	PushEVPNMac(ctx context.Context, r bgp.EVPNRoute) error
	WithdrawEVPNMac(ctx context.Context, key bgp.EVPNMACKey) error
	PushEVPNInclusiveMulticast(ctx context.Context, r bgp.EVPNRoute) error
	WithdrawEVPNInclusiveMulticast(ctx context.Context, key bgp.EVPNMcastKey) error
}

// bdState is the per-bridge-domain EVPN export bookkeeping: the binding, the
// minted End.DT2U (RT2 unicast) and End.DT2M (RT3 BUM flood) service SIDs, the
// locator base (the RX reverse-map key carried as RemoteSrc), whether RT3 is
// advertised, and the set of locally-learned MACs currently advertised as RT2.
type bdState struct {
	binding       vrfbgp.Binding
	sid           netip.Addr // End.DT2U (RT2 unicast)
	sidStr        string     // sid.String(), rendered once (constant per BD)
	dt2mSID       netip.Addr // End.DT2M (RT3 BUM flood)
	dt2mSIDStr    string
	remoteSrc     string
	rt3Advertised bool
	advertised    map[bgp.EVPNMACKey]struct{}
}

// EVPNExporter turns local bridge-domain state into EVPN advertisements, the
// EVPN counterpart of the L3VPN Exporter. EnableBD mints the bridge domain's
// End.DT2U (RT2 unicast) and End.DT2M (RT3 BUM flood) service SIDs from the
// binding's default locator (symmetric with the L3VPN Exporter's DT4/DT6) and
// advertises RT3; locally-learned MACs then advertise as RT2 through OnLocalMAC
// (the netlinkwatch.MACSink the FDBWatcher feeds). An operator only binds the BD.
//
// Only locally-learned MACs reach this exporter: the EVPN receive path installs
// remote MACs into the BPF fdb_map with IsRemote=1, never into the kernel bridge
// FDB the FDBWatcher observes, so re-advertising cannot loop.
type EVPNExporter struct {
	mu       sync.Mutex
	evpn     EVPNAdvertiser
	sidOps   SidOps
	locators *locator.Manager
	// nextHop is the BGP next hop stamped on every RT2: this PE's reachable IPv6
	// address (its loopback), NOT the locator base -- same rule as the L3VPN path.
	nextHop string
	logger  *zap.Logger
	bds     map[uint16]*bdState
}

// NewEVPNExporter wires an EVPN exporter (RT2 + RT3). nextHop is the advertising
// PE's reachable IPv6 address (its loopback); the caller resolves a bridge domain
// to its binding and passes it to EnableBD.
func NewEVPNExporter(evpn EVPNAdvertiser, sidOps SidOps, locators *locator.Manager, nextHop string, logger *zap.Logger) *EVPNExporter {
	return &EVPNExporter{
		evpn:     evpn,
		sidOps:   sidOps,
		locators: locators,
		nextHop:  nextHop,
		logger:   logger.Named("bgp.export.evpn"),
		bds:      make(map[uint16]*bdState),
	}
}

// checkNextHop validates the BGP next hop: a non-empty IPv6 (not v4-in-6)
// address. SRv6 VPN transport is IPv6-only; an empty / IPv4 / malformed next hop
// serializes into an RT2 no PE can forward toward. Mirrors the L3VPN exporter's
// Start-time validation, applied per EnableBD since the EVPN path has no Start.
func checkNextHop(nextHop string) error {
	if nextHop == "" {
		return fmt.Errorf("bgp.global.next_hop is required for EVPN auto advertise")
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

// EnableBD makes a bridge domain eligible for EVPN auto-advertise: it mints the
// End.DT2U (RT2 unicast) and End.DT2M (RT3 BUM flood) service SIDs from the
// binding's default locator, installs them into sid_function_map keyed to the
// bridge, and advertises RT3 so remote PEs flood BUM toward this node; local MACs
// then advertise as RT2 via OnLocalMAC. bridgeIfindex is the BD's Linux bridge
// device, needed for the L2 aux entry. A binding with a zero BDID, or without an
// RD or a default locator, is rejected. It is idempotent: a BD already enabled
// is replaced.
func (e *EVPNExporter) EnableBD(b vrfbgp.Binding, bridgeIfindex uint32) error {
	if err := checkNextHop(e.nextHop); err != nil {
		return fmt.Errorf("vrf %q: %w", b.VRFName, err)
	}
	if b.BDID == 0 {
		return fmt.Errorf("vrf %q: bd_id is required for EVPN auto advertise", b.VRFName)
	}
	if b.RD == "" {
		return fmt.Errorf("vrf %q: rd is required for EVPN auto advertise", b.VRFName)
	}
	if b.DefaultLocator == "" {
		return fmt.Errorf("vrf %q: default_locator is required for EVPN auto advertise", b.VRFName)
	}
	loc, ok := e.locators.Get(b.DefaultLocator)
	if !ok {
		return fmt.Errorf("vrf %q: unknown locator %q", b.VRFName, b.DefaultLocator)
	}
	remoteSrc := loc.Prefix.Masked().Addr().String()

	e.mu.Lock()
	defer e.mu.Unlock()
	// Replace any existing enablement so a re-enable updates cleanly.
	e.disableBDLocked(b.BDID)

	dt2uSID, err := e.installL2SID(b.DefaultLocator, b.BDID, bridgeIfindex, endpointActionDT2U)
	if err != nil {
		return fmt.Errorf("vrf %q: install End.DT2U SID: %w", b.VRFName, err)
	}
	dt2mSID, err := e.installL2SID(b.DefaultLocator, b.BDID, bridgeIfindex, endpointActionDT2M)
	if err != nil {
		// Roll the DT2U SID back so a half-enabled BD leaves no orphan.
		e.removeL2SID(dt2uSID)
		return fmt.Errorf("vrf %q: install End.DT2M SID: %w", b.VRFName, err)
	}
	st := &bdState{
		binding:    b,
		sid:        dt2uSID,
		sidStr:     dt2uSID.String(),
		dt2mSID:    dt2mSID,
		dt2mSIDStr: dt2mSID.String(),
		remoteSrc:  remoteSrc,
		advertised: make(map[bgp.EVPNMACKey]struct{}),
	}
	e.bds[b.BDID] = st
	// Advertise RT3 (Inclusive Multicast) so remote PEs flood BUM traffic toward
	// this node's End.DT2M. A failure is non-fatal: RT2 unicast still works, so
	// log it and leave the BD enabled rather than failing the whole bridge.
	r3 := bgp.EVPNRoute{
		Type:        bgp.EVPNRouteTypeInclusiveMulticast,
		RD:          b.RD,
		RTs:         b.ExportRTs,
		EthernetTag: 0,
		SRv6SID:     st.dt2mSIDStr,
		NextHop:     e.nextHop,
		RemoteSrc:   remoteSrc,
	}
	if err := e.evpn.PushEVPNInclusiveMulticast(context.Background(), r3); err != nil {
		e.logger.Error("advertise RT3 inclusive multicast",
			zap.String("vrf", b.VRFName), zap.Uint16("bd_id", b.BDID), zap.Error(err))
	} else {
		st.rt3Advertised = true
	}
	e.logger.Info("bridge domain enabled for EVPN auto advertise",
		zap.String("vrf", b.VRFName), zap.Uint16("bd_id", b.BDID), zap.String("rd", b.RD),
		zap.String("dt2u_sid", dt2uSID.String()), zap.String("dt2m_sid", dt2mSID.String()))
	return nil
}

// DisableBD withdraws every RT2 advertised for the bridge domain and releases
// its End.DT2U SID. A no-op for an unknown BD.
func (e *EVPNExporter) DisableBD(bdID uint16) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.disableBDLocked(bdID)
}

// SIDsForBD returns the sid_function_map keys ("<addr>/128") of the End.DT2U and
// End.DT2M SIDs the exporter installed for the bridge domain, so BridgeDelete can
// exclude these lifecycle-owned SIDs from its bridge-reference check. nil for a
// BD the exporter has not enabled.
func (e *EVPNExporter) SIDsForBD(bdID uint16) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	st, ok := e.bds[bdID]
	if !ok {
		return nil
	}
	return []string{st.sidStr + "/128", st.dt2mSIDStr + "/128"}
}

// Close disables every enabled bridge domain, withdrawing its RT2s/RT3 and
// releasing its End.DT2U/DT2M SIDs. It is the graceful-shutdown counterpart of
// EnableBD; the BGP session teardown is the backstop, but this withdraws first.
func (e *EVPNExporter) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for bdID := range e.bds {
		e.disableBDLocked(bdID)
	}
}

// disableBDLocked withdraws the BD's RT3 and advertised RT2s, releases its
// End.DT2U/DT2M SIDs, and drops the state. The caller holds e.mu.
func (e *EVPNExporter) disableBDLocked(bdID uint16) {
	st, ok := e.bds[bdID]
	if !ok {
		return
	}
	if st.rt3Advertised {
		if err := e.evpn.WithdrawEVPNInclusiveMulticast(context.Background(),
			bgp.EVPNMcastKey{RD: st.binding.RD, EthernetTag: 0}); err != nil {
			e.logger.Warn("withdraw RT3 on disable", zap.Uint16("bd_id", bdID), zap.Error(err))
		}
	}
	for key := range st.advertised {
		if err := e.evpn.WithdrawEVPNMac(context.Background(), key); err != nil {
			e.logger.Warn("withdraw RT2 on disable",
				zap.Uint16("bd_id", bdID), zap.String("mac", key.MAC), zap.Error(err))
		}
	}
	e.removeL2SID(st.sid)
	e.removeL2SID(st.dt2mSID)
	delete(e.bds, bdID)
	e.logger.Info("bridge domain disabled for EVPN auto advertise", zap.Uint16("bd_id", bdID))
}

// OnLocalMAC is the netlinkwatch.MACSink callback: a MAC learned (added=true) or
// aged/removed (added=false) on a watched local bridge. For an enabled BD it
// advertises (or withdraws) the MAC as an EVPN RT2. A MAC in an unbound BD is
// ignored.
func (e *EVPNExporter) OnLocalMAC(bdID uint16, mac net.HardwareAddr, added bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st, ok := e.bds[bdID]
	if !ok {
		return
	}
	macStr := mac.String()
	key := bgp.EVPNMACKey{RD: st.binding.RD, EthernetTag: 0, MAC: macStr}
	if added {
		if _, dup := st.advertised[key]; dup {
			return
		}
		r := bgp.EVPNRoute{
			Type: bgp.EVPNRouteTypeMACIP,
			RD:   st.binding.RD,
			RTs:  st.binding.ExportRTs,
			// EthernetTag 0: VLAN-based EVI, one bridge domain = one EVI. ESI is
			// left zero -- single-homed; multi-homing RT2 ESI is a future
			// increment that needs the bridge's ES attribute.
			EthernetTag: 0,
			MAC:         macStr,
			SRv6SID:     st.sidStr,
			NextHop:     e.nextHop,
			RemoteSrc:   st.remoteSrc,
		}
		if err := e.evpn.PushEVPNMac(context.Background(), r); err != nil {
			e.logger.Error("advertise RT2 for local MAC",
				zap.Uint16("bd_id", bdID), zap.String("mac", r.MAC), zap.Error(err))
			return
		}
		st.advertised[key] = struct{}{}
		e.logger.Info("auto-advertised local MAC as EVPN RT2",
			zap.Uint16("bd_id", bdID), zap.String("mac", r.MAC), zap.String("sid", r.SRv6SID))
		return
	}
	if _, ok := st.advertised[key]; !ok {
		// Never advertised (a failed push, or a MAC we did not originate): skip
		// the withdraw so we do not touch another owner's same-NLRI path.
		return
	}
	if err := e.evpn.WithdrawEVPNMac(context.Background(), key); err != nil {
		e.logger.Error("withdraw RT2 for local MAC",
			zap.Uint16("bd_id", bdID), zap.String("mac", key.MAC), zap.Error(err))
		return
	}
	delete(st.advertised, key)
}

// installL2SID mints a function from locatorName and installs an L2 bridge-domain
// endpoint SID for the given action (End.DT2U for RT2, End.DT2M for RT3) into
// sid_function_map, owned by Vinbero. On failure the function is returned to the
// pool. The caller holds e.mu.
func (e *EVPNExporter) installL2SID(locatorName string, bdID uint16, bridgeIfindex uint32, action uint8) (netip.Addr, error) {
	sid, _, err := e.locators.AllocateSID(locatorName, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	entry := &bpf.SidFunctionEntry{Action: action}
	aux := bpf.NewSidAuxL2(bdID, bridgeIfindex)
	if err := e.sidOps.CreateSidFunction(sid.String()+"/128", entry, aux, bpf.OwnerBuiltin); err != nil {
		e.locators.ReleaseSID(sid)
		return netip.Addr{}, err
	}
	return sid, nil
}

// removeL2SID deletes an L2 endpoint SID and returns its function to the pool.
// Best-effort: a delete failure is logged, not propagated. The caller holds e.mu.
func (e *EVPNExporter) removeL2SID(sid netip.Addr) {
	if err := e.sidOps.DeleteSidFunction(sid.String()+"/128", bpf.OwnerBuiltin); err != nil {
		e.logger.Warn("delete L2 endpoint SID", zap.String("sid", sid.String()), zap.Error(err))
	}
	e.locators.ReleaseSID(sid)
}
