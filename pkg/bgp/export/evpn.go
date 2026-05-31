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

// endpointActionDT2U is the local action for a bridge domain's unicast L2 decap
// endpoint (End.DT2, FDB lookup). It is the EVPN RT2 service SID a remote PE
// targets to reach a local MAC. End.DT2M (BUM flood, RT3) is a separate action.
const endpointActionDT2U = uint8(v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT2)

// EVPNAdvertiser is the subset of bgp.EVPNController the EVPN exporter drives:
// the RT2 (MAC/IP) advertise direction. RT3/RT4 are future increments.
type EVPNAdvertiser interface {
	PushEVPNMac(ctx context.Context, r bgp.EVPNRoute) error
	WithdrawEVPNMac(ctx context.Context, key bgp.EVPNMACKey) error
}

// bdState is the per-bridge-domain EVPN export bookkeeping: the binding, the
// minted End.DT2U service SID, its locator base (the RX reverse-map key carried
// as RemoteSrc), and the set of locally-learned MACs currently advertised.
type bdState struct {
	binding    vrfbgp.Binding
	sid        netip.Addr
	sidStr     string // sid.String(), rendered once (it is constant per BD)
	remoteSrc  string
	advertised map[bgp.EVPNMACKey]struct{}
}

// EVPNExporter turns locally-learned bridge MACs into EVPN RT2 (MAC/IP)
// advertisements, the EVPN counterpart of the L3VPN Exporter. It is a
// netlinkwatch.MACSink: the FDBWatcher delivers local MAC changes to OnLocalMAC.
// EnableBD mints and installs the bridge domain's End.DT2U service SID from the
// binding's default locator (symmetric with the L3VPN Exporter's DT4/DT6), so an
// operator only binds the BD and every RT2 follows automatically.
//
// Only locally-learned MACs reach this exporter: the EVPN receive path installs
// remote MACs into the BPF fdb_map with IsRemote=1, never into the kernel bridge
// FDB the FDBWatcher observes, so re-advertising cannot loop.
type EVPNExporter struct {
	mu       sync.Mutex
	evpn     EVPNAdvertiser
	sidOps   SidOps
	locators *locator.Manager
	bindings *vrfbgp.Manager
	// nextHop is the BGP next hop stamped on every RT2: this PE's reachable IPv6
	// address (its loopback), NOT the locator base -- same rule as the L3VPN path.
	nextHop string
	logger  *zap.Logger
	bds     map[uint16]*bdState
}

// NewEVPNExporter wires an EVPN RT2 exporter. nextHop is the advertising PE's
// reachable IPv6 address (its loopback). bindings is the shared binding registry
// the L3VPN path also reads; an EVPN binding is one whose BDID is non-zero.
func NewEVPNExporter(evpn EVPNAdvertiser, sidOps SidOps, locators *locator.Manager, bindings *vrfbgp.Manager, nextHop string, logger *zap.Logger) *EVPNExporter {
	return &EVPNExporter{
		evpn:     evpn,
		sidOps:   sidOps,
		locators: locators,
		bindings: bindings,
		nextHop:  nextHop,
		logger:   logger.Named("bgp.export.evpn"),
		bds:      make(map[uint16]*bdState),
	}
}

// EnableBD makes a bridge domain's locally-learned MACs eligible for RT2
// auto-advertise: it mints an End.DT2U service SID from the binding's default
// locator and installs it into sid_function_map keyed to the bridge, so a remote
// PE can decap unicast toward this node. bridgeIfindex is the BD's Linux bridge
// device, needed for the L2 aux entry. A binding without an RD, a default
// locator, or a non-zero BDID is rejected. It is idempotent: a BD already
// enabled is replaced.
func (e *EVPNExporter) EnableBD(b vrfbgp.Binding, bridgeIfindex uint32) error {
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

	sid, err := e.installDT2U(b.DefaultLocator, b.BDID, bridgeIfindex)
	if err != nil {
		return fmt.Errorf("vrf %q: install End.DT2U SID: %w", b.VRFName, err)
	}
	e.bds[b.BDID] = &bdState{
		binding:    b,
		sid:        sid,
		sidStr:     sid.String(),
		remoteSrc:  remoteSrc,
		advertised: make(map[bgp.EVPNMACKey]struct{}),
	}
	e.logger.Info("bridge domain enabled for EVPN RT2 auto advertise",
		zap.String("vrf", b.VRFName), zap.Uint16("bd_id", b.BDID),
		zap.String("rd", b.RD), zap.String("dt2u_sid", sid.String()))
	return nil
}

// DisableBD withdraws every RT2 advertised for the bridge domain and releases
// its End.DT2U SID. A no-op for an unknown BD.
func (e *EVPNExporter) DisableBD(bdID uint16) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.disableBDLocked(bdID)
}

// Close disables every enabled bridge domain, withdrawing its RT2s and releasing
// its End.DT2U SIDs. It is the graceful-shutdown counterpart of EnableBD; the
// BGP session teardown is the backstop, but this withdraws explicitly first.
func (e *EVPNExporter) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for bdID := range e.bds {
		e.disableBDLocked(bdID)
	}
}

// disableBDLocked withdraws the BD's advertised RT2s, releases its SID, and
// drops the state. The caller holds e.mu.
func (e *EVPNExporter) disableBDLocked(bdID uint16) {
	st, ok := e.bds[bdID]
	if !ok {
		return
	}
	for key := range st.advertised {
		if err := e.evpn.WithdrawEVPNMac(context.Background(), key); err != nil {
			e.logger.Warn("withdraw RT2 on disable",
				zap.Uint16("bd_id", bdID), zap.String("mac", key.MAC), zap.Error(err))
		}
	}
	e.removeDT2U(st.sid)
	delete(e.bds, bdID)
	e.logger.Info("bridge domain disabled for EVPN RT2 auto advertise", zap.Uint16("bd_id", bdID))
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

// installDT2U mints a function from locatorName, builds the End.DT2U SID, and
// installs it into sid_function_map as an l2 bridge-domain endpoint owned by
// Vinbero. On failure the function is returned to the pool. The caller holds e.mu.
func (e *EVPNExporter) installDT2U(locatorName string, bdID uint16, bridgeIfindex uint32) (netip.Addr, error) {
	sid, _, err := e.locators.AllocateSID(locatorName, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	entry := &bpf.SidFunctionEntry{Action: endpointActionDT2U}
	aux := bpf.NewSidAuxL2(bdID, bridgeIfindex)
	if err := e.sidOps.CreateSidFunction(sid.String()+"/128", entry, aux, bpf.OwnerBuiltin); err != nil {
		e.locators.ReleaseSID(sid)
		return netip.Addr{}, err
	}
	return sid, nil
}

// removeDT2U deletes the End.DT2U SID and returns its function to the pool.
// Best-effort: a delete failure is logged, not propagated. The caller holds e.mu.
func (e *EVPNExporter) removeDT2U(sid netip.Addr) {
	if err := e.sidOps.DeleteSidFunction(sid.String()+"/128", bpf.OwnerBuiltin); err != nil {
		e.logger.Warn("delete End.DT2U SID", zap.String("sid", sid.String()), zap.Error(err))
	}
	e.locators.ReleaseSID(sid)
}
