package export

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
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
// RT2 (MAC/IP) for local MACs, RT3 (Inclusive Multicast) for the bridge domain's
// BUM flood endpoint, and RT4 (Ethernet Segment) for a locally-attached ES.
type EVPNAdvertiser interface {
	PushEVPNMac(ctx context.Context, r bgp.EVPNRoute) error
	WithdrawEVPNMac(ctx context.Context, key bgp.EVPNMACKey) error
	PushEVPNInclusiveMulticast(ctx context.Context, r bgp.EVPNRoute) error
	WithdrawEVPNInclusiveMulticast(ctx context.Context, key bgp.EVPNMcastKey) error
	PushEVPNEthernetSegment(ctx context.Context, r bgp.EVPNRoute) error
	WithdrawEVPNEthernetSegment(ctx context.Context, key bgp.EVPNESKey) error
}

// bdState is the per-bridge-domain EVPN export bookkeeping: the binding, the
// minted End.DT2U (RT2 unicast) and End.DT2M (RT3 BUM flood) service SIDs, the
// locator base (the RX reverse-map key carried as RemoteSrc), whether RT3 is
// advertised, and the set of locally-learned MACs currently advertised as RT2.
type bdState struct {
	binding       vrfbgp.Binding
	bridgeIfindex uint32     // the BD's Linux bridge device, for the re-enable idempotency check
	sid           netip.Addr // End.DT2U (RT2 unicast)
	sidStr        string     // sid.String(), rendered once (constant per BD)
	dt2mSID       netip.Addr // End.DT2M (RT3 BUM flood)
	dt2mSIDStr    string
	remoteSrc     string
	rt3Advertised bool
	advertised    map[bgp.EVPNMACKey]struct{}
	// atLimit is set once the BD crosses into the MaxPrefixes-capped state, so the
	// cap-reached warning fires once per crossing rather than per flooded MAC.
	atLimit bool
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
	// es maps a locally-attached Ethernet Segment ID to the RD its RT4 was
	// advertised with, so DisableES can build the withdraw key. RT4 carries no
	// SRv6 SID, so there is no per-ES SID to track.
	es map[[bpf.ESILen]byte]string
}

// NewEVPNExporter wires an EVPN exporter (RT2 + RT3 per bridge domain, RT4 per
// Ethernet Segment). nextHop is the advertising
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
		es:       make(map[[bpf.ESILen]byte]string),
	}
}

// EnableES advertises an EVPN RT4 (Ethernet Segment route) for a locally-attached
// Ethernet Segment so peers run RFC 8584 DF election with this PE as a candidate.
// The ES-Import route target is auto-derived from the high-order 6 octets of the
// ESI value (RFC 7432 Sec. 7.6); RT4 carries no SRv6 SID. rd must be set. It is
// idempotent: an ES already advertised is replaced. A push failure is returned
// (the caller logs it; the ES data-plane entry is unaffected).
func (e *EVPNExporter) EnableES(esi [bpf.ESILen]byte, rd string) error {
	if _, err := bgp.ValidateIPv6NextHop(e.nextHop); err != nil {
		return fmt.Errorf("bgp.global.next_hop %w", err)
	}
	if rd == "" {
		return fmt.Errorf("rd is required for EVPN RT4 auto advertise")
	}
	// ESI byte 0 is the type; bytes 1..6 are the MAC encoded as the ES-Import RT.
	esImportRT := net.HardwareAddr(esi[1:7]).String()

	e.mu.Lock()
	defer e.mu.Unlock()
	prevRD, hadPrev := e.es[esi]
	r := bgp.EVPNRoute{
		Type:       bgp.EVPNRouteTypeEthernetSegment,
		RD:         rd,
		ESI:        esi,
		ESImportRT: esImportRT,
		NextHop:    e.nextHop,
	}
	// Push the new RT4 FIRST. gobgp AddPath supersedes a same-NLRI path, so for an
	// unchanged RD this replaces the prior advertisement in place; for a changed RD
	// the old NLRI survives and is withdrawn below. Pushing first means a push
	// failure returns with the prior advertisement still intact rather than having
	// withdrawn it for a replacement that never landed.
	if err := e.evpn.PushEVPNEthernetSegment(context.Background(), r); err != nil {
		return fmt.Errorf("advertise RT4 for esi %s: %w", bpf.FormatESI(esi), err)
	}
	if hadPrev && prevRD != rd {
		// The RD changed, so the new push created a different NLRI (RD+ESI) and did
		// not supersede the old one; withdraw it explicitly. Non-fatal: the new RT4
		// is already up.
		if err := e.evpn.WithdrawEVPNEthernetSegment(context.Background(), bgp.EVPNESKey{RD: prevRD, ESI: esi}); err != nil {
			e.logger.Warn("withdraw superseded RT4 after RD change",
				zap.String("esi", bpf.FormatESI(esi)), zap.String("old_rd", prevRD), zap.Error(err))
		}
	}
	e.es[esi] = rd
	e.logger.Info("ethernet segment enabled for EVPN RT4 auto advertise",
		zap.String("esi", bpf.FormatESI(esi)), zap.String("rd", rd),
		zap.String("es_import_rt", esImportRT))
	return nil
}

// DisableES withdraws the RT4 advertised for the Ethernet Segment. A no-op for an
// ES that was not advertised.
func (e *EVPNExporter) DisableES(esi [bpf.ESILen]byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.disableESLocked(esi)
}

// RDForESI returns the route distinguisher the ES's RT4 is currently advertised
// with, so EsList can echo the operator-supplied RD that lives only in this
// control-plane state (the BPF esi_map carries no RD). ok=false for an ES that
// is not auto-advertised.
func (e *EVPNExporter) RDForESI(esi [bpf.ESILen]byte) (string, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	rd, ok := e.es[esi]
	return rd, ok
}

// disableESLocked withdraws the ES's RT4 and drops its state. The caller holds e.mu.
func (e *EVPNExporter) disableESLocked(esi [bpf.ESILen]byte) {
	rd, ok := e.es[esi]
	if !ok {
		return
	}
	if err := e.evpn.WithdrawEVPNEthernetSegment(context.Background(), bgp.EVPNESKey{RD: rd, ESI: esi}); err != nil {
		e.logger.Warn("withdraw RT4 on disable", zap.String("esi", bpf.FormatESI(esi)), zap.Error(err))
	}
	delete(e.es, esi)
}

// bdAdvertiseUnchanged reports whether re-enabling the bridge domain with binding
// b and bridgeIfindex would produce the same advertisements and SIDs as the
// current state st, so EnableBD can skip a needless disable + SID re-mint + RT3
// re-advertise. It compares only the fields that shape what this exporter
// originates: the RD and export RTs scoped to FamilyEVPN (RT2/RT3 keys +
// attributes), the default locator (SID minting + RemoteSrc), the bridge ifindex
// (the End.DT2 L2 aux), and the RT2 MaxPrefixes cap. Per-family scoping keeps a
// vpnv4-only RT mutation from flapping RT3 + replayFDB. Receive-only fields
// (import RTs, redistribute) do not affect origination, so changing them alone
// is a no-op here.
func bdAdvertiseUnchanged(st *bdState, b vrfbgp.Binding, bridgeIfindex uint32) bool {
	return st.bridgeIfindex == bridgeIfindex &&
		st.binding.RD == b.RD &&
		st.binding.DefaultLocator == b.DefaultLocator &&
		st.binding.MaxPrefixes == b.MaxPrefixes &&
		sameStringSet(st.binding.ExportRTsForFamily(bgp.FamilyEVPN), b.ExportRTsForFamily(bgp.FamilyEVPN))
}

// sameStringSet reports whether two string lists carry the same set, ignoring
// order. Used for the re-bind idempotency check on fields that are semantically
// unordered sets: BGP route-target extended communities and the redistribute
// protocol list. Reordering them (e.g. a config rewrite) is the same
// advertisement and must not trigger a re-enable. The lists are tiny; sort clones
// and compare (also handles duplicates).
func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac, bc := slices.Clone(a), slices.Clone(b)
	slices.Sort(ac)
	slices.Sort(bc)
	return slices.Equal(ac, bc)
}

// EnableBD makes a bridge domain eligible for EVPN auto-advertise: it mints the
// End.DT2U (RT2 unicast) and End.DT2M (RT3 BUM flood) service SIDs from the
// binding's default locator, installs them into sid_function_map keyed to the
// bridge, and advertises RT3 so remote PEs flood BUM toward this node; local MACs
// then advertise as RT2 via OnLocalMAC. bdID and bridgeIfindex identify the
// bridge domain and its Linux bridge device -- both come from the VRF's bridge
// facet, needed for the L2 aux entry and the exporter's per-BD keying. A zero
// bdID, or a binding without an RD or a default locator, is rejected. It is
// idempotent: a re-enable whose advertisement-affecting fields are unchanged is
// a no-op (no RT3/SID flap); any real change re-enables cleanly (the prior
// enablement is torn down first).
func (e *EVPNExporter) EnableBD(b vrfbgp.Binding, bdID uint16, bridgeIfindex uint32) error {
	// Normalize so the per-AF ExportRTsForFamily(FamilyEVPN) on b returns
	// the synthesized EVPN RT list when a unit-test or legacy caller hands
	// a binding whose Families map has not been populated.
	b = b.Normalize()
	if _, err := bgp.ValidateIPv6NextHop(e.nextHop); err != nil {
		return fmt.Errorf("vrf %q: bgp.global.next_hop %w", b.VRFName, err)
	}
	if bdID == 0 {
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
	// Idempotent re-enable: if the BD is already enabled and nothing that affects
	// its advertisements changed, skip the disable + SID re-mint + RT3 re-advertise
	// that would otherwise flap the bridge domain's routes for no change. A
	// VrfBgpBind re-binds the same VRF on every call, so without this an unchanged
	// re-bind would withdraw and re-originate RT3 + every RT2 and rewrite
	// sid_function_map each time.
	if st, ok := e.bds[bdID]; ok && bdAdvertiseUnchanged(st, b, bridgeIfindex) {
		return nil
	}
	// Replace any existing enablement so a re-enable updates cleanly.
	e.disableBDLocked(bdID)

	dt2uSID, err := e.installL2SID(b.DefaultLocator, bdID, bridgeIfindex, endpointActionDT2U)
	if err != nil {
		return fmt.Errorf("vrf %q: install End.DT2U SID: %w", b.VRFName, err)
	}
	dt2mSID, err := e.installL2SID(b.DefaultLocator, bdID, bridgeIfindex, endpointActionDT2M)
	if err != nil {
		// Roll the DT2U SID back so a half-enabled BD leaves no orphan. If the
		// rollback delete itself fails, surface it: the DT2U SID is then stranded
		// in sid_function_map and would block a later VrfBridgeDetach reference check.
		if rbErr := e.removeL2SID(dt2uSID); rbErr != nil {
			return fmt.Errorf("vrf %q: install End.DT2M SID: %w; rolling back the End.DT2U SID failed (%v): it may be stranded in sid_function_map", b.VRFName, err, rbErr)
		}
		return fmt.Errorf("vrf %q: install End.DT2M SID: %w", b.VRFName, err)
	}
	st := &bdState{
		binding:       b,
		bridgeIfindex: bridgeIfindex,
		sid:           dt2uSID,
		sidStr:        dt2uSID.String(),
		dt2mSID:       dt2mSID,
		dt2mSIDStr:    dt2mSID.String(),
		remoteSrc:     remoteSrc,
		advertised:    make(map[bgp.EVPNMACKey]struct{}),
	}
	e.bds[bdID] = st
	// Advertise RT3 (Inclusive Multicast) so remote PEs flood BUM traffic toward
	// this node's End.DT2M. A failure is non-fatal: RT2 unicast still works, so
	// log it and leave the BD enabled rather than failing the whole bridge.
	r3 := bgp.EVPNRoute{
		Type:        bgp.EVPNRouteTypeInclusiveMulticast,
		RD:          b.RD,
		RTs:         b.ExportRTsForFamily(bgp.FamilyEVPN),
		EthernetTag: 0,
		SRv6SID:     st.dt2mSIDStr,
		NextHop:     e.nextHop,
		RemoteSrc:   remoteSrc,
	}
	if err := e.evpn.PushEVPNInclusiveMulticast(context.Background(), r3); err != nil {
		e.logger.Error("advertise RT3 inclusive multicast",
			zap.String("vrf", b.VRFName), zap.Uint16("bd_id", bdID), zap.Error(err))
	} else {
		st.rt3Advertised = true
	}
	e.logger.Info("bridge domain enabled for EVPN auto advertise",
		zap.String("vrf", b.VRFName), zap.Uint16("bd_id", bdID), zap.String("rd", b.RD),
		zap.String("dt2u_sid", st.sidStr), zap.String("dt2m_sid", st.dt2mSIDStr))
	return nil
}

// DisableBD withdraws the bridge domain's RT3 and every advertised RT2, and
// releases its End.DT2U and End.DT2M SIDs. A no-op for an unknown BD.
func (e *EVPNExporter) DisableBD(bdID uint16) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.disableBDLocked(bdID)
}

// SIDsForBD returns the sid_function_map keys ("<addr>/128") of the End.DT2U and
// End.DT2M SIDs the exporter installed for the bridge domain, so VrfBridgeDetach can
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
	for esi := range e.es {
		e.disableESLocked(esi)
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
	// Teardown is best-effort; removeL2SID logs a delete failure internally.
	_ = e.removeL2SID(st.sid)
	_ = e.removeL2SID(st.dt2mSID)
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
		if st.binding.MaxPrefixes > 0 && uint32(len(st.advertised)) >= st.binding.MaxPrefixes {
			// Per-BD MAC cap reached: stop originating RT2 so a local-MAC flood into
			// a bound bridge cannot amplify into unbounded off-box advertisements
			// (the same blast-radius bound the L3VPN path applies). Which MACs land
			// under the cap follows FDB event/dump order, not a deterministic
			// selection. Warn once per crossing so the flood does not also flood the
			// log; atLimit clears when a withdraw frees headroom.
			if !st.atLimit {
				e.logger.Warn("bridge domain MAC limit reached; capping EVPN RT2 auto-advertise",
					zap.Uint16("bd_id", bdID), zap.Uint32("max", st.binding.MaxPrefixes))
				st.atLimit = true
			}
			return
		}
		r := bgp.EVPNRoute{
			Type: bgp.EVPNRouteTypeMACIP,
			RD:   st.binding.RD,
			RTs:  st.binding.ExportRTsForFamily(bgp.FamilyEVPN),
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
	// Headroom freed: let the cap-reached warning fire again if it refills.
	st.atLimit = false
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

// removeL2SID deletes an L2 endpoint SID and returns its function to the pool,
// returning the delete error so a caller doing a rollback can surface a stranded
// SID. The caller holds e.mu. On a delete failure the SID is NOT released: the
// sid_function_map entry may still be present, and releasing the SID would let a
// later AllocateSID hand out the same SID, whose CreateSidFunction would then hit
// an owner conflict on the stuck entry. Leaking the SID is the safer outcome.
func (e *EVPNExporter) removeL2SID(sid netip.Addr) error {
	if err := e.sidOps.DeleteSidFunction(sid.String()+"/128", bpf.OwnerBuiltin); err != nil {
		e.logger.Warn("delete L2 endpoint SID; keeping it allocated to avoid reuse",
			zap.String("sid", sid.String()), zap.Error(err))
		return err
	}
	e.locators.ReleaseSID(sid)
	return nil
}
