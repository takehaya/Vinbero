package server

import (
	"github.com/takehaya/vinbero/pkg/vrf"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
	"go.uber.org/zap"
)

// EvpnBridgeHook enables or disables EVPN auto-advertise (RT2 + RT3) for a
// bridge domain as its bridge facet is attached or detached. bdID and
// bridgeIfindex come from the VRF's bridge facet.
// *pkg/bgp/export.EVPNExporter satisfies it; it is nil unless EVPN
// auto-advertise is on.
type EvpnBridgeHook interface {
	EnableBD(b vrfbgp.Binding, bdID uint16, bridgeIfindex uint32) error
	DisableBD(bdID uint16)
	// SIDsForBD returns the sid_function_map keys the exporter installed for the
	// bd (End.DT2U + End.DT2M), so VrfBridgeDetach can exclude these
	// lifecycle-owned SIDs from its reference check. nil for a bd that is not
	// enabled.
	SIDsForBD(bdID uint16) []string
}

// EvpnCoordinator drives EVPN auto-advertise (RT2 + RT3) for a VRF's bridge
// domain. A bridge domain may auto-advertise only when the VRF carries BOTH a
// bridge facet and a binding with EVPN export RTs, so every mutation that can
// change either side (VrfBridgeAttach / VrfBridgeDetach, VrfBgpBind /
// VrfBgpUnbind, RT mutations through commitBinding, and the boot pass) calls
// Enable or Disable here. Centralizing the enable (EnableBD + FDB replay)
// sequence in one place keeps the replay ordering and the teardown symmetric
// regardless of which side of the VRF changed.
//
// It is nil unless EVPN auto-advertise is on; callers nil-check before use.
type EvpnCoordinator struct {
	exporter EvpnBridgeHook
	// facet resolves a VRF name to its bridge facet (bd_id + bridge ifindex +
	// device name); ok=false when the VRF has no bridge attached yet.
	facet func(vrfName string) (vrf.Bridge, bool)
	// replayFDB re-runs a bridge's existing kernel FDB through the RT2 path
	// (FDBWatcher.DumpBridge), so a bridge already holding MACs advertises them.
	replayFDB func(ifindex int) error
	logger    *zap.Logger
}

// NewEvpnCoordinator wires the coordinator. exporter is the EVPNExporter,
// facet resolves a VRF name to its bridge facet (a closure over
// vrf.Manager.Get), replayFDB is FDBWatcher.DumpBridge.
func NewEvpnCoordinator(exporter EvpnBridgeHook, facet func(vrfName string) (vrf.Bridge, bool), replayFDB func(ifindex int) error, logger *zap.Logger) *EvpnCoordinator {
	return &EvpnCoordinator{
		exporter:  exporter,
		facet:     facet,
		replayFDB: replayFDB,
		logger:    logger.Named("evpn.coordinator"),
	}
}

// Enable turns on EVPN auto-advertise for the binding's bridge domain and
// replays the bridge's existing FDB as RT2. The bridge domain (bd_id +
// ifindex) comes from the VRF's bridge facet; when the VRF has no facet yet it
// is a no-op -- VrfBridgeAttach calls Enable again when the bridge arrives.
// Both steps are non-fatal: the bridge is usable regardless, it just won't
// auto-originate, so failures are logged, not returned.
func (c *EvpnCoordinator) Enable(b vrfbgp.Binding) {
	br, ok := c.facet(b.VRFName)
	if !ok {
		c.logger.Debug("EVPN binding has no bridge facet yet",
			zap.String("vrf", b.VRFName))
		return
	}
	fields := []zap.Field{
		zap.String("vrf", b.VRFName), zap.Uint16("bd_id", br.BdID),
		zap.String("bridge", br.Name),
	}
	if err := c.exporter.EnableBD(b, br.BdID, br.Ifindex); err != nil {
		c.logger.Warn("enable EVPN auto-advertise for bridge domain",
			append(fields, zap.Error(err))...)
		return
	}
	if err := c.replayFDB(int(br.Ifindex)); err != nil {
		// Replay MACs already in the bridge's FDB (e.g. a pre-existing bridge) so
		// they advertise as RT2. Non-fatal: live events still cover anything
		// learned after this.
		c.logger.Warn("replay bridge FDB for EVPN RT2 auto-advertise",
			append(fields, zap.Error(err))...)
	}
}

// Disable tears down a bridge domain's EVPN auto-advertise (withdraw RT2/RT3,
// release SIDs). It takes the bd_id rather than a VRF name because both
// callers act on pre-mutation state: VrfBridgeDetach captures the facet's bd
// before removing it, and VrfBgpUnbind captures it before the binding goes. A
// no-op for a BD the exporter has not enabled, so calling it from either side
// is safe.
func (c *EvpnCoordinator) Disable(bdID uint16) {
	if bdID == 0 {
		return
	}
	c.exporter.DisableBD(bdID)
}

// SIDsForBD returns the sid_function_map keys the exporter installed for the
// bridge domain, so VrfBridgeDetach can exclude them from its reference check.
func (c *EvpnCoordinator) SIDsForBD(bdID uint16) []string {
	return c.exporter.SIDsForBD(bdID)
}
