package server

import (
	"github.com/takehaya/vinbero/pkg/vrfbgp"
	"go.uber.org/zap"
)

// EvpnCoordinator drives EVPN auto-advertise (RT2 + RT3) across the two
// lifecycles that gate a bridge domain: the bridge device (BridgeCreate /
// BridgeDelete) and the VRF<->BGP binding (VrfBgpBind / VrfBgpUnbind). A bridge
// domain may auto-advertise only when BOTH its bridge exists and its binding is
// present, so whichever arrives second enables it and whichever leaves first
// disables it. Centralizing both axes here keeps the enable (EnableBD + FDB
// replay) sequence in one place and closes the asymmetry where an unbind left
// the device-axis enablement originating routes under a removed RD/RT.
//
// It is nil unless EVPN auto-advertise is on; callers nil-check before use.
type EvpnCoordinator struct {
	exporter EvpnBridgeHook
	// bridgeIfindex resolves a bridge domain id to its Linux bridge ifindex
	// (ResourceManager.BridgeIfindexByBDID); ok=false when no bridge exists yet.
	bridgeIfindex func(bdID uint16) (uint32, bool)
	// replayFDB re-runs a bridge's existing kernel FDB through the RT2 path
	// (FDBWatcher.DumpBridge), so a bridge already holding MACs advertises them.
	replayFDB func(ifindex int) error
	logger    *zap.Logger
}

// NewEvpnCoordinator wires the coordinator. exporter is the EVPNExporter,
// bridgeIfindex is ResourceManager.BridgeIfindexByBDID, replayFDB is
// FDBWatcher.DumpBridge.
func NewEvpnCoordinator(exporter EvpnBridgeHook, bridgeIfindex func(bdID uint16) (uint32, bool), replayFDB func(ifindex int) error, logger *zap.Logger) *EvpnCoordinator {
	return &EvpnCoordinator{
		exporter:      exporter,
		bridgeIfindex: bridgeIfindex,
		replayFDB:     replayFDB,
		logger:        logger.Named("evpn.coordinator"),
	}
}

// EnableForBridge enables EVPN auto-advertise for a binding whose bridge is at
// ifindex, and replays the bridge's existing FDB as RT2. Both steps are
// non-fatal -- the bridge is usable regardless; it just won't auto-originate --
// so failures are logged, not returned. bridgeName is the Linux bridge device
// name when the caller knows it (the device axis, BridgeCreate); the binding
// axis passes "" since it resolves only the ifindex, so the log omits the
// bridge field rather than mislabelling another value as the bridge name.
func (c *EvpnCoordinator) EnableForBridge(b vrfbgp.Binding, ifindex uint32, bridgeName string) {
	if err := c.exporter.EnableBD(b, ifindex); err != nil {
		c.logger.Warn("enable EVPN auto-advertise for bridge domain",
			c.bdFields(b, bridgeName, zap.Error(err))...)
		return
	}
	if err := c.replayFDB(int(ifindex)); err != nil {
		// Replay MACs already in the bridge's FDB (e.g. a pre-existing bridge) so
		// they advertise as RT2. Non-fatal: live events still cover anything
		// learned after this.
		c.logger.Warn("replay bridge FDB for EVPN RT2 auto-advertise",
			c.bdFields(b, bridgeName, zap.Error(err))...)
	}
}

// bdFields builds the common log fields for a bridge domain: vrf and bd_id
// always, bridge only when its name is known, plus any extra fields.
func (c *EvpnCoordinator) bdFields(b vrfbgp.Binding, bridgeName string, extra ...zap.Field) []zap.Field {
	f := make([]zap.Field, 0, 3+len(extra))
	f = append(f, zap.String("vrf", b.VRFName), zap.Uint16("bd_id", b.BDID))
	if bridgeName != "" {
		f = append(f, zap.String("bridge", bridgeName))
	}
	return append(f, extra...)
}

// EnableForBinding is the binding axis: a VRF was just bound, so enable EVPN
// auto-advertise for its bridge domain if the bridge already exists. When the
// bridge has not been created yet it is a no-op -- BridgeCreate enables it via
// EnableForBridge when it arrives. A binding without a bridge domain (BDID 0,
// i.e. L3VPN-only) is ignored.
func (c *EvpnCoordinator) EnableForBinding(b vrfbgp.Binding) {
	if b.BDID == 0 {
		return
	}
	ifindex, ok := c.bridgeIfindex(b.BDID)
	if !ok {
		// bridgeIfindex fails closed for an absent OR ambiguous bd_id (more than one
		// bridge claims it); either way nothing is enabled here. For the absent case
		// BridgeCreate enables it when the bridge arrives; an ambiguous bd_id
		// originates nothing on either axis (the device axis refuses it too).
		c.logger.Debug("EVPN binding has no unique bridge yet (absent or ambiguous bd_id)",
			zap.String("vrf", b.VRFName), zap.Uint16("bd_id", b.BDID))
		return
	}
	// The binding axis resolves only the ifindex, not the bridge device name, so
	// pass "" -- EnableForBridge omits the bridge log field rather than mislabel.
	c.EnableForBridge(b, ifindex, "")
}

// Disable tears down a bridge domain's EVPN auto-advertise (withdraw RT2/RT3,
// release SIDs). Driven by BridgeDelete (device gone) and VrfBgpUnbind (binding
// gone); a no-op for a BD the exporter has not enabled, so calling it from both
// axes is safe.
func (c *EvpnCoordinator) Disable(bdID uint16) {
	if bdID == 0 {
		return
	}
	c.exporter.DisableBD(bdID)
}

// SIDsForBD returns the sid_function_map keys the exporter installed for the
// bridge domain, so BridgeDelete can exclude them from its reference check.
func (c *EvpnCoordinator) SIDsForBD(bdID uint16) []string {
	return c.exporter.SIDsForBD(bdID)
}
