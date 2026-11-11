package server

import (
	"slices"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/locator"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// vpnFamilies are the families the loc-rib replay re-evaluates when the
// import filter changes: the routes placed in the VRFs that import them,
// L3VPN and MUP.
var vpnFamilies = []bgp.Family{bgp.FamilyVPNv4, bgp.FamilyVPNv6, bgp.FamilyMUPIPv4, bgp.FamilyMUPIPv6}

// vpnImportFilterHook turns the binding manager's import filter changes into
// VPN loc-rib replay requests. The import-RT filter decides a route once,
// when it arrives, and the watch stream never sends it again, so every route
// already received has to be evaluated again whenever the filter changes:
// an added import RT brings in routes that were dropped, a removed RT or
// binding takes out routes no VRF imports any more, the first binding of a
// family ends its default-allow and removing the last one restores it.
// request must not block (vpnReplayer.request does not).
func vpnImportFilterHook(request func([]bgp.Family), logger *zap.Logger) func([]vrfbgp.ImportFilterChange) {
	return func(changes []vrfbgp.ImportFilterChange) {
		var families []bgp.Family
		for _, c := range changes {
			if !slices.Contains(vpnFamilies, c.Family) {
				continue
			}
			families = append(families, c.Family)
			if c.After == vrfbgp.ImportFilterDefaultAllow {
				logger.Warn("no VRF binding declares the family any more; it is default-allow again, and every received route of it is installed",
					zap.String("family", string(c.Family)))
			}
		}
		if len(families) > 0 {
			request(families)
		}
	}
}

// TrackedReconciler writes what the BGP applier tracks but has not written
// (implemented by *apply.Applier).
type TrackedReconciler interface {
	ReconcileTracked() error
}

// trackedRetrySetter is the part of *apply.Applier that reports tracked
// writes failing outside ReconcileTracked, so the replayer retries them.
type trackedRetrySetter interface {
	SetTrackedRetry(func())
}

// sourceLocatorHooks wraps the locator add and delete with what the BGP
// source locator (bgp.global.source_locator) needs. Every headend entry the
// applier writes takes its encapsulation source from that locator, and the
// locator is often created over RPC after the daemon, and so its BGP
// sessions, are already up:
//
//   - Registering it writes the routes the applier tracks within the RPC:
//     those received while it was missing, and those already written whose
//     source moved with the locator's prefix. It then requests a replay of
//     the EVPN loc-rib, since an EVPN route that could not be written is not
//     tracked. That replay runs the tracked pass again, and the replayer
//     retries what still fails (see vpnReplayer), so a write that fails
//     here converges. The locator stays registered and the RPC succeeds
//     either way.
//   - Deleting it leaves written entries forwarding with the source they
//     have; it logs one warning, and nothing is rewritten until the locator
//     is registered again.
//
// add and del are returned unchanged when BGP or the source locator is not
// configured.
func (s *Server) sourceLocatorHooks(add func(*locator.Locator) error, del func(string, bool) error, requestReplay func([]bgp.Family)) (func(*locator.Locator) error, func(string, bool) error) {
	source := s.cfg.BGP.Global.SourceLocator
	if source == "" || s.tracked == nil || requestReplay == nil || add == nil || del == nil {
		return add, del
	}
	wrappedAdd := func(loc *locator.Locator) error {
		if err := add(loc); err != nil {
			return err
		}
		if loc.Name == source {
			if err := s.tracked.ReconcileTracked(); err != nil {
				s.logger.Warn("writing routes after the source locator was registered failed; retrying",
					zap.String("locator", loc.Name), zap.Error(err))
			}
			requestReplay([]bgp.Family{bgp.FamilyEVPN})
		}
		return nil
	}
	wrappedDel := func(name string, force bool) error {
		if err := del(name, force); err != nil {
			return err
		}
		if name == source {
			s.logger.Warn("BGP source locator deleted; installed routes keep their encapsulation source, and routes received from now on are not installed until it is registered again",
				zap.String("locator", name))
		}
		return nil
	}
	return wrappedAdd, wrappedDel
}
