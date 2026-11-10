package server

import (
	"slices"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/locator"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// vpnFamilies are the families the VPN loc-rib replay re-evaluates.
var vpnFamilies = []bgp.Family{bgp.FamilyVPNv4, bgp.FamilyVPNv6}

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

// SourceLocatorReconciler rewrites what the BGP applier tracks once the
// source locator is registered (implemented by *apply.Applier).
type SourceLocatorReconciler interface {
	ReconcileSourceLocator()
}

// sourceLocatorHooks wraps the locator add and delete with what the BGP
// source locator (bgp.global.source_locator) needs. Every headend entry the
// applier writes takes its encapsulation source from that locator, and the
// locator is often created over RPC after the daemon, and so its BGP
// sessions, are already up:
//
//   - Registering it rewrites the routes the applier tracks: those received
//     while it was missing are written, and those already written take the
//     new prefix if it changed. The EVPN loc-rib is replayed as well, since
//     an EVPN route that could not be written is not tracked.
//   - Deleting it leaves written entries forwarding with the source they
//     have; it logs one warning, and nothing is rewritten until the locator
//     is registered again.
//
// add and del are returned unchanged when BGP or the source locator is not
// configured.
func (s *Server) sourceLocatorHooks(add func(*locator.Locator) error, del func(string, bool) error) (func(*locator.Locator) error, func(string, bool) error) {
	source := s.cfg.BGP.Global.SourceLocator
	if source == "" || s.srcLocator == nil || add == nil || del == nil {
		return add, del
	}
	wrappedAdd := func(loc *locator.Locator) error {
		if err := add(loc); err != nil {
			return err
		}
		if loc.Name == source {
			s.srcLocator.ReconcileSourceLocator()
			if s.evpnReplay != nil {
				s.evpnReplay()
			}
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
