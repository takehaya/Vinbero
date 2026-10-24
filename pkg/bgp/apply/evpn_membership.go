package apply

import (
	"net/netip"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
)

type esPathKey struct {
	esi    [bpf.ESILen]byte
	nlri   string
	source bgp.PathSource
}

type esPeerKey struct {
	esi    [bpf.ESILen]byte
	source [bpf.IPv6AddrLen]byte
}

func esRouteKey(ev bgp.RouteEvent) esPathKey {
	r := ev.EVPN
	key := esPathKey{esi: r.ESI, source: ev.Source}
	if ev.BGPPath != nil && len(ev.BGPPath.RouteKey) != 0 {
		key.nlri = string(ev.BGPPath.RouteKey)
	} else {
		// RT4 NLRI identifies the originating router independently of its
		// mutable MP_REACH next hop. Legacy in-process callers omit IPAddr.
		origin := r.IPAddr
		if origin == "" {
			origin = r.NextHop
		}
		key.nlri = r.RD + "\x00" + origin
	}
	return key
}

// applyEVPNEthernetSegment retains each RT4 path separately: replay is
// idempotent, and withdrawing one RD or reflected path cannot remove another
// path's membership. esMu also serializes RPC-triggered ReelectDF.
//
// The exact IPv6 next hop is the existing DF identity. RX membership matches
// only when the remote uses that same address as its encapsulation source
// (as in the Vinbero multihoming fixture); no locator-length guess is made.
func (a *Applier) applyEVPNEthernetSegment(ev bgp.RouteEvent) {
	r := ev.EVPN
	a.evpn.esMu.Lock()
	defer a.evpn.esMu.Unlock()
	defer func() {
		a.syncESPeers()
		a.electDF(r.ESI)
	}()
	k := esRouteKey(ev)
	addr, err := netip.ParseAddr(r.NextHop)
	valid := err == nil && addr.Is6() && !addr.Is4In6() &&
		!addr.IsUnspecified() && !addr.IsMulticast() && addr.Zone() == "" && r.ESI != [bpf.ESILen]byte{}
	var peer esPeerKey
	if valid {
		peer = esPeerKey{esi: r.ESI, source: addr.As16()}
	}
	if old, exists := a.evpn.esPaths[k]; exists {
		if !ev.IsWithdraw && valid && old == peer {
			return // still retry failed map operations in the deferred sync
		}
		delete(a.evpn.esPaths, k)
		a.evpn.esRefs[old]--
		if a.evpn.esRefs[old] == 0 {
			delete(a.evpn.esRefs, old)
			delete(a.evpn.esMembers[old.esi], netip.AddrFrom16(old.source).String())
			if len(a.evpn.esMembers[old.esi]) == 0 {
				delete(a.evpn.esMembers, old.esi)
			}
		}
	}
	if ev.IsWithdraw {
		return
	}
	if !valid {
		a.logger.Warn("EVPN RT4 has invalid ESI or IPv6 member; skipping", zap.String("rd", r.RD), zap.String("pe", r.NextHop))
		return
	}
	members := a.evpn.esMembers[r.ESI]
	if len(a.evpn.esPaths) >= maxESPaths ||
		(members == nil && len(a.evpn.esMembers) >= maxTrackedESIs) ||
		(a.evpn.esRefs[peer] == 0 && len(members) >= maxMembersPerESI) {
		a.logger.Warn("EVPN RT4 membership limit reached; skipping", zap.String("rd", r.RD), zap.String("pe", r.NextHop))
		return
	}
	if members == nil {
		members = make(map[string]struct{})
		a.evpn.esMembers[r.ESI] = members
	}
	members[addr.String()] = struct{}{}
	a.evpn.esPaths[k] = peer
	a.evpn.esRefs[peer]++
}

// syncESPeers separates desired membership from successful map writes. Failed
// creates/deletes remain pending and retry on the next RT4, replay or ReelectDF.
// The map is unpinned and has no other writer; it does not contain unicast peer
// indexes. Even failed deletions cannot grow this applied ledger without bound.
// Caller holds esMu.
func (a *Applier) syncESPeers() {
	for peer := range a.evpn.esApplied {
		if a.evpn.esRefs[peer] != 0 {
			continue
		}
		if err := a.fdbBd.DeleteEsiPeer(peer.esi, peer.source); err != nil {
			a.logger.Error("delete EVPN RX membership; retry pending", zap.Error(err))
			continue
		}
		delete(a.evpn.esApplied, peer)
	}
	for peer := range a.evpn.esRefs {
		if _, applied := a.evpn.esApplied[peer]; applied {
			continue
		}
		if len(a.evpn.esApplied) >= maxESPaths {
			a.logger.Error("EVPN RX membership full; retry pending")
			return
		}
		if err := a.fdbBd.CreateEsiPeer(peer.esi, peer.source); err != nil {
			a.logger.Error("create EVPN RX membership; retry pending", zap.Error(err))
			continue
		}
		a.evpn.esApplied[peer] = struct{}{}
	}
}
