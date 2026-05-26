package apply

import (
	"fmt"
	"net"
	"net/netip"

	"go.uber.org/zap"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// fdbBdOps is the subset of bpf.MapOperations the EVPN applier writes:
// the FDB (MAC -> peer) and the per-PE bd_peer encap entry.
type fdbBdOps interface {
	CreateFdb(bdID uint16, mac net.HardwareAddr, entry *bpf.FdbEntry) error
	DeleteFdb(bdID uint16, mac net.HardwareAddr) error
	CreateBdPeer(bdID, index uint16, entry *bpf.HeadendEntry, esi [bpf.ESILen]byte) error
	DeleteBdPeer(bdID, index uint16) error
	// FindFreeBdPeerIndex returns the lowest bd_peer index not in use in the
	// real map, so a BGP-allocated peer never collides with an operator-created
	// or restart-pinned entry.
	FindFreeBdPeerIndex(bdID uint16) uint16
}

// evpnPeerKey identifies a remote PE within a bridge domain by its End.DT2U
// transport SID. Every MAC learned from that PE shares one bd_peer entry.
type evpnPeerKey struct {
	bdID uint16
	sid  string
}

// evpnFdbKey is the stable identity of an RT2 NLRI ({RD, EthernetTag, MAC}),
// used as a reverse index so a withdrawal -- whose path attributes (route
// targets, Prefix-SID) may be absent -- can still find the bridge domain and
// peer the advertisement installed.
type evpnFdbKey struct {
	rd   string
	etag uint32
	mac  string
}

type evpnPeerState struct {
	index uint16
	refs  int
}

type evpnFdbState struct {
	bdID uint16
	mac  net.HardwareAddr
	peer evpnPeerKey
}

// evpnTable holds the EVPN applier's in-memory bookkeeping. It is touched
// only from the single GoBGP RouteHandler goroutine (like steeredRoutes),
// so it needs no locking.
type evpnTable struct {
	peers map[evpnPeerKey]*evpnPeerState
	fdb   map[evpnFdbKey]evpnFdbState
}

func newEVPNTable() *evpnTable {
	return &evpnTable{
		peers: make(map[evpnPeerKey]*evpnPeerState),
		fdb:   make(map[evpnFdbKey]evpnFdbState),
	}
}

// allocIndex returns a stable bd_peer index for key, reusing the existing one
// (and bumping its reference count) when the PE already has a peer in this BD.
// For a new peer it takes the index from newIdx -- backed by the real
// bd_peer_map via FindFreeBdPeerIndex -- so the slot never collides with an
// operator-created or restart-pinned entry. ok is false when the BD is full.
func (t *evpnTable) allocIndex(key evpnPeerKey, newIdx func() uint16) (uint16, bool) {
	if st, ok := t.peers[key]; ok {
		st.refs++
		return st.index, true
	}
	idx := newIdx()
	if idx >= bpf.MaxBumNexthops {
		return 0, false
	}
	t.peers[key] = &evpnPeerState{index: idx, refs: 1}
	return idx, true
}

// releaseIndex drops one reference to key's peer and reports whether the peer
// is now unreferenced (so the caller deletes the bd_peer).
func (t *evpnTable) releaseIndex(key evpnPeerKey) (uint16, bool) {
	st, ok := t.peers[key]
	if !ok {
		return 0, false
	}
	st.refs--
	if st.refs > 0 {
		return st.index, false
	}
	delete(t.peers, key)
	return st.index, true
}

func (a *Applier) applyEVPN(r *bgp.EVPNRoute, withdraw bool) {
	switch r.Type {
	case bgp.EVPNRouteTypeMACIP:
		a.applyEVPNMacIP(r, withdraw)
	default:
		// RT3 (Inclusive Multicast) and RT4 (Ethernet Segment) arrive in
		// later phases; ignore them until then.
	}
}

func (a *Applier) applyEVPNMacIP(r *bgp.EVPNRoute, withdraw bool) {
	if r.MAC == "" {
		a.logger.Warn("EVPN RT2 has no MAC; skipping", zap.String("rd", r.RD))
		return
	}
	fk := evpnFdbKey{rd: r.RD, etag: r.EthernetTag, mac: r.MAC}

	if withdraw {
		// A withdrawal may carry no route targets, so the bridge domain and
		// peer are recovered from the reverse index rather than re-resolved
		// from RTs. An unknown withdraw is a no-op.
		if st, ok := a.evpn.fdb[fk]; ok {
			a.withdrawEVPNMac(fk, st)
		}
		return
	}

	mac, err := net.ParseMAC(r.MAC)
	if err != nil {
		a.logger.Error("parse EVPN MAC", zap.String("mac", r.MAC), zap.Error(err))
		return
	}
	// An EVPN route installs only into an explicitly bound bridge domain: the
	// route targets must match a VRF binding that carries a BDID. Unlike the
	// L3VPN path, an empty binding manager does not accept everything, because
	// there is no bridge domain to install into without a binding.
	bdID, ok := a.vrfBindings.MatchImportBD(r.RTs)
	if !ok {
		a.logger.Warn("EVPN RT2 matches no bridge-domain binding; dropping",
			zap.String("mac", r.MAC), zap.Strings("rts", r.RTs))
		return
	}
	if r.SRv6SID == "" {
		a.logger.Warn("EVPN RT2 has no SRv6 SID; skipping",
			zap.String("mac", r.MAC), zap.String("rd", r.RD))
		return
	}
	// The End.DT2U SID must be a usable SRv6 (IPv6) SID. A crafted route with
	// an unspecified (::) or IPv4-mapped SID would otherwise install a
	// black-hole / wrong-target bd_peer, so reject it here (the SR Policy
	// decode applies the same guard to transport SIDs).
	if sid, err := netip.ParseAddr(r.SRv6SID); err != nil || !sid.Is6() || sid.Is4In6() || sid.IsUnspecified() {
		a.logger.Warn("EVPN RT2 SID is not a usable IPv6 SID; skipping",
			zap.String("mac", r.MAC), zap.String("sid", r.SRv6SID))
		return
	}
	pk := evpnPeerKey{bdID: bdID, sid: r.SRv6SID}

	// Re-advertise / MAC move: this NLRI ({RD, EthernetTag, MAC}) is already
	// installed. If nothing changed, return without re-referencing the peer --
	// a second allocIndex would bump refs with no matching withdraw and leak
	// the bd_peer slot (mirrors steer()'s reverse-index diff). If the MAC moved
	// to a different PE/BD, tear the old mapping down first so its peer ref and
	// FDB entry are released before the new one is installed.
	if prev, ok := a.evpn.fdb[fk]; ok {
		if prev.peer == pk && prev.bdID == bdID {
			return
		}
		a.withdrawEVPNMac(fk, prev)
	}

	entry, err := a.buildL2HeadendEntry(r.SRv6SID, bdID)
	if err != nil {
		a.logger.Error("build EVPN headend entry",
			zap.String("mac", r.MAC), zap.Error(err))
		return
	}
	idx, ok := a.evpn.allocIndex(pk, func() uint16 { return a.fdbBd.FindFreeBdPeerIndex(bdID) })
	if !ok {
		a.logger.Error("EVPN bridge domain is full; cannot add peer",
			zap.Uint16("bd_id", bdID), zap.String("sid", r.SRv6SID))
		return
	}
	if err := a.fdbBd.CreateBdPeer(bdID, idx, entry, r.ESI); err != nil {
		a.logger.Error("install EVPN bd_peer",
			zap.Uint16("bd_id", bdID), zap.Error(err))
		a.evpn.releaseIndex(pk)
		return
	}
	fdb := &bpf.FdbEntry{IsRemote: 1, PeerIndex: idx, BdId: bdID, Esi: r.ESI}
	if err := a.fdbBd.CreateFdb(bdID, mac, fdb); err != nil {
		a.logger.Error("install EVPN FDB", zap.String("mac", r.MAC), zap.Error(err))
		if rIdx, gone := a.evpn.releaseIndex(pk); gone {
			_ = a.fdbBd.DeleteBdPeer(bdID, rIdx)
		}
		return
	}
	a.evpn.fdb[fk] = evpnFdbState{bdID: bdID, mac: mac, peer: pk}
	a.logger.Info("EVPN MAC installed",
		zap.String("mac", r.MAC), zap.Uint16("bd_id", bdID), zap.String("sid", r.SRv6SID))
}

// withdrawEVPNMac removes the FDB entry recorded for fk and releases its peer
// reference, deleting the bd_peer when the last MAC stops referencing it. The
// caller holds the only goroutine that touches evpnTable.
func (a *Applier) withdrawEVPNMac(fk evpnFdbKey, st evpnFdbState) {
	if err := a.fdbBd.DeleteFdb(st.bdID, st.mac); err != nil {
		// The FDB entry is still in the map. Keep the reverse index so a
		// later retry can find and remove it; dropping it here would orphan
		// the map entry and the peer reference it holds.
		a.logger.Error("withdraw EVPN MAC",
			zap.String("mac", st.mac.String()), zap.Error(err))
		return
	}
	delete(a.evpn.fdb, fk)
	if idx, gone := a.evpn.releaseIndex(st.peer); gone {
		if err := a.fdbBd.DeleteBdPeer(st.bdID, idx); err != nil {
			// The bd_peer is still in the map but releaseIndex already
			// dropped it from the ledger. Re-pin the index (refs 0) so a
			// re-learn of this PE reuses the surviving entry instead of
			// allocating a duplicate and leaking the slot.
			a.evpn.peers[st.peer] = &evpnPeerState{index: idx, refs: 0}
			a.logger.Error("delete EVPN bd_peer",
				zap.Uint16("bd_id", st.bdID), zap.Uint16("index", idx), zap.Error(err))
		}
	}
}

// buildL2HeadendEntry assembles an H.Encaps.L2 entry that encapsulates the
// matched L2 frame toward a remote PE's End.DT2U SID. SrcAddr is the local
// encap source (the outer IPv6 source on the wire); the destination is the
// SID, taken from Segments[0] by the data plane, so DstAddr is left unset to
// match the server's L2 peer construction.
func (a *Applier) buildL2HeadendEntry(sid string, bdID uint16) (*bpf.HeadendEntry, error) {
	src, err := a.encapSource()
	if err != nil {
		return nil, err
	}
	segments, numSegments, err := bpf.ParseSegments([]string{sid})
	if err != nil {
		return nil, fmt.Errorf("parse End.DT2U SID %q: %w", sid, err)
	}
	return &bpf.HeadendEntry{
		Mode:        uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2),
		NumSegments: numSegments,
		SrcAddr:     src,
		Segments:    segments,
		BdId:        bdID,
	}, nil
}
