package cplane

import "net/netip"

// BGPPathKey identifies a received path using the host's canonical destination key.
// Attributes, metadata and non-key NLRI fields do not participate in identity.
type BGPPathKey struct {
	Codec       string
	AFI         uint16
	SAFI        uint8
	Destination string
	Peer        string
	PathID      uint32
}

// BGPKey also works when attribute encoding failed. Do not discard such an
// update before removing the prior version of this key from an input view.
func (r Route) BGPKey() (BGPPathKey, bool) {
	p := r.BGPPath
	if p == nil || p.Codec != BGPPathCodec || p.AFI == 0 || p.SAFI == 0 || len(p.RouteKey) == 0 {
		return BGPPathKey{}, false
	}
	peer, err := netip.ParseAddr(r.Peer)
	if err != nil {
		return BGPPathKey{}, false
	}
	return BGPPathKey{p.Codec, p.AFI, p.SAFI, string(p.RouteKey), peer.String(), r.PathID}, true
}
