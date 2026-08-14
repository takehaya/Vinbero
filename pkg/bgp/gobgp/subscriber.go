package gobgp

import (
	"context"
	"fmt"
	"time"

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	gobgpsrv "github.com/osrg/gobgp/v4/pkg/server"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// compile-time assertion that *Session also satisfies RouteSubscriber.
var _ bgp.RouteSubscriber = (*Session)(nil)

// Subscribe registers handler for post-policy route updates. The cancel
// func tears down the underlying gobgp watcher; callers must invoke it
// to avoid leaking the watch goroutine.
//
// handler is called from a gobgp-internal goroutine and must not block
// (see bgp.RouteHandler). filter restricts delivery to one family; an
// empty filter delivers every supported family.
func (s *Session) Subscribe(filter bgp.Family, handler bgp.RouteHandler) (func(), error) {
	srv := s.bgpServer()
	if srv == nil {
		return nil, bgp.ErrSessionNotStarted
	}
	ctx, cancel := context.WithCancel(context.Background())
	cbs := gobgpsrv.WatchEventMessageCallbacks{
		OnPathUpdate: func(paths []*apiutil.Path, _ time.Time) {
			for _, p := range paths {
				ev, ok := pathToRouteEvent(p)
				if !ok {
					continue // family Vinbero does not consume
				}
				if filter != "" && ev.Family != filter {
					continue
				}
				handler(ev)
			}
		},
	}
	// WatchPostUpdate: post-import-policy routes, which is what the data
	// plane should mirror. current=true replays the existing RIB so a
	// subscriber that attaches after peers are up still sees them.
	//
	// INVARIANT: Subscribe is called exactly once per daemon, by the demux
	// (pkg/bgp/demux), which every consumer registers with instead of
	// calling this directly. A second Subscribe would open a second
	// current=true watch and replay the loc-rib into whoever attached late.
	//
	// The replay and the live stream both carry this node's own
	// advertisements once anything in the process advertises, so a consumer
	// acting on them would install self-pointing state (an own EVPN RT3
	// becomes a BUM peer aimed back here). Local-origin paths are therefore
	// dropped by the demux on both paths; do not rely on subscribe-before-
	// advertise ordering for that. (ListRoutes, the on-demand rib snapshot,
	// filters local-origin paths itself for the same reason.)
	if err := srv.WatchEvent(ctx, cbs, gobgpsrv.WatchPostUpdate(true, "", "")); err != nil {
		cancel()
		return nil, fmt.Errorf("watch event: %w", err)
	}
	return cancel, nil
}

// pathToRouteEvent converts a gobgp received Path into a Vinbero
// RouteEvent. VPN families are fully decoded (RD / prefix / SRv6 SID /
// route targets / next hop); IPv6 unicast carries prefix and next hop.
//
// This is the single conversion point for both the live subscription and
// the loc-rib snapshot, so the path identity it attaches below reaches
// every consumer of either.
func pathToRouteEvent(p *apiutil.Path) (bgp.RouteEvent, bool) {
	fam, ok := apiFamilyToVinbero(p.Family)
	if !ok {
		return bgp.RouteEvent{}, false
	}
	ev := bgp.RouteEvent{
		Family:     fam,
		Source:     pathSource(p),
		IsWithdraw: p.Withdrawal,
	}
	switch fam {
	case bgp.FamilyVPNv4, bgp.FamilyVPNv6:
		ev.VPN = decodeVPNRoute(p, fam)
	case bgp.FamilyIPv6Unicast:
		ev.Unicast = &bgp.UnicastRoute{
			Prefix:  nlriString(p.Nlri),
			NextHop: decodeNextHop(p.Attrs),
		}
	case bgp.FamilySRPolicyIPv6:
		ev.SRPolicy = decodeSRPolicy(p)
	case bgp.FamilyEVPN:
		ev.EVPN = decodeEVPNRoute(p)
	case bgp.FamilyMUPIPv4, bgp.FamilyMUPIPv6:
		ev.MUP = decodeMUPRoute(p)
	}
	ev.EndpointBehavior = decodeEndpointBehavior(p.Attrs)
	ev.UnknownAttrs = decodeUnknownAttrs(p.Attrs)
	return ev, true
}

// decodeEndpointBehavior returns the SRv6 Endpoint Behavior codepoint of
// the path's service SID, or 0 when it carries none.
//
// It reads the codepoint straight off the wire without checking it against
// the behaviors Vinbero implements: an unrecognized value is the whole
// point, since that is what an operator's own behavior looks like here and
// what a plugin claims. Transposition does not apply -- only the SID bytes
// are transposed, never the behavior field -- so this needs no label.
func decodeEndpointBehavior(attrs []gobgppkt.PathAttributeInterface) uint16 {
	for _, a := range attrs {
		psid, ok := a.(*gobgppkt.PathAttributePrefixSID)
		if !ok {
			continue
		}
		for _, tlv := range psid.TLVs {
			svc, ok := tlv.(*gobgppkt.SRv6ServiceTLV)
			if !ok {
				continue
			}
			for _, st := range svc.SubTLVs {
				info, ok := st.(*gobgppkt.SRv6InformationSubTLV)
				if !ok || len(info.SID) != 16 {
					continue
				}
				// First SID wins, matching srv6L2ServiceSIDBytes so the
				// behavior always describes the SID the rest of the decode
				// settled on.
				return info.EndpointBehavior
			}
		}
	}
	return 0
}

// decodeUnknownAttrs carries through the path attributes gobgp could not
// type, so a consumer that understands one can read it. Returns nil for the
// common case of a path with no unknown attribute.
//
// The bytes are copied: gobgp owns the decoded path and a consumer may keep
// the event past this call.
func decodeUnknownAttrs(attrs []gobgppkt.PathAttributeInterface) []bgp.UnknownAttribute {
	var out []bgp.UnknownAttribute
	for _, a := range attrs {
		u, ok := a.(*gobgppkt.PathAttributeUnknown)
		if !ok {
			continue
		}
		out = append(out, bgp.UnknownAttribute{
			Type:  uint8(u.GetType()),
			Flags: uint8(u.GetFlags()),
			Value: append([]byte(nil), u.Value...),
		})
	}
	return out
}

// pathSource extracts the path's identity: which neighbor sent it and,
// when ADD-PATH receive is negotiated, which of that neighbor's paths it
// is. gobgp names the received ADD-PATH identifier RemoteID (LocalID is
// the id gobgp would use when re-advertising, which is not this path's
// identity on the wire we learned it from).
//
// A locally originated path has no source address, which leaves Peer as
// the zero Addr and makes PathSource.IsLocal report true.
func pathSource(p *apiutil.Path) bgp.PathSource {
	return bgp.PathSource{Peer: p.PeerAddress, PathID: p.RemoteID}
}

// apiFamilyToVinbero maps a gobgp route family to a Vinbero Family.
// Unsupported families return ok=false so the caller skips them.
func apiFamilyToVinbero(f gobgppkt.Family) (bgp.Family, bool) {
	switch f {
	case gobgppkt.RF_IPv4_VPN:
		return bgp.FamilyVPNv4, true
	case gobgppkt.RF_IPv6_VPN:
		return bgp.FamilyVPNv6, true
	case gobgppkt.RF_IPv6_UC:
		return bgp.FamilyIPv6Unicast, true
	case gobgppkt.RF_SR_POLICY_IPv6:
		return bgp.FamilySRPolicyIPv6, true
	case gobgppkt.RF_EVPN:
		return bgp.FamilyEVPN, true
	case gobgppkt.RF_MUP_IPv4:
		return bgp.FamilyMUPIPv4, true
	case gobgppkt.RF_MUP_IPv6:
		return bgp.FamilyMUPIPv6, true
	default:
		return "", false
	}
}
