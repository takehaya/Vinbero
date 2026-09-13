package apply

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
)

type vpnDiagnostic uint8

const (
	vpnPathOK vpnDiagnostic = iota
	vpnImportDenied
	vpnSIDMissing
	vpnSteeringInvalidNextHop
	vpnSteeringNonIPv6NextHop
)

// selectVPNPath evaluates one replacement advertisement. The caller resolves
// importAllowed from the current family bindings and removes the previous path
// when the result is nil. Diagnostics for steering leave the path eligible for
// unsteered forwarding. The caller manages policy references for all retained
// candidates, including those outside the programmed ECMP set.
func selectVPNPath(vr *bgp.VPNRoute, importAllowed bool) (*vpnPath, vpnDiagnostic) {
	if !importAllowed {
		return nil, vpnImportDenied
	}
	// Decode already removes unusable SID information. A replacement without
	// a service SID must also remove any previously accepted version of the path.
	if vr.SRv6SID == "" {
		return nil, vpnSIDMissing
	}
	path := &vpnPath{sid: vr.SRv6SID, reduced: vr.SIDStructure.IsUSID(), nh: vr.NextHop}
	if vr.Color == 0 {
		return path, vpnPathOK
	}
	endpoint, err := netip.ParseAddr(vr.NextHop)
	if err != nil {
		return path, vpnSteeringInvalidNextHop
	}
	if !endpoint.Is6() {
		return path, vpnSteeringNonIPv6NextHop
	}
	path.steer = &policyKey{color: vr.Color, endpoint: endpoint}
	return path, vpnPathOK
}

// selectVPNMembers picks the paths to program, in a deterministic order.
//
// Sorting matters beyond tidiness: the data plane selects by hash modulo
// the member list, so if the order depended on Go's map iteration the same
// set of paths would spread flows differently on every reconcile and every
// restart. Sorting by SID pins it.
//
// Two paths that resolve to the same SID are the same forwarding outcome
// (typically one PE re-advertised under a second RD), so they are deduped:
// programming both would silently double that PE's share of the traffic.
func selectVPNMembers(paths map[vpnPathKey]*vpnPath) []*vpnPath {
	type keyed struct {
		key vpnPathKey
		p   *vpnPath
	}
	all := make([]keyed, 0, len(paths))
	for k, p := range paths {
		all = append(all, keyed{k, p})
	}
	// SID orders the members, but SortFunc is not stable and two paths can
	// share a SID, so the key breaks the tie. Without it the survivor of the
	// dedupe below would depend on map iteration order -- and since the paths
	// sharing a SID can carry different colors, the programmed policy id
	// would flip between reconciles and defeat the unchanged-set skip.
	slices.SortFunc(all, func(a, b keyed) int {
		if c := cmp.Compare(a.p.sid, b.p.sid); c != 0 {
			return c
		}
		if c := cmp.Compare(a.key.rd, b.key.rd); c != 0 {
			return c
		}
		if c := cmp.Compare(a.key.source.Peer.String(), b.key.source.Peer.String()); c != 0 {
			return c
		}
		return cmp.Compare(a.key.source.PathID, b.key.source.PathID)
	})
	out := make([]*vpnPath, 0, len(all))
	for _, k := range all {
		out = append(out, k.p)
	}
	out = slices.CompactFunc(out, func(a, b *vpnPath) bool { return a.sid == b.sid })
	if len(out) > bpf.EcmpMaxPaths {
		out = out[:bpf.EcmpMaxPaths]
	}
	return out
}

// memberFingerprint renders the programmed member set so an unchanged
// reconcile can be skipped. The steering target is part of it: a path whose
// color changed keeps its SID but must be rewritten with a new policy id.
func memberFingerprint(ms []*vpnPath) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		if m.steer == nil {
			out[i] = fmt.Sprintf("%s>%s;r=%t", m.sid, m.nh, m.reduced)
			continue
		}
		out[i] = fmt.Sprintf("%s@%d/%s>%s;r=%t", m.sid, m.steer.color, m.steer.endpoint, m.nh, m.reduced)
	}
	return out
}
