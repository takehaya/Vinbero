package apply

import (
	"net/netip"

	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/prober"
	"go.uber.org/zap"
)

// SetProber hands the applier the liveness prober to keep in sync with the
// ECMP groups it programs. Must be called before the BGP session starts
// (alongside NewApplier); the default is the no-op registry.
func (a *Applier) SetProber(p prober.Registry) {
	a.prober = p
}

// probeTargets renders one prober target per programmed group member.
//
// The probe traverses the member's transport segments and terminates at
// dsts[i] -- the advertising PE's routable address (its BGP next hop), the
// liveness question the group actually asks. A member steered onto an SR
// Policy prepends the policy's installed transport, mirroring what the XDP
// program composes ahead of the service SID, so the probe walks the same
// waypoints the traffic does. The member's terminal segment is the remote
// service SID and is deliberately not part of the probe journey: a service
// SID is not an End behavior, and per RFC 8986 its endpoint drops
// SRH-carrying packets with segments left, so probing "through" it could
// never succeed. A member whose next hop is unknown or unparseable yields a
// target with no destination, which the prober pins permanently up rather
// than failing it on probes that cannot be sent.
func (a *Applier) probeTargets(paths []bpf.EcmpPath, dsts []string) []prober.Target {
	out := make([]prober.Target, 0, len(paths))
	for i, p := range paths {
		t := prober.Target{PathIndex: uint8(i)}
		// The two slices are built pairwise by every caller; a future
		// producer that filters one but not the other must degrade to an
		// unprobeable (pinned-up) path, not panic or probe the wrong PE.
		if i < len(dsts) {
			if addr, err := netip.ParseAddr(dsts[i]); err == nil && addr.Is6() && !addr.Is4In6() {
				t.Dst = addr
			}
		}
		// An id whose policy is not (yet) installed contributes nothing: the
		// XDP lookup-miss falls the member back to its bare service SID, and
		// the probe matches that by going straight to the PE.
		//
		// The transport's own terminal segment is dropped too, for a reason
		// specific to the probe's shape: an SR Policy's last segment lands on
		// the policy endpoint, and a Linux endpoint's End behavior refuses to
		// forward to an address the node itself owns (the post-End lookup
		// excludes local routes as an anti-loop measure and the packet hits a
		// discard dst). Traffic never notices -- after that End it proceeds
		// to the service SID, a route, not a local address -- but a probe
		// whose next hop after the terminal End is the same node's loopback
		// would be dropped there forever, permanently failing a healthy
		// path. Ending the journey at Dst instead asks the same node the
		// same liveness question. The cost is real but bounded: a terminal
		// transport segment on a node other than the endpoint goes unprobed.
		if tr := a.srPolicy.transportOf(p.Entry.PolicyId); len(tr) > 1 {
			t.Segments = append(t.Segments, tr[:len(tr)-1]...)
		}
		n := int(p.Entry.NumSegments)
		for s := 0; s < n-1; s++ {
			t.Segments = append(t.Segments, netip.AddrFrom16(p.Entry.Segments[s]))
		}
		out = append(out, t)
	}
	return out
}

// reprobeSRPolicy re-registers the probe targets of every VPN group with a
// member steered onto key, after that policy's installed transport changed.
// The groups' data-plane entries need no rewrite -- they reference the policy
// by its stable id -- but a probe registration embeds the transport itself,
// so leaving the old one standing would probe a journey the traffic no
// longer takes: it could fail a member that forwards fine, or keep reporting
// a dead transport as up. Invoked from the srPolicyTable's transport-change
// hook, on whichever goroutine changed the policy (the BGP route handler or
// an SRPolicyService RPC).
func (a *Applier) reprobeSRPolicy(key policyKey) {
	a.vpnMu.Lock()
	defer a.vpnMu.Unlock()
	for dk, d := range a.vpnGroups.dests {
		if d.installed == nil {
			// Never programmed (or the last write failed): there is no
			// registration to refresh and reconcile owns the retry.
			continue
		}
		ms := d.members()
		steered := false
		for _, m := range ms {
			if m.steer != nil && *m.steer == key {
				steered = true
				break
			}
		}
		if !steered {
			continue
		}
		paths := make([]bpf.EcmpPath, 0, len(ms))
		rebuilt := true
		for _, m := range ms {
			entry, err := a.buildHeadendEntry(m.sid)
			if err != nil {
				a.logger.Error("rebuild probe targets after SR Policy transport change",
					zap.String("prefix", dk.prefix), zap.String("sid", m.sid), zap.Error(err))
				rebuilt = false
				break
			}
			if m.steer != nil {
				entry.PolicyId = a.srPolicy.idOf(m.steer.color, m.steer.endpoint)
			}
			paths = append(paths, bpf.EcmpPath{Entry: entry, Weight: 1})
		}
		if !rebuilt {
			// A registration that cannot be refreshed describes the old
			// journey; failing open beats failing a healthy member on it.
			a.prober.Unregister(d.groupID)
			continue
		}
		dsts := make([]string, len(ms))
		for i, m := range ms {
			dsts[i] = m.nh
		}
		a.prober.Register(d.groupID, a.probeTargets(paths, dsts))
	}
}

// EncapSourceAddr resolves the SRv6 encapsulation source as an address, for
// callers outside the applier (the prober stamps it as the probe source).
func (a *Applier) EncapSourceAddr() (netip.Addr, error) {
	src, err := a.encapSource()
	if err != nil {
		return netip.Addr{}, err
	}
	return netip.AddrFrom16(src), nil
}
