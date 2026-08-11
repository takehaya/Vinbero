package apply

import (
	"net/netip"

	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/prober"
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
// liveness question the group actually asks. The member's terminal segment
// is the remote service SID and is deliberately not part of the probe
// journey: a service SID is not an End behavior, and per RFC 8986 its
// endpoint drops SRH-carrying packets with segments left, so probing
// "through" it could never succeed. A member whose next hop is unknown or
// unparseable yields a target with no destination, which the prober pins
// permanently up rather than failing it on probes that cannot be sent.
func probeTargets(paths []bpf.EcmpPath, dsts []string) []prober.Target {
	out := make([]prober.Target, 0, len(paths))
	for i, p := range paths {
		t := prober.Target{PathIndex: uint8(i)}
		if addr, err := netip.ParseAddr(dsts[i]); err == nil && addr.Is6() && !addr.Is4In6() {
			t.Dst = addr
		}
		n := int(p.Entry.NumSegments)
		for s := 0; s < n-1; s++ {
			t.Segments = append(t.Segments, netip.AddrFrom16(p.Entry.Segments[s]))
		}
		out = append(out, t)
	}
	return out
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
