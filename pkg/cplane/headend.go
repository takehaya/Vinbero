package cplane

import (
	"fmt"

	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/headend"
	"github.com/takehaya/vinbero/pkg/vrf"
)

// Compatibility names for the shared headend declaration API.
type HeadendMapOps = headend.MapOps
type AddressFamily = headend.Family
type HeadendDesired = headend.Desired
type ApplyResult = headend.Result

const (
	AFv4 = headend.AFv4
	AFv6 = headend.AFv6
)

// errNoVRFDirectory refuses a VRF name on a host that resolves none.
var errNoVRFDirectory = fmt.Errorf("this daemon resolves no VRF names for headend entries")

// declaredHeadend is one headend entry as the plugin declared it: the
// entry and the name of the VRF it named. The name is resolved to the
// vrf_id the entry is keyed by (HeadendDesired.VRF) when the set is
// written, so the two travel together.
type declaredHeadend struct {
	HeadendDesired
	VRFName string
}

// namesVRF reports whether any entry names a VRF other than the global one.
func namesVRF(sets ...[]declaredHeadend) bool {
	for _, set := range sets {
		for _, d := range set {
			if !vrf.IsGlobalName(d.VRFName) {
				return true
			}
		}
	}
	return false
}

// resolveDeclared returns the entries with each one's VRF id looked up
// from its name. An unknown VRF refuses the set; no VRF is created. The
// host does not keep a refused set: the plugin declares it again once the
// VRF exists.
func resolveDeclared(vrfs vrf.Directory, set []declaredHeadend) ([]HeadendDesired, error) {
	out := make([]HeadendDesired, len(set))
	for i, d := range set {
		out[i] = d.HeadendDesired
		out[i].VRF = vrf.GlobalVRFID
		if vrf.IsGlobalName(d.VRFName) {
			continue
		}
		if vrfs == nil {
			return nil, errNoVRFDirectory
		}
		id, err := vrfs.LookupID(d.VRFName)
		if err != nil {
			return nil, fmt.Errorf("headend entry for %q: %w", d.TriggerPrefix, err)
		}
		out[i].VRF = id
	}
	return out, nil
}

// holdDeclared takes the VRF hold a write of these sets needs: it holds the
// VRFs against the start of their deletion and resolves the names, and the
// caller writes the result and then releases, doing nothing else in
// between. A set naming only the global VRF takes no hold.
func holdDeclared(vrfs vrf.Directory, sets ...[]declaredHeadend) (out [][]HeadendDesired, release func(), err error) {
	release = func() {}
	if namesVRF(sets...) && vrfs != nil {
		release = vrfs.HoldIDs()
	}
	for _, set := range sets {
		resolved, err := resolveDeclared(vrfs, set)
		if err != nil {
			release()
			return nil, nil, err
		}
		out = append(out, resolved)
	}
	return out, release, nil
}

// heldVRFName names the VRF of an entry the plugin already holds, for
// re-checking it against the scope; false for an id no VRF holds.
func heldVRFName(vrfs vrf.Directory, id uint32) (string, bool) {
	if id == vrf.GlobalVRFID {
		return vrf.GlobalVRFName, true
	}
	if vrfs == nil {
		return "", false
	}
	return vrfs.NameOf(id)
}

// ApplyHeadendSet is the stateless compatibility API. Callers must serialize
// it with other writers. The daemon uses a shared headend.Reconciler instead.
func ApplyHeadendSet(ops HeadendMapOps, leases *Leases, owner bpf.OwnerTag, af AddressFamily, desired []HeadendDesired, quota int) (ApplyResult, error) {
	return headend.ApplySet(ops, leases, owner, af, desired, quota)
}

func PruneHeadendOwner(ops HeadendMapOps, leases *Leases, owner bpf.OwnerTag, af AddressFamily) (int, error) {
	return headend.PruneOwner(ops, leases, owner, af)
}

func OwnedHeadendEntries(ops HeadendMapOps, owner bpf.OwnerTag, af AddressFamily) ([]HeadendDesired, error) {
	return headend.OwnedEntries(ops, owner, af)
}
