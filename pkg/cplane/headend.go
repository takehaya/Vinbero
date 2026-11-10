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

// VRFDirectory resolves the VRF a headend declaration names to the vrf_id
// its entry is keyed by. *vrf.Manager satisfies it.
type VRFDirectory interface {
	// LookupID resolves a name without creating the VRF: "" and "global"
	// are vrf 0, an unknown name is an error.
	LookupID(name string) (uint32, error)
	// NameOf names the VRF holding id.
	NameOf(id uint32) (string, bool)
	// HoldIDs keeps every VRF from being deleted until release is called.
	HoldIDs() (release func())
}

// errNoVRFDirectory refuses a VRF name on a host that resolves none.
var errNoVRFDirectory = fmt.Errorf("this daemon resolves no VRF names for headend entries")

// resolveHeadendVRFs returns entries with each one's VRF set to the id of
// the name at the same index, and holds the VRFs against deletion until
// release is called; the caller writes the entries before it does. A set
// naming only the global VRF comes back as it is, with no hold. An unknown
// VRF refuses the set, as an unknown locator does: no VRF is created, and
// the retry that follows a failed apply tries again.
func resolveHeadendVRFs(vrfs VRFDirectory, entries []HeadendDesired, names []string) ([]HeadendDesired, func(), error) {
	named := false
	for _, name := range names {
		if !isGlobalVRFName(name) {
			named = true
			break
		}
	}
	if !named {
		return entries, func() {}, nil
	}
	if vrfs == nil {
		return nil, nil, errNoVRFDirectory
	}
	release := vrfs.HoldIDs()
	out := make([]HeadendDesired, len(entries))
	for i, e := range entries {
		out[i] = e
		if i >= len(names) || isGlobalVRFName(names[i]) {
			out[i].VRF = vrf.GlobalVRFID
			continue
		}
		id, err := vrfs.LookupID(names[i])
		if err != nil {
			release()
			return nil, nil, fmt.Errorf("headend entry for %q: %w", e.TriggerPrefix, err)
		}
		out[i].VRF = id
	}
	return out, release, nil
}

// headendVRFName names the VRF of an entry the plugin already holds, for
// re-checking it against the scope: "" for the global VRF, false for an id
// no VRF holds.
func headendVRFName(vrfs VRFDirectory, id uint32) (string, bool) {
	if id == vrf.GlobalVRFID {
		return "", true
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
