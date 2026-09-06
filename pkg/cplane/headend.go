package cplane

import (
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/headend"
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
