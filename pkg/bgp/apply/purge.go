package apply

import (
	"errors"
	"fmt"
	"strings"

	"github.com/takehaya/vinbero/pkg/bpf"
)

// HeadendPurgeOps is what PurgeBuiltinHeadends reads and removes.
// *bpf.MapOperations satisfies it.
type HeadendPurgeOps interface {
	ListHeadendV4OwnerIDs() (map[bpf.HeadendID]bpf.OwnerTag, error)
	ListHeadendV6OwnerIDs() (map[bpf.HeadendID]bpf.OwnerTag, error)
	DeleteHeadendV4In(vrfID uint32, triggerPrefix string, requester bpf.OwnerTag) error
	DeleteHeadendV6In(vrfID uint32, triggerPrefix string, requester bpf.OwnerTag) error
}

// IsBuiltinRouteOwner reports whether owner is one of the per-route headend
// owners the applier of localASN writes: the VPN trigger owner, a
// pre-aggregation (per RD) VPN owner, or a MUP downlink owner. The MUP gate
// owners are not: gates are shared with plugins and recovered on their own.
func IsBuiltinRouteOwner(localASN uint32, owner bpf.OwnerTag) bool {
	return owner == bpf.OwnerBGPVPN(localASN, "") ||
		bpf.IsLegacyBGPVPNOwner(localASN, owner) ||
		strings.HasPrefix(string(owner), string(bpf.OwnerBGPMUP(localASN, "")))
}

// PurgeBuiltinHeadends removes, in every VRF, the headend entries and owner
// records the BGP applier of localASN wrote for received routes (see
// IsBuiltinRouteOwner). It runs at boot before the data plane is attached:
// with pinned maps an entry a previous run wrote may belong to a VRF the
// route no longer imports into (a binding changed while the daemon was
// down, or the previous run placed every route in the global VRF), and
// nothing else would remove it before the route is received again. Routes
// are rebuilt from BGP. Entries of operators, plugins and MUP gates are
// left alone. It returns how many entries it removed, and every failure.
func PurgeBuiltinHeadends(ops HeadendPurgeOps, localASN uint32) (int, error) {
	removed := 0
	var errs []error
	for _, f := range []struct {
		name string
		list func() (map[bpf.HeadendID]bpf.OwnerTag, error)
		del  func(uint32, string, bpf.OwnerTag) error
	}{
		{"headend_v4", ops.ListHeadendV4OwnerIDs, ops.DeleteHeadendV4In},
		{"headend_v6", ops.ListHeadendV6OwnerIDs, ops.DeleteHeadendV6In},
	} {
		owners, err := f.list()
		if err != nil {
			errs = append(errs, fmt.Errorf("list %s owners: %w", f.name, err))
			continue
		}
		for id, owner := range owners {
			if !IsBuiltinRouteOwner(localASN, owner) {
				continue
			}
			if err := f.del(id.VRF, id.Prefix, owner); err != nil {
				errs = append(errs, fmt.Errorf("remove %s %s: %w", f.name, id, err))
				continue
			}
			removed++
		}
	}
	return removed, errors.Join(errs...)
}
