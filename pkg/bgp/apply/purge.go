package apply

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/takehaya/vinbero/pkg/bpf"
	"go.uber.org/zap"
)

// HeadendPurgeOps is what PurgeBuiltinHeadends reads and removes: the
// headend maps and the MUP uplink (F-TEID) maps. *bpf.MapOperations
// satisfies it.
type HeadendPurgeOps interface {
	ListHeadendV4OwnerIDs() (map[bpf.HeadendID]bpf.OwnerTag, error)
	ListHeadendV6OwnerIDs() (map[bpf.HeadendID]bpf.OwnerTag, error)
	DeleteHeadendV4In(vrfID uint32, triggerPrefix string, requester bpf.OwnerTag) error
	DeleteHeadendV6In(vrfID uint32, triggerPrefix string, requester bpf.OwnerTag) error
	mupOwnerInventory
	DeleteMupUplinkV4Owned(instance uint32, endpoint string, teid uint32, teidPrefixBits uint8, owner bpf.OwnerTag) error
	DeleteMupUplinkV6Owned(instance uint32, endpoint string, teid uint32, teidPrefixBits uint8, owner bpf.OwnerTag) error
}

// IsBuiltinRouteOwner reports whether owner is one of the per-route headend
// owners the applier of localASN writes: the VPN trigger owner or a MUP
// downlink owner. The MUP gate owners are not: gates are shared with plugins
// and recovered on their own.
func IsBuiltinRouteOwner(localASN uint32, owner bpf.OwnerTag) bool {
	return owner == bpf.OwnerBGPVPN(localASN, "") ||
		strings.HasPrefix(string(owner), string(bpf.OwnerBGPMUP(localASN, "")))
}

// PurgeBuiltinHeadends removes, in every VRF, the headend entries and owner
// records the BGP applier of localASN wrote for received routes (see
// IsBuiltinRouteOwner), and its MUP uplink (F-TEID) entries of every
// instance. It runs at boot before the data plane is attached: with pinned
// maps an entry a previous run wrote may belong to a VRF the route no
// longer imports into (a binding changed while the daemon was down, or the
// previous run placed every route in the global VRF), and nothing else
// would remove it before the route is received again. Routes are rebuilt
// from BGP. Entries of operators and plugins, and the MUP gates (shared
// with plugins; a gate with no uplink behind it forwards nothing), are left
// alone. It returns how many entries it removed, and every failure.
func PurgeBuiltinHeadends(ops HeadendPurgeOps, localASN uint32) (int, error) {
	removed, err := purgeBuiltinMUPUplinks(ops, localASN)
	errs := []error{err}
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

// EVPNPurgeOps is what PurgeBuiltinEVPN reads and removes: the FDB, the
// bridge-domain peers and the ECMP groups. *bpf.MapOperations satisfies it.
type EVPNPurgeOps interface {
	fdbBdOps
	ecmpOps
}

// PurgeBuiltinEVPN removes, before the data plane is attached, the EVPN
// state the BGP applier of localASN wrote in an earlier run and pinned maps
// kept: its FDB entries (remote MACs) and bridge-domain peers (RT2 and RT3),
// the FDB pointers and synthetic peers in the Ethernet Segment peer range,
// which only the applier allocates, and its segment ECMP groups. FDB entries
// go before the peers they point at, and the groups only once both are gone.
// Entries other owners wrote (the operator's, a plugin's, another ASN's)
// stay. Routes are rebuilt from BGP. It returns how many entries it removed;
// on any failure (each is logged) it returns an error, and the start stops:
// a stale MAC would forward to a peer index another remote PE may get.
func PurgeBuiltinEVPN(ops EVPNPurgeOps, localASN uint32, logger *zap.Logger) (int, error) {
	a := &Applier{fdbBd: ops, ecmp: ops, localASN: localASN, evpn: newEVPNTable(), logger: logger.Named("bgp.apply")}
	n, ok := a.sweepEVPNState()
	if !ok {
		return n, errors.New("the EVPN entries an earlier run's BGP applier wrote could not all be removed (each failure is logged above)")
	}
	return n, nil
}

// purgeBuiltinMUPUplinks removes the MUP uplink entries the applier of
// localASN owns, in every instance.
func purgeBuiltinMUPUplinks(ops HeadendPurgeOps, localASN uint32) (int, error) {
	prefix := string(bpf.OwnerBGPMUP(localASN, ""))
	removed := 0
	var errs []error
	v4, err := ops.ListMupUplinkV4Owners()
	if err != nil {
		errs = append(errs, fmt.Errorf("list mup_uplink_v4 owners: %w", err))
	}
	for k, o := range v4 {
		if !strings.HasPrefix(string(o), prefix) {
			continue
		}
		ep := netip.AddrFrom4(k.Endpoint)
		if err := ops.DeleteMupUplinkV4Owned(binary.BigEndian.Uint32(k.Instance[:]), ep.String(), binary.BigEndian.Uint32(k.Teid[:]), uint8(k.Prefixlen-64), o); err != nil {
			errs = append(errs, fmt.Errorf("remove mup_uplink_v4 %s: %w", ep, err))
			continue
		}
		removed++
	}
	v6, err := ops.ListMupUplinkV6Owners()
	if err != nil {
		errs = append(errs, fmt.Errorf("list mup_uplink_v6 owners: %w", err))
	}
	for k, o := range v6 {
		if !strings.HasPrefix(string(o), prefix) {
			continue
		}
		ep := netip.AddrFrom16(k.Endpoint)
		if err := ops.DeleteMupUplinkV6Owned(binary.BigEndian.Uint32(k.Instance[:]), ep.String(), binary.BigEndian.Uint32(k.Teid[:]), uint8(k.Prefixlen-160), o); err != nil {
			errs = append(errs, fmt.Errorf("remove mup_uplink_v6 %s: %w", ep, err))
			continue
		}
		removed++
	}
	return removed, errors.Join(errs...)
}
