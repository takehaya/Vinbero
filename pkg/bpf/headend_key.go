package bpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/cilium/ebpf"
)

// headendKeyVRFBits is the length of the vrf_id field at the front of the
// matched data of a headend key (HEADEND_KEY_VRF_BITS in xdp_prog.h). The
// VRF always matches in full, so a /p trigger prefix is stored with
// prefixlen headendKeyVRFBits + p.
const headendKeyVRFBits = 32

// HeadendLookupVRF is the VRF the data plane matches every packet in
// (headend_vrf in process_l3). Entries of any other VRF are stored, listed
// and removable, but no packet looks them up.
const HeadendLookupVRF uint32 = 0

// globalVRF is the vrf_id of the global VRF (vrf.GlobalVRFID; pkg/vrf
// imports this package). The MapOperations methods that take a trigger
// prefix alone read and write this VRF; the ...In methods name the VRF.
const globalVRF uint32 = 0

// HeadendID names one headend entry: the VRF it belongs to and its trigger
// prefix in CIDR form, host bits cleared. The same prefix in two VRFs is
// two entries.
type HeadendID struct {
	VRF    uint32
	Prefix string
}

// String renders the id for errors and logs: the bare prefix in the global
// VRF, "vrf <id> <prefix>" elsewhere.
func (id HeadendID) String() string {
	if id.VRF == globalVRF {
		return id.Prefix
	}
	return fmt.Sprintf("vrf %d %s", id.VRF, id.Prefix)
}

// globalOnly narrows a per-VRF listing to the global VRF, keyed by prefix.
func globalOnly[V any](all map[HeadendID]V) map[string]V {
	out := make(map[string]V, len(all))
	for id, v := range all {
		if id.VRF == globalVRF {
			out[id.Prefix] = v
		}
	}
	return out
}

// ErrInvalidHeadendPrefix is returned for a trigger prefix that does not
// parse, or that belongs to the other address family than the map.
var ErrInvalidHeadendPrefix = errors.New("invalid headend trigger prefix")

// parseHeadendPrefix parses a trigger prefix of one address family: a CIDR
// or a bare address (a host prefix). Host bits are cleared. An IPv6
// headend refuses an IPv4 prefix and the other way round; an IPv4-mapped
// IPv6 address is IPv6.
func parseHeadendPrefix(cidr string, v6 bool) (netip.Prefix, error) {
	var (
		p   netip.Prefix
		err error
	)
	if strings.Contains(cidr, "/") {
		p, err = netip.ParsePrefix(cidr)
	} else {
		var a netip.Addr
		if a, err = netip.ParseAddr(cidr); err == nil && a.Zone() != "" {
			err = errors.New("zoned address")
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%w: %q is not a CIDR or IP address", ErrInvalidHeadendPrefix, cidr)
	}
	if v6 && !p.Addr().Is6() {
		return netip.Prefix{}, fmt.Errorf("%w: %q is not an IPv6 prefix", ErrInvalidHeadendPrefix, cidr)
	}
	if !v6 && !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("%w: %q is not an IPv4 prefix", ErrInvalidHeadendPrefix, cidr)
	}
	return p.Masked(), nil
}

// BuildHeadendV4Key returns the headend_v4_map / headend_v4_owner_map key
// for an IPv4 trigger prefix in VRF vrfID. Host bits are cleared and a bare
// address is taken as a /32. Anything that is not IPv4 is refused.
func BuildHeadendV4Key(vrfID uint32, cidr string) (*HeadendV4Key, error) {
	p, err := parseHeadendPrefix(cidr, false)
	if err != nil {
		return nil, err
	}
	key := &HeadendV4Key{Prefixlen: headendKeyVRFBits + uint32(p.Bits()), Addr: p.Addr().As4()}
	binary.BigEndian.PutUint32(key.Instance[:], vrfID)
	return key, nil
}

// BuildHeadendV6Key is the IPv6 counterpart of BuildHeadendV4Key; a bare
// address is a /128 and an IPv4 prefix or address is refused.
func BuildHeadendV6Key(vrfID uint32, cidr string) (*HeadendV6Key, error) {
	p, err := parseHeadendPrefix(cidr, true)
	if err != nil {
		return nil, err
	}
	key := &HeadendV6Key{Prefixlen: headendKeyVRFBits + uint32(p.Bits()), Addr: p.Addr().As16()}
	binary.BigEndian.PutUint32(key.Instance[:], vrfID)
	return key, nil
}

// ErrMalformedHeadendKey reports a stored headend key whose prefix length
// cannot belong to an entry: shorter than the vrf_id field, or longer than
// the vrf_id and the whole address. No MapOperations writer produces one.
var ErrMalformedHeadendKey = errors.New("malformed headend key")

// vrf is the vrf_id of a headend v4 key.
func (k *BpfHeadendV4Key) vrf() uint32 { return binary.BigEndian.Uint32(k.Instance[:]) }

// prefix is the trigger prefix of a headend v4 key in CIDR form, the
// inverse of BuildHeadendV4Key, or false for a malformed key.
func (k *BpfHeadendV4Key) prefix() (string, bool) {
	return headendKeyPrefix(k.Prefixlen, netip.AddrFrom4(k.Addr))
}

// vrf is the vrf_id of a headend v6 key.
func (k *BpfHeadendV6Key) vrf() uint32 { return binary.BigEndian.Uint32(k.Instance[:]) }

// prefix is the IPv6 counterpart of BpfHeadendV4Key.prefix.
func (k *BpfHeadendV6Key) prefix() (string, bool) {
	return headendKeyPrefix(k.Prefixlen, netip.AddrFrom16(k.Addr))
}

func headendKeyPrefix(prefixlen uint32, addr netip.Addr) (string, bool) {
	if prefixlen < headendKeyVRFBits || prefixlen-headendKeyVRFBits > uint32(addr.BitLen()) {
		return "", false
	}
	return netip.PrefixFrom(addr, int(prefixlen-headendKeyVRFBits)).String(), true
}

// headendKey is a key of the headend maps: the methods above.
type headendKey[K any] interface {
	*K
	vrf() uint32
	prefix() (string, bool)
}

// deleteHeadendKey removes one headend entry and its owner record by key,
// after checking that requester owns it unless force is set.
func deleteHeadendKey(main *ebpf.Map, owners *entryOwnerMap, key any, requester OwnerTag, force bool, family string) error {
	if !force {
		if _, err := checkEntryOwner(owners, key, requester); err != nil {
			return err
		}
	}
	if err := deleteMapKey(main, key); err != nil {
		return fmt.Errorf("failed to delete headend %s entry: %w", family, err)
	}
	if err := owners.Delete(key); err != nil {
		return fmt.Errorf("failed to delete headend %s owner: %w", family, err)
	}
	return nil
}

// flushHeadend empties one headend map of every VRF, or of *vrfID alone
// when it is set: the entries scope owns (and those with no owner
// recorded), or every entry when force is set, and the owner records of
// scope (every one when force is set) whose entry is already gone. Each
// removed entry or record counts once. A malformed key is left in place
// and reported after the rest is done.
func flushHeadend[K comparable, PK headendKey[K]](main *ebpf.Map, owners *entryOwnerMap, vrfID *uint32, scope OwnerTag, force bool, family string) (uint32, error) {
	var (
		keys      []K
		malformed int
	)
	inScope := func(key *K) bool { return vrfID == nil || PK(key).vrf() == *vrfID }
	// Keys first: the iterator's behaviour while the map changes is not defined.
	live := map[K]struct{}{}
	if err := eachKey(main, func(key *K) bool {
		live[*key] = struct{}{}
		if !inScope(key) {
			return true
		}
		if _, ok := PK(key).prefix(); !ok {
			malformed++
			return true
		}
		keys = append(keys, *key)
		return true
	}); err != nil {
		return 0, fmt.Errorf("flush headend_%s: iterate: %w", family, err)
	}
	held, err := listEntryOwners[K](owners)
	if err != nil {
		return 0, fmt.Errorf("flush headend_%s: list owners: %w", family, err)
	}
	for key, holder := range held {
		if _, ok := live[key]; ok || !inScope(&key) || (!force && holder != scope) {
			continue
		}
		if _, ok := PK(&key).prefix(); !ok {
			malformed++
			continue
		}
		keys = append(keys, key)
	}
	var count uint32
	for i := range keys {
		err := deleteHeadendKey(main, owners, &keys[i], scope, force, family)
		if errors.Is(err, ErrEntryOwnerMismatch) {
			continue
		}
		if err != nil {
			prefix, _ := PK(&keys[i]).prefix()
			return count, fmt.Errorf("flush headend_%s: delete vrf %d %s: %w", family, PK(&keys[i]).vrf(), prefix, err)
		}
		count++
	}
	if malformed > 0 {
		return count, fmt.Errorf("flush headend_%s: deleted %d, %w: %d left in place", family, count, ErrMalformedHeadendKey, malformed)
	}
	return count, nil
}

// eachKey calls fn with every key of m, without reading the values, until
// fn returns false.
func eachKey[K any](m *ebpf.Map, fn func(*K) bool) error {
	var (
		cur, next K
		prev      any
	)
	for {
		err := m.NextKey(prev, &next)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !fn(&next) {
			return nil
		}
		cur = next
		prev = &cur
	}
}

// pruneUnlistedHeadend removes what owner holds under the keys no listing
// can name, a malformed prefix length: the entry and its owner record, or
// an owner record left without its entry. Every well-formed key of any VRF
// is in ListHeadendV4OwnerIDs and is the inventory's to prune.
func pruneUnlistedHeadend[K comparable, PK headendKey[K]](main *ebpf.Map, owners *entryOwnerMap, owner OwnerTag, family string) (int, error) {
	if owner == "" {
		return 0, ErrEmptyOwner
	}
	held, err := listEntryOwners[K](owners)
	if err != nil {
		return 0, err
	}
	var pruned int
	for key, holder := range held {
		if holder != owner {
			continue
		}
		if _, ok := PK(&key).prefix(); ok {
			continue
		}
		if err := deleteHeadendKey(main, owners, &key, owner, false, family); err != nil {
			return pruned, fmt.Errorf("prune headend_%s owner %q: vrf %d: %w", family, owner, PK(&key).vrf(), err)
		}
		pruned++
	}
	return pruned, nil
}

// PruneUnlistedHeadendV4 removes what owner holds in headend_v4 under
// malformed keys, which ListHeadendV4OwnerIDs does not show. The owner
// cleanup (headend.PruneOwner) runs it after removing the owner's listed
// entries, so an owner leaves nothing behind.
func (m *MapOperations) PruneUnlistedHeadendV4(owner OwnerTag) (int, error) {
	return pruneUnlistedHeadend[HeadendV4Key](m.objs.HeadendV4Map, m.headendV4Owners, owner, "v4")
}

// PruneUnlistedHeadendV6 is the IPv6 counterpart of PruneUnlistedHeadendV4.
func (m *MapOperations) PruneUnlistedHeadendV6(owner OwnerTag) (int, error) {
	return pruneUnlistedHeadend[HeadendV6Key](m.objs.HeadendV6Map, m.headendV6Owners, owner, "v6")
}

// listHeadend reads one headend map, every VRF. A malformed key is skipped;
// the flushes report it.
func listHeadend[K any, PK headendKey[K]](main *ebpf.Map, family string) (map[HeadendID]*HeadendEntry, error) {
	result := make(map[HeadendID]*HeadendEntry)
	var (
		key   K
		entry HeadendEntry
	)
	iter := main.Iterate()
	for iter.Next(&key, &entry) {
		prefix, ok := PK(&key).prefix()
		if !ok {
			continue
		}
		entryCopy := entry
		result[HeadendID{VRF: PK(&key).vrf(), Prefix: prefix}] = &entryCopy
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate headend %s map: %w", family, err)
	}
	return result, nil
}

// listHeadendOwners reads one headend owner map, every VRF, including
// reservations left after a partial deletion. A malformed key is skipped.
func listHeadendOwners[K comparable, PK headendKey[K]](owners *entryOwnerMap) (map[HeadendID]OwnerTag, error) {
	held, err := listEntryOwners[K](owners)
	result := make(map[HeadendID]OwnerTag, len(held))
	for key, owner := range held {
		if prefix, ok := PK(&key).prefix(); ok {
			result[HeadendID{VRF: PK(&key).vrf(), Prefix: prefix}] = owner
		}
	}
	return result, err
}

// ListHeadendV4OwnerIDs lists the owners of every VRF's headend v4 entries,
// including reservations left after partial deletion.
func (m *MapOperations) ListHeadendV4OwnerIDs() (map[HeadendID]OwnerTag, error) {
	return listHeadendOwners[HeadendV4Key](m.headendV4Owners)
}

// ListHeadendV6OwnerIDs is the IPv6 counterpart of ListHeadendV4OwnerIDs.
func (m *MapOperations) ListHeadendV6OwnerIDs() (map[HeadendID]OwnerTag, error) {
	return listHeadendOwners[HeadendV6Key](m.headendV6Owners)
}
