package cplane

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/headend"
)

// ForwardingMapOps is the host's owned service surface, never imported by guests.
type ForwardingMapOps interface {
	CreateMupUplinkV4Owned(uint32, string, uint32, uint8, *bpf.HeadendEntry, bpf.OwnerTag) error
	DeleteMupUplinkV4Owned(uint32, string, uint32, uint8, bpf.OwnerTag) error
	DeleteMupUplinkV6Owned(uint32, string, uint32, uint8, bpf.OwnerTag) error
	ListMupUplinkV4Owners() (map[bpf.MupUplinkV4Key]bpf.OwnerTag, error)
	ListMupUplinkV6Owners() (map[bpf.MupUplinkV6Key]bpf.OwnerTag, error)
	CreateFdbOwned(uint16, net.HardwareAddr, *bpf.FdbEntry, bpf.OwnerTag) error
	DeleteFdbOwned(uint16, net.HardwareAddr, bpf.OwnerTag) error
	ListFdbOwners() (map[bpf.FdbKey]bpf.OwnerTag, error)
	CreateBdPeerOwned(uint16, uint16, *bpf.HeadendEntry, [bpf.ESILen]byte, [16]byte, bool, bpf.OwnerTag) error
	CreateBdPeerAtFreeIndexOwned(uint16, *bpf.HeadendEntry, [bpf.ESILen]byte, [16]byte, bool, bpf.OwnerTag) (uint16, error)
	DeleteBdPeerOwned(uint16, uint16, bpf.OwnerTag) (bool, error)
	ListBdPeerOwners() (map[bpf.BdPeerKey]bpf.OwnerTag, error)
	ListBdPeers() (map[bpf.BdPeerKey]*bpf.HeadendEntry, error)
	GetHeadendV4Owner(string) (bpf.OwnerTag, bool, error)
	GetHeadendV6Owner(string) (bpf.OwnerTag, bool, error)
}
type uplinkDesired struct {
	instance uint32
	endpoint string
	teid     uint32
	bits     uint8
	entry    bpf.HeadendEntry
}

func (u uplinkDesired) key() string {
	return fmt.Sprintf("%d/%s/%08x/%d", u.instance, u.endpoint, u.teid, u.bits)
}

type peerDesired struct {
	bd     uint16
	entry  bpf.HeadendEntry
	remote [16]byte
	macs   []net.HardwareAddr
}

func (p peerDesired) key() string {
	return fmt.Sprintf("%d/%d/%x/%x", p.bd, p.entry.NumSegments, p.entry.Segments, p.remote)
}

type compositionMaps struct {
	mu      sync.Mutex
	maps    ForwardingMapOps
	headend *headend.Reconciler
	// Only gate dependencies need host memory; owned map inventory survives restart.
	gates map[bpf.OwnerTag]map[string]bool
	peers map[bpf.OwnerTag]map[string]bpf.BdPeerKey
}

func newCompositionMaps(maps ForwardingMapOps, h *headend.Reconciler) (*compositionMaps, error) {
	s := &compositionMaps{maps: maps, headend: h, gates: map[bpf.OwnerTag]map[string]bool{}, peers: map[bpf.OwnerTag]map[string]bpf.BdPeerKey{}}
	if maps == nil {
		return s, nil
	}
	v4, err := maps.ListMupUplinkV4Owners()
	if err != nil {
		return nil, err
	}
	for k, o := range v4 {
		if strings.HasPrefix(string(o), "plugin:") {
			if err := s.holdGate(o, netip.AddrFrom4(k.Endpoint).String()); err != nil {
				return nil, err
			}
		}
	}
	v6, err := maps.ListMupUplinkV6Owners()
	if err != nil {
		return nil, err
	}
	for k, o := range v6 {
		if strings.HasPrefix(string(o), "plugin:") {
			if err := s.holdGate(o, netip.AddrFrom16(k.Endpoint).String()); err != nil {
				return nil, err
			}
		}
	}
	if err := h.PruneUnreferencedMUPGates(); err != nil {
		return nil, err
	}
	return s, nil
}
func (s *compositionMaps) holdGate(owner bpf.OwnerTag, endpoint string) error {
	addr, err := netip.ParseAddr(endpoint)
	if err != nil {
		return err
	}
	af, mode := headend.AFv4, uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_M_GTP4_D_TEID)
	if addr.Is6() {
		af = headend.AFv6
		mode = uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_M_GTP6_D_TEID)
	}
	if err := s.headend.SetGateReferences(af, netip.PrefixFrom(addr, addr.BitLen()).String(), mode, owner, 1); err != nil {
		return err
	}
	if s.gates[owner] == nil {
		s.gates[owner] = map[string]bool{}
	}
	s.gates[owner][endpoint] = true
	return nil
}
func (s *compositionMaps) releaseGates(owner bpf.OwnerTag, keep map[string]bool) error {
	var errs []error
	for ep := range s.gates[owner] {
		if keep[ep] {
			continue
		}
		a, _ := netip.ParseAddr(ep)
		af, mode := headend.AFv4, uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_M_GTP4_D_TEID)
		if a.Is6() {
			af = headend.AFv6
			mode = uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_M_GTP6_D_TEID)
		}
		if err := s.headend.SetGateReferences(af, netip.PrefixFrom(a, a.BitLen()).String(), mode, owner, 0); err != nil {
			errs = append(errs, err)
		} else {
			delete(s.gates[owner], ep)
		}
	}
	return errors.Join(errs...)
}
func ownedUplink(k bpf.MupUplinkV4Key) uplinkDesired {
	return uplinkDesired{instance: binary.BigEndian.Uint32(k.Instance[:]), endpoint: netip.AddrFrom4(k.Endpoint).String(), teid: binary.BigEndian.Uint32(k.Teid[:]), bits: uint8(k.Prefixlen - 64)}
}
func (s *compositionMaps) applyUplinks(owner bpf.OwnerTag, desired []uplinkDesired, write bool) error {
	if s.maps == nil {
		if len(desired) > 0 {
			return fmt.Errorf("MUP maps unavailable")
		}
		return nil
	}
	want := map[string]uplinkDesired{}
	for _, u := range desired {
		if old, dup := want[u.key()]; dup && old.entry != u.entry {
			return fmt.Errorf("ambiguous MUP forwarding key")
		}
		want[u.key()] = u
	}
	existing, err := s.maps.ListMupUplinkV4Owners()
	if err != nil {
		return err
	}
	keepGates := map[string]bool{}
	var errs []error
	for k, o := range existing {
		if o != owner {
			continue
		}
		u := ownedUplink(k)
		if _, keep := want[u.key()]; keep {
			keepGates[u.endpoint] = true
			continue
		}
		if err := s.maps.DeleteMupUplinkV4Owned(u.instance, u.endpoint, u.teid, u.bits, owner); err != nil {
			errs = append(errs, err)
			keepGates[u.endpoint] = true
		}
	}
	// The initial output profile is GTP4. Old GTP6 ownership is still cleaned.
	v6, err := s.maps.ListMupUplinkV6Owners()
	if err != nil {
		return errors.Join(append(errs, err)...)
	} else {
		for k, o := range v6 {
			if o == owner {
				ep := netip.AddrFrom16(k.Endpoint).String()
				if err := s.maps.DeleteMupUplinkV6Owned(binary.BigEndian.Uint32(k.Instance[:]), ep, binary.BigEndian.Uint32(k.Teid[:]), uint8(k.Prefixlen-160), owner); err != nil {
					errs = append(errs, err)
					keepGates[ep] = true
				}
			}
		}
	}
	// Do not release a gate while any delete for that owner is outstanding.
	if err := s.releaseGates(owner, keepGates); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	if !write {
		return nil
	}
	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		u := want[key]
		if err := s.holdGate(owner, u.endpoint); err != nil {
			return err
		}
		if err := s.maps.CreateMupUplinkV4Owned(u.instance, u.endpoint, u.teid, u.bits, &u.entry, owner); err != nil {
			return err
		}
	}
	return nil
}
func (s *compositionMaps) applyEVPN(owner bpf.OwnerTag, desired []peerDesired, write bool) error {
	if s.maps == nil {
		if len(desired) > 0 {
			return fmt.Errorf("EVPN maps unavailable")
		}
		return nil
	}
	want := map[string]peerDesired{}
	macWant := map[bpf.FdbKey]string{}
	for _, p := range desired {
		key := p.key()
		if old, ok := want[key]; ok {
			if old.entry.SrcAddr != p.entry.SrcAddr {
				return fmt.Errorf("ambiguous EVPN peer source")
			}
			if p.entry.FloodExclude == 0 {
				old.entry.FloodExclude = 0
			}
			old.macs = append(old.macs, p.macs...)
			want[key] = old
		} else {
			want[key] = p
		}
		for _, mac := range p.macs {
			var bytes [6]byte
			copy(bytes[:], mac)
			fk := bpf.FdbKey{BdId: p.bd, Mac: bytes}
			if previous, ok := macWant[fk]; ok && previous != key {
				return fmt.Errorf("ambiguous EVPN MAC")
			}
			macWant[fk] = key
		}
	}
	fdbs, err := s.maps.ListFdbOwners()
	if err != nil {
		return err
	}
	peers, err := s.maps.ListBdPeerOwners()
	if err != nil {
		return err
	}
	// Recover peer identity after a daemon restart. Reverse keys are immutable
	// for a retained slot; unknown remnants are deleted before allocating anew.
	current := s.peers[owner]
	if current == nil {
		current = map[string]bpf.BdPeerKey{}
		s.peers[owner] = current
	}
	keepPeers := map[bpf.BdPeerKey]bool{}
	for key, pk := range current {
		if _, ok := want[key]; ok {
			keepPeers[pk] = true
		}
	}
	// Rewrite MACs after peer preparation. First remove only MACs absent from
	// the new desired set; a failed delete keeps every peer dependency reserved.
	var errs []error
	for fk, o := range fdbs {
		if o == owner {
			if _, keep := macWant[fk]; !keep {
				if err := s.maps.DeleteFdbOwned(fk.BdId, net.HardwareAddr(fk.Mac[:]), owner); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	// On cold recovery no peer identity is trusted. Remove controlled MACs before
	// releasing old slots, including MACs that will be recreated in the same set.
	for pk, o := range peers {
		if o != owner || keepPeers[pk] {
			continue
		}
		for fk, fo := range fdbs {
			if fo == owner && fk.BdId == pk.BdId {
				if err := s.maps.DeleteFdbOwned(fk.BdId, net.HardwareAddr(fk.Mac[:]), owner); err != nil {
					errs = append(errs, err)
				}
			}
		}
		if len(errs) > 0 {
			return errors.Join(errs...)
		}
		if _, err := s.maps.DeleteBdPeerOwned(pk.BdId, pk.Index, owner); err != nil {
			return err
		}
		for k, v := range current {
			if v == pk {
				delete(current, k)
			}
		}
	}
	if !write {
		return nil
	}
	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		p := want[key]
		pk, held := current[key]
		if held {
			if err := s.maps.CreateBdPeerOwned(pk.BdId, pk.Index, &p.entry, [bpf.ESILen]byte{}, p.remote, len(p.macs) > 0, owner); err != nil {
				return err
			}
		} else {
			idx, err := s.maps.CreateBdPeerAtFreeIndexOwned(p.bd, &p.entry, [bpf.ESILen]byte{}, p.remote, len(p.macs) > 0, owner)
			if err != nil {
				return err
			}
			pk = bpf.BdPeerKey{BdId: p.bd, Index: idx}
			current[key] = pk
		}
		for _, mac := range p.macs {
			entry := &bpf.FdbEntry{BdId: p.bd, PeerIndex: pk.Index, IsRemote: 1, IsStatic: 1}
			if err := s.maps.CreateFdbOwned(p.bd, mac, entry, owner); err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *compositionMaps) apply(owner bpf.OwnerTag, u []uplinkDesired, e []peerDesired) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.applyUplinks(owner, u, true); err != nil {
		return err
	}
	return s.applyEVPN(owner, e, true)
}
func (s *compositionMaps) flush(owner bpf.OwnerTag) error {
	if s == nil {
		return nil
	}
	return s.apply(owner, nil, nil)
}

// inventoryOwners includes main-map deletion failures whose owner reservation
// survived. These owners remain visible even if their registration is missing.
func (s *compositionMaps) inventoryOwners() (map[bpf.OwnerTag]bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[bpf.OwnerTag]bool{}
	for o, eps := range s.gates {
		if len(eps) > 0 {
			out[o] = true
		}
	}
	for o, peers := range s.peers {
		if len(peers) > 0 {
			out[o] = true
		}
	}
	if s.maps == nil {
		return out, nil
	}
	a, e := s.maps.ListMupUplinkV4Owners()
	if e != nil {
		return nil, e
	}
	for _, o := range a {
		out[o] = true
	}
	b, e := s.maps.ListMupUplinkV6Owners()
	if e != nil {
		return nil, e
	}
	for _, o := range b {
		out[o] = true
	}
	c, e := s.maps.ListFdbOwners()
	if e != nil {
		return nil, e
	}
	for _, o := range c {
		out[o] = true
	}
	d, e := s.maps.ListBdPeerOwners()
	if e != nil {
		return nil, e
	}
	for _, o := range d {
		out[o] = true
	}
	return out, nil
}

func (s *compositionMaps) prune(owner bpf.OwnerTag, u []uplinkDesired, e []peerDesired) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.applyUplinks(owner, u, false); err != nil {
		return err
	}
	return s.applyEVPN(owner, e, false)
}
