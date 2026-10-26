package cplane

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

type evpnUpdateMaps struct {
	*evpnValueFake
	after           func(string)
	failPeerRefresh bool
	leakPeerRefresh bool
	failPeerList    bool
	refreshes       int
}

func (f *evpnUpdateMaps) mutated(operation string, err error) error {
	if f.after != nil {
		f.after(operation)
	}
	return err
}
func (f *evpnUpdateMaps) CreateFdbOwned(bd uint16, mac net.HardwareAddr, entry *bpf.FdbEntry, owner bpf.OwnerTag) error {
	return f.mutated("write MAC", f.evpnValueFake.CreateFdbOwned(bd, mac, entry, owner))
}
func (f *evpnUpdateMaps) DeleteFdbOwned(bd uint16, mac net.HardwareAddr, owner bpf.OwnerTag) error {
	return f.mutated("delete MAC", f.evpnValueFake.DeleteFdbOwned(bd, mac, owner))
}
func (f *evpnUpdateMaps) CreateBdPeerOwned(bd, index uint16, entry *bpf.HeadendEntry, esi [bpf.ESILen]byte, remote [16]byte, reverse bool, owner bpf.OwnerTag) error {
	f.refreshes++
	if f.failPeerRefresh {
		return f.mutated("failed peer refresh", errors.New("peer refresh failed"))
	}
	err := f.evpnValueFake.CreateBdPeerOwned(bd, index, entry, esi, remote, reverse, owner)
	if err == nil && f.leakPeerRefresh {
		err = bpf.ErrBdPeerForwardLeaked
	}
	return f.mutated("refresh peer", err)
}
func (f *evpnUpdateMaps) CreateBdPeerAtFreeIndexOwned(bd uint16, entry *bpf.HeadendEntry, esi [bpf.ESILen]byte, remote [16]byte, reverse bool, owner bpf.OwnerTag) (uint16, error) {
	index, err := f.evpnValueFake.CreateBdPeerAtFreeIndexOwned(bd, entry, esi, remote, reverse, owner)
	return index, f.mutated("allocate peer", err)
}
func (f *evpnUpdateMaps) DeleteBdPeerOwned(bd, index uint16, owner bpf.OwnerTag) (bool, error) {
	present, err := f.evpnValueFake.DeleteBdPeerOwned(bd, index, owner)
	return present, f.mutated("delete peer", err)
}
func (f *evpnUpdateMaps) ListBdPeers() (map[bpf.BdPeerKey]*bpf.HeadendEntry, error) {
	if f.failPeerList {
		return nil, errors.New("peer inventory failed")
	}
	return f.evpnValueFake.ListBdPeers()
}

func evpnUpdateFixture(t *testing.T) (*PluginOps, *evpnUpdateMaps) {
	t.Helper()
	p, maps := compositionOps(t)
	f := &evpnUpdateMaps{evpnValueFake: &evpnValueFake{serviceFake: maps, entries: map[bpf.FdbKey]*bpf.FdbEntry{}}}
	p.services.maps = f
	return p, f
}
func evpnUpdateSet(revision uint64, segments ...string) *v1.PluginApplyChunk {
	return &v1.PluginApplyChunk{DesiredRevision: revision, EvpnForwards: []*v1.PluginEvpnForward{{
		Context: "mobile", Mac: "02:00:00:00:00:01", Segments: segments,
		SrcAddr: "fd00:feed::1", RemoteSrc: "fd00:c::2",
	}}}
}

func TestCompositionEVPNSegmentUpdateKeepsForwarding(t *testing.T) {
	for _, shared := range []bool{false, true} {
		name := "one MAC"
		if shared {
			name = "shared peer"
		}
		t.Run(name, func(t *testing.T) {
			p, maps := evpnUpdateFixture(t)
			set := func(revision uint64, segments ...string) *v1.PluginApplyChunk {
				m := evpnUpdateSet(revision, segments...)
				if shared {
					other := *m.EvpnForwards[0]
					other.Mac = "02:00:00:00:00:02"
					m.EvpnForwards = append(m.EvpnForwards, &other)
				}
				return m
			}
			if err := putComposition(p, set(1, "fd00:c::1")); err != nil {
				t.Fatal(err)
			}
			var slot bpf.BdPeerKey
			for key := range maps.peers {
				slot = key
			}
			macs := make([]bpf.FdbKey, 0, len(maps.entries))
			for key := range maps.entries {
				macs = append(macs, key)
			}
			maps.after = func(operation string) {
				for _, key := range macs {
					entry := maps.entries[key]
					if entry == nil || entry.PeerIndex != slot.Index || maps.peerEntries[slot] == nil {
						t.Errorf("forwarding absent after %s: MAC=%+v peer=%+v", operation, entry, maps.peerEntries[slot])
					}
				}
			}
			for i, segments := range [][]string{{"fd00:c::9", "fd00:c::1"}, {"fd00:c::1"}} {
				if err := putComposition(p, set(uint64(i+2), segments...)); err != nil {
					t.Fatal(err)
				}
				peer := maps.peerEntries[slot]
				if peer == nil || peer.NumSegments != uint8(len(segments)) || peer.DstAddr != netip.MustParseAddr(segments[0]).As16() || len(maps.peers) != 1 {
					t.Fatalf("segment update did not retain the live slot: %+v", peer)
				}
			}
			maps.after = nil
			if err := putComposition(p, &v1.PluginApplyChunk{DesiredRevision: 4}); err != nil {
				t.Fatal(err)
			}
			if len(maps.entries)+len(maps.peers) != 0 {
				t.Fatal("withdrawal retained output")
			}
		})
	}
}

func TestCompositionEVPNSegmentUpdateFailureAndRetry(t *testing.T) {
	for _, failure := range []string{"inventory", "peer refresh", "peer rollback"} {
		t.Run(failure, func(t *testing.T) {
			p, maps := evpnUpdateFixture(t)
			if err := putComposition(p, evpnUpdateSet(1, "fd00:c::1")); err != nil {
				t.Fatal(err)
			}
			before := cloneMap(p.services.peers[p.owner])
			var slot bpf.BdPeerKey
			for _, value := range before {
				slot = value
			}
			old := *maps.peerEntries[slot]
			maps.failPeerList = failure == "inventory"
			maps.failPeerRefresh = failure == "peer refresh"
			maps.leakPeerRefresh = failure == "peer rollback"
			if err := putComposition(p, evpnUpdateSet(2, "fd00:c::9", "fd00:c::1")); err == nil {
				t.Fatal("failed update reported success")
			}
			if len(maps.entries) != 1 || len(maps.peers) != 1 || p.PendingDeclarations() != 1 || p.appliedRevision != 1 {
				t.Fatal("failed update lost ownership or retry")
			}
			for key, value := range before {
				if p.services.peers[p.owner][key] != value {
					t.Fatal("failed update changed its private identity")
				}
			}
			if failure != "peer rollback" && *maps.peerEntries[slot] != old {
				t.Fatal("failed refresh changed forwarding")
			}
			maps.failPeerList, maps.failPeerRefresh, maps.leakPeerRefresh = false, false, false
			var operations []string
			maps.after = func(operation string) { operations = append(operations, operation) }
			p.RetryPending()
			if p.PendingDeclarations() != 0 || p.appliedRevision != 2 || len(maps.peers) != 1 || len(maps.entries) != 1 {
				t.Fatal("retry did not converge")
			}
			for key, value := range p.services.peers[p.owner] {
				if maps.peerEntries[value].NumSegments != 2 || key == evpnPeerKey(before) {
					t.Fatal("retry retained the old identity or value")
				}
			}
			if failure == "peer rollback" {
				deletedMAC := false
				deletedPeer := false
				for _, operation := range operations {
					if operation == "delete MAC" {
						deletedMAC = true
					}
					if operation == "delete peer" {
						if !deletedMAC {
							t.Fatal("degraded peer released before its MAC")
						}
						deletedPeer = true
					}
				}
				if !deletedPeer {
					t.Fatal("failed rollback did not use conservative recovery")
				}
			}
		})
	}
}

func evpnPeerKey(peers map[string]bpf.BdPeerKey) string {
	for key := range peers {
		return key
	}
	return ""
}

func TestCompositionEVPNSegmentUpdateDeletesRevokedMACFirst(t *testing.T) {
	p, maps := evpnUpdateFixture(t)
	old := evpnUpdateSet(1, "fd00:c::1")
	second := *old.EvpnForwards[0]
	second.Mac = "02:00:00:00:00:02"
	old.EvpnForwards = append(old.EvpnForwards, &second)
	if err := putComposition(p, old); err != nil {
		t.Fatal(err)
	}
	maps.failFDBDelete = true
	if err := putComposition(p, evpnUpdateSet(2, "fd00:c::9", "fd00:c::1")); err == nil {
		t.Fatal("failed revocation hidden")
	}
	if maps.refreshes != 0 || len(maps.entries) != 2 {
		t.Fatal("peer changed before MAC revocation succeeded")
	}
	maps.failFDBDelete = false
	maps.after = func(operation string) {
		if operation == "refresh peer" && (len(maps.entries) != 1 || maps.entries[fk(100, net.HardwareAddr{2, 0, 0, 0, 0, 2})] != nil) {
			t.Fatal("peer changed while revoked MAC remained")
		}
	}
	p.RetryPending()
	if p.PendingDeclarations() != 0 || len(maps.entries) != 1 || maps.refreshes != 1 {
		t.Fatal("revocation retry did not converge")
	}
}

func TestCompositionEVPNSegmentUpdateFallsBack(t *testing.T) {
	for _, change := range []string{"source", "remote", "flood", "cold", "alias", "remnant", "split"} {
		t.Run(change, func(t *testing.T) {
			p, maps := evpnUpdateFixture(t)
			if err := putComposition(p, evpnUpdateSet(1, "fd00:c::1")); err != nil {
				t.Fatal(err)
			}
			m := evpnUpdateSet(2, "fd00:c::9", "fd00:c::1")
			switch change {
			case "source":
				m.EvpnForwards[0].SrcAddr = "fd00:feed::2"
			case "remote":
				m.EvpnForwards[0].RemoteSrc = "fd00:c::3"
			case "flood":
				m.EvpnForwards[0].Flood = true
			case "cold":
				p.services.peers[p.owner] = nil
			case "alias":
				for _, slot := range p.services.peers[p.owner] {
					p.services.peers[p.owner]["alias"] = slot
					break
				}
			case "remnant":
				if err := maps.CreateBdPeerOwned(100, 4, &bpf.HeadendEntry{}, [bpf.ESILen]byte{}, [16]byte{}, false, p.owner); err != nil {
					t.Fatal(err)
				}
			case "split":
				other := *m.EvpnForwards[0]
				other.Mac, other.RemoteSrc = "02:00:00:00:00:02", "fd00:c::3"
				m.EvpnForwards = append(m.EvpnForwards, &other)
			}
			maps.refreshes = 0
			removed := false
			maps.after = func(operation string) { removed = removed || operation == "delete peer" }
			if err := putComposition(p, m); err != nil {
				t.Fatal(err)
			}
			if !removed || maps.refreshes != 0 {
				t.Fatal("unsafe or ambiguous update reused a live slot")
			}
		})
	}
}
