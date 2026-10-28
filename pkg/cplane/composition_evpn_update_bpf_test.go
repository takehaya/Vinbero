package cplane

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// This opt-in test uses only newly allocated anonymous maps. It checks reverse
// ownership cleanup, not packet delivery or pinned deployment state.
func TestCompositionEVPNSegmentUpdateLastMACWithdrawalBPF(t *testing.T) {
	if os.Getenv("VINBERO_CPLANE_EVPN_BPF") != "1" {
		t.Skip("set VINBERO_CPLANE_EVPN_BPF=1 with BPF map privileges")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	makeMap := func(key, value any) *ebpf.Map {
		m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: uint32(binary.Size(key)), ValueSize: uint32(binary.Size(value)), MaxEntries: 32})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := m.Close(); err != nil {
				t.Error(err)
			}
		})
		return m
	}
	objects := &bpf.BpfObjects{}
	objects.SidAuxMap = makeMap(uint32(0), uint32(0))
	objects.FdbMap = makeMap(bpf.FdbKey{}, bpf.FdbEntry{})
	objects.FdbOwnerMap = makeMap(bpf.FdbKey{}, [64]byte{})
	objects.BdPeerMap = makeMap(bpf.BdPeerKey{}, bpf.HeadendEntry{})
	objects.BdPeerOwnerMap = makeMap(bpf.BdPeerKey{}, [64]byte{})
	objects.BdPeerReverseMap = makeMap(bpf.BdPeerReverseKey{}, bpf.BdPeerReverseVal{})
	objects.BdPeerL2ExtMap = makeMap(bpf.BpfBdPeerL2ExtKey{}, bpf.BpfBdPeerL2ExtVal{})
	maps := bpf.NewMapOperations(objects)
	p, _ := compositionOps(t)
	p.services.maps = maps
	old := evpnUpdateSet(1, "fd00:c::1")
	old.EvpnForwards[0].Flood = true
	if err := putComposition(p, old); err != nil {
		t.Fatal(err)
	}
	reverseKey := bpf.BdPeerReverseKey{BdId: 100, SrcAddr: netip.MustParseAddr("fd00:c::2").As16()}
	var reverse bpf.BdPeerReverseVal
	if err := objects.BdPeerReverseMap.Lookup(&reverseKey, &reverse); err != nil {
		t.Fatal("initial MAC did not install its reverse reference:", err)
	}
	next := evpnUpdateSet(2, "fd00:c::9", "fd00:c::1")
	next.EvpnForwards[0].Mac, next.EvpnForwards[0].Flood = "", true
	if err := putComposition(p, next); err != nil {
		t.Fatal(err)
	}
	if err := objects.BdPeerReverseMap.Lookup(&reverseKey, &reverse); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("last MAC withdrawal left a reverse reference: %v", err)
	}
	fdb, err := maps.ListFdb()
	if err != nil || len(fdb) != 0 {
		t.Fatalf("withdrawn MAC remains: entries=%v error=%v", fdb, err)
	}
	peers, err := maps.ListBdPeers()
	if err != nil || len(peers) != 1 {
		t.Fatalf("flood peer was not retained as the only peer: entries=%v error=%v", peers, err)
	}
	var flood bpf.HeadendEntry
	for _, entry := range peers {
		flood = *entry
	}
	if flood.NumSegments != 2 || flood.FloodExclude != 0 {
		t.Fatal("replacement flood peer differs:", flood)
	}
	otherOwner := bpf.OwnerPluginBundle("other-unicast")
	flood.FloodExclude = 1
	index, err := maps.CreateBdPeerAtFreeIndexOwned(100, &flood, [bpf.ESILen]byte{}, reverseKey.SrcAddr, true, otherOwner)
	if err != nil {
		t.Fatal("stale reverse reference blocks another owner's unicast peer:", err)
	}
	if err := objects.BdPeerReverseMap.Lookup(&reverseKey, &reverse); err != nil || reverse.Index != index {
		t.Fatalf("new owner's reverse reference differs: value=%v index=%d error=%v", reverse, index, err)
	}
}
