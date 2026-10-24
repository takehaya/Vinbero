package apply

import (
	"errors"
	"github.com/takehaya/vinbero/pkg/bpf"
	"go.uber.org/zap"
	"net"
	"testing"
)

func (f *fakeHeadend) CreateFdbOwned(bdID uint16, mac net.HardwareAddr, e *bpf.FdbEntry, owner bpf.OwnerTag) error {
	return f.CreateFdb(bdID, mac, e)
}
func (f *fakeHeadend) DeleteFdbOwned(bdID uint16, mac net.HardwareAddr, owner bpf.OwnerTag) error {
	return f.DeleteFdb(bdID, mac)
}
func (f *fakeHeadend) CreateBdPeerOwned(bdID, index uint16, e *bpf.HeadendEntry, esi [bpf.ESILen]byte, remoteSrc [bpf.IPv6AddrLen]byte, writeReverse bool, owner bpf.OwnerTag) error {
	return f.CreateBdPeer(bdID, index, e, esi, remoteSrc, writeReverse)
}
func (f *fakeHeadend) CreateBdPeerAtFreeIndexOwned(bdID uint16, e *bpf.HeadendEntry, esi [bpf.ESILen]byte, remoteSrc [bpf.IPv6AddrLen]byte, writeReverse bool, owner bpf.OwnerTag) (uint16, error) {
	return f.CreateBdPeerAtFreeIndex(bdID, e, esi, remoteSrc, writeReverse)
}
func (f *fakeHeadend) DeleteBdPeerOwned(bdID, index uint16, owner bpf.OwnerTag) (bool, error) {
	return f.DeleteBdPeer(bdID, index)
}
func (f *fakeHeadend) CreateMupUplinkV4Owned(instance uint32, endpoint string, teid uint32, bits uint8, e *bpf.HeadendEntry, owner bpf.OwnerTag) error {
	return f.CreateMupUplinkV4(instance, endpoint, teid, bits, e)
}
func (f *fakeHeadend) DeleteMupUplinkV4Owned(instance uint32, endpoint string, teid uint32, bits uint8, owner bpf.OwnerTag) error {
	return f.DeleteMupUplinkV4(instance, endpoint, teid, bits)
}
func (f *fakeHeadend) CreateMupUplinkV6Owned(instance uint32, endpoint string, teid uint32, bits uint8, e *bpf.HeadendEntry, owner bpf.OwnerTag) error {
	return f.CreateMupUplinkV6(instance, endpoint, teid, bits, e)
}
func (f *fakeHeadend) DeleteMupUplinkV6Owned(instance uint32, endpoint string, teid uint32, bits uint8, owner bpf.OwnerTag) error {
	return f.DeleteMupUplinkV6(instance, endpoint, teid, bits)
}

func (f *fakeHeadend) GetFdbOwner(bdID uint16, mac net.HardwareAddr) (bpf.OwnerTag, bool, error) {
	return "", false, nil
}
func (f *fakeHeadend) GetBdPeerOwner(bdID, index uint16) (bpf.OwnerTag, bool, error) {
	return "", false, nil
}

func (f *fakeHeadend) ListFdbOwners() (map[bpf.FdbKey]bpf.OwnerTag, error)       { return nil, nil }
func (f *fakeHeadend) ListBdPeerOwners() (map[bpf.BdPeerKey]bpf.OwnerTag, error) { return nil, nil }

type ownedSweepFake struct {
	*fakeHeadend
	fdb     map[bpf.FdbKey]bpf.OwnerTag
	peers   map[bpf.BdPeerKey]bpf.OwnerTag
	failFDB bool
}

func (f *ownedSweepFake) ListFdbOwners() (map[bpf.FdbKey]bpf.OwnerTag, error) { return f.fdb, nil }
func (f *ownedSweepFake) ListBdPeerOwners() (map[bpf.BdPeerKey]bpf.OwnerTag, error) {
	return f.peers, nil
}
func (f *ownedSweepFake) DeleteFdbOwned(bdID uint16, mac net.HardwareAddr, owner bpf.OwnerTag) error {
	if f.failFDB {
		return errors.New("injected delete failure")
	}
	key := bpf.FdbKey{BdId: bdID}
	copy(key.Mac[:], mac)
	delete(f.fdb, key)
	return nil
}
func (f *ownedSweepFake) DeleteBdPeerOwned(bdID, index uint16, owner bpf.OwnerTag) (bool, error) {
	delete(f.peers, bpf.BdPeerKey{BdId: bdID, Index: index})
	return true, nil
}
func TestSweepOwnedEVPNEntries(t *testing.T) {
	own := bpf.OwnerBGPEVPN(65000)
	foreign := bpf.OwnerPluginBundle("plugin")
	f := &ownedSweepFake{fakeHeadend: &fakeHeadend{}, fdb: map[bpf.FdbKey]bpf.OwnerTag{{BdId: 100}: own, {BdId: 200}: foreign}, peers: map[bpf.BdPeerKey]bpf.OwnerTag{{BdId: 100, Index: 1}: own, {BdId: 200, Index: 1}: foreign}, failFDB: true}
	a := &Applier{fdbBd: f, localASN: 65000, logger: zap.NewNop()}
	if a.sweepOwnedEVPNEntries() {
		t.Fatal("failed cleanup reported complete")
	}
	if len(f.peers) != 2 {
		t.Fatal("freed peer while an FDB reference survived")
	}
	f.failFDB = false
	if !a.sweepOwnedEVPNEntries() {
		t.Fatal("cleanup failed")
	}
	if len(f.fdb) != 1 || len(f.peers) != 1 || f.fdb[bpf.FdbKey{BdId: 200}] != foreign || f.peers[bpf.BdPeerKey{BdId: 200, Index: 1}] != foreign {
		t.Fatalf("foreign owner was touched: %v %v", f.fdb, f.peers)
	}
}
