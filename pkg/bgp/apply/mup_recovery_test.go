package apply

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/headend"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
	"go.uber.org/zap"
)

type recoveryMaps struct {
	*fakeHeadend
	owners4                                   map[bpf.MupUplinkV4Key]bpf.OwnerTag
	owners6                                   map[bpf.MupUplinkV6Key]bpf.OwnerTag
	failDelete, failGateDelete, failInventory bool
}

func (m *recoveryMaps) ListMupUplinkV4Owners() (map[bpf.MupUplinkV4Key]bpf.OwnerTag, error) {
	if m.failInventory {
		return nil, errors.New("inventory failed")
	}
	return m.owners4, nil
}
func (m *recoveryMaps) ListMupUplinkV6Owners() (map[bpf.MupUplinkV6Key]bpf.OwnerTag, error) {
	return m.owners6, nil
}
func (m *recoveryMaps) ListHeadendV4() (map[string]*bpf.HeadendEntry, error) { return m.v4created, nil }
func (m *recoveryMaps) ListHeadendV6() (map[string]*bpf.HeadendEntry, error) { return m.v6created, nil }
func recoveryKey4(instance uint32, ep string, teid uint32, bits uint8) bpf.MupUplinkV4Key {
	k := bpf.MupUplinkV4Key{Prefixlen: 64 + uint32(bits), Endpoint: netip.MustParseAddr(ep).As4()}
	binary.BigEndian.PutUint32(k.Instance[:], instance)
	binary.BigEndian.PutUint32(k.Teid[:], teid)
	return k
}
func recoveryKey6(instance uint32, ep string, teid uint32, bits uint8) bpf.MupUplinkV6Key {
	k := bpf.MupUplinkV6Key{Prefixlen: 160 + uint32(bits), Endpoint: netip.MustParseAddr(ep).As16()}
	binary.BigEndian.PutUint32(k.Instance[:], instance)
	binary.BigEndian.PutUint32(k.Teid[:], teid)
	return k
}
func (m *recoveryMaps) DeleteMupUplinkV4Owned(instance uint32, ep string, teid uint32, bits uint8, owner bpf.OwnerTag) error {
	if m.failDelete {
		return errors.New("delete failed")
	}
	k := recoveryKey4(instance, ep, teid, bits)
	if o, ok := m.owners4[k]; ok && o != owner {
		return bpf.ErrEntryOwnerMismatch
	}
	delete(m.owners4, k)
	return nil
}
func (m *recoveryMaps) DeleteMupUplinkV6Owned(instance uint32, ep string, teid uint32, bits uint8, owner bpf.OwnerTag) error {
	if m.failDelete {
		return errors.New("delete failed")
	}
	k := recoveryKey6(instance, ep, teid, bits)
	if o, ok := m.owners6[k]; ok && o != owner {
		return bpf.ErrEntryOwnerMismatch
	}
	delete(m.owners6, k)
	return nil
}
func (m *recoveryMaps) DeleteHeadendV4(prefix string, owner bpf.OwnerTag) error {
	if m.failGateDelete {
		return errors.New("gate delete failed")
	}
	return m.fakeHeadend.DeleteHeadendV4(prefix, owner)
}
func (m *recoveryMaps) DeleteHeadendV6(prefix string, owner bpf.OwnerTag) error {
	if m.failGateDelete {
		return errors.New("gate delete failed")
	}
	return m.fakeHeadend.DeleteHeadendV6(prefix, owner)
}

func TestMUPStartupDeleteFailurePreservesGateAndRetries(t *testing.T) {
	owner := bpf.OwnerBGPMUP(65000, "65000:7")
	foreign := bpf.OwnerPluginBundle("foreign")
	m := &recoveryMaps{fakeHeadend: newFakeHeadend(), owners4: map[bpf.MupUplinkV4Key]bpf.OwnerTag{
		recoveryKey4(0, "192.0.2.1", 1, 32): owner, recoveryKey4(0, "192.0.2.1", 2, 32): owner,
		recoveryKey4(0, "192.0.2.9", 1, 32): foreign,
	}, owners6: map[bpf.MupUplinkV6Key]bpf.OwnerTag{recoveryKey6(0, "2001:db8::1", 1, 32): owner}, failDelete: true}
	r, err := headend.NewReconciler(m, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := NewApplier(m, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop(), WithHeadendWriter(r))
	if len(a.mupRecovery.pending) != 3 || len(a.mupRecovery.gates) != 2 {
		t.Fatalf("recovery lost: %+v", a.mupRecovery)
	}
	if err := r.PruneUnreferencedMUPGates(); err != nil {
		t.Fatal(err)
	}
	if m.v4created["192.0.2.1/32"] == nil || m.v6created["2001:db8::1/128"] == nil {
		t.Fatal("startup pruned needed gate")
	}
	if err := a.createMUPUplinkOwned(0, "192.0.2.1", 1, 32, &bpf.HeadendEntry{}, owner); err == nil {
		t.Fatal("new session overwrote cleanup remnant")
	}
	m.failDelete = false
	m.failGateDelete = true
	a.RetryMUPOwnedCleanup()
	if len(a.mupRecovery.pending) != 0 || len(a.mupRecovery.gates) != 2 {
		t.Fatal("failed gate release was forgotten")
	}
	// Once the old uplink has gone, a replacement must not be deleted by a
	// subsequent retry whose only remaining work is releasing the gate.
	m.owners4[recoveryKey4(0, "192.0.2.1", 1, 32)] = owner
	m.failGateDelete = false
	a.RetryMUPOwnedCleanup()
	if len(a.mupRecovery.gates) != 0 || len(m.owners4) != 2 || m.owners4[recoveryKey4(0, "192.0.2.9", 1, 32)] != foreign {
		t.Fatal("retry deleted replacement/foreign owner")
	}
}

func TestMUPRecoveryGateWriteFailureStillPreventsPrune(t *testing.T) {
	owner := bpf.OwnerBGPMUP(65000, "65000:7")
	m := &recoveryMaps{fakeHeadend: newFakeHeadend(), owners4: map[bpf.MupUplinkV4Key]bpf.OwnerTag{recoveryKey4(0, "192.0.2.1", 1, 32): owner}, failDelete: true}
	m.v4created["192.0.2.1/32"] = &bpf.HeadendEntry{}
	m.v4owners["192.0.2.1/32"] = headend.MUPGateOwner
	m.createErr = errors.New("gate update failed")
	r, err := headend.NewReconciler(m, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := NewApplier(m, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop(), WithHeadendWriter(r))
	if err := r.PruneUnreferencedMUPGates(); err != nil {
		t.Fatal(err)
	}
	if m.v4created["192.0.2.1/32"] == nil {
		t.Fatal("failed gate repair lost reservation")
	}
	m.createErr = nil
	m.failDelete = false
	a.RetryMUPOwnedCleanup()
	if len(a.mupRecovery.gates) != 0 || len(m.owners4) != 0 {
		t.Fatal("recovery did not converge")
	}
}

func TestMUPStartupInventoryFailureDefersNewWrites(t *testing.T) {
	m := &recoveryMaps{fakeHeadend: newFakeHeadend(), failInventory: true}
	a := NewApplier(m, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())
	if err := a.createMUPUplinkOwned(0, "192.0.2.1", 1, 32, &bpf.HeadendEntry{}, bpf.OwnerBGPMUP(65000, "65000:7")); err == nil {
		t.Fatal("unknown startup inventory allowed replacement")
	}
	m.failInventory = false
	a.RetryMUPOwnedCleanup()
	if a.mupRecovery.rescan {
		t.Fatal("inventory not retried")
	}
}

func TestMUPRekeyDeleteFailureRetainsRecoveryDependency(t *testing.T) {
	owner := bpf.OwnerBGPMUP(65000, "65000:7")
	m := &recoveryMaps{fakeHeadend: newFakeHeadend(), owners4: map[bpf.MupUplinkV4Key]bpf.OwnerTag{}}
	r, err := headend.NewReconciler(m, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := NewApplier(m, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop(), WithHeadendWriter(r))
	st := &mupSessionState{route: bgp.MUPRoute{RD: "65000:7", Endpoint: "192.0.2.1", TEID: 1, TEIDLen: 32}, installedSID: "fd00:2::1", instance: 0}
	m.owners4[recoveryKey4(0, "192.0.2.1", 1, 32)] = owner
	dp := a.mupT2STDataPlane(netip.MustParseAddr(st.route.Endpoint), st.route.Endpoint)
	if err := a.acquireMUPGate(dp.gatePrefix, dp.gateMode, bpf.OwnerBGPMUPGate(65000), dp.createGate); err != nil {
		t.Fatal(err)
	}
	m.failDelete = true
	a.rekeyMUPT2ST(st, 9)
	if st.instance != 9 || len(a.mupRecovery.pending) != 1 {
		t.Fatal("rekey lost old instance cleanup")
	}
	if !a.releaseMUPGate(dp.gatePrefix, bpf.OwnerBGPMUPGate(65000), dp.deleteGate) {
		t.Fatal("current session release failed")
	}
	if err := r.PruneUnreferencedMUPGates(); err != nil {
		t.Fatal(err)
	}
	if m.v4created[dp.gatePrefix] == nil {
		t.Fatal("old instance lost gate after new session withdrew")
	}
	m.failDelete = false
	a.RetryMUPOwnedCleanup()
	if len(a.mupRecovery.pending) != 0 || m.v4created[dp.gatePrefix] != nil {
		t.Fatal("rekey remnant did not converge")
	}
}
