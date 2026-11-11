package apply

import (
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/fib"
)

// Hooks for the tests in package apply_test, which drive the applier through
// the RPC server the daemon runs.

// FakeDataPlane records the data-plane writes of an applier.
type FakeDataPlane = fakeHeadend

func NewFakeDataPlane() *FakeDataPlane { return newFakeHeadend() }

func NewFakeFib() fib.Injector { return &fakeFib{} }

// HeadendV4 returns the trigger entry installed for prefix in vrfID.
func (f *fakeHeadend) HeadendV4(vrfID uint32, prefix string) (*bpf.HeadendEntry, bool) {
	e, ok := f.v4created[fakeHeadendKey(vrfID, prefix)]
	return e, ok
}

// EcmpGroup returns the members installed for group id.
func (f *fakeHeadend) EcmpGroup(id uint32) []bpf.EcmpPath {
	return f.ecmpGroups[id]
}

// FailEcmpWrites makes the next n ECMP group writes fail.
func (f *fakeHeadend) FailEcmpWrites(n int32) { f.putEcmpFailures.Store(n) }

// FailBdPeerWrites makes the next n bd_peer writes fail.
func (f *fakeHeadend) FailBdPeerWrites(n int32) { f.bdPeerFailures.Store(n) }

// HasFdb reports whether an FDB entry is installed for mac in bdID.
func (f *fakeHeadend) HasFdb(bdID uint16, mac string) bool {
	_, ok := f.fdb[fdbKey{bdID, mac}]
	return ok
}

// Locked runs f with the applier's locks held, so a test can read the fake
// data plane while a retry on another goroutine writes it.
func (a *Applier) Locked(f func()) {
	a.vpnMu.Lock()
	defer a.vpnMu.Unlock()
	a.mupMu.Lock()
	defer a.mupMu.Unlock()
	a.evpnMu.Lock()
	defer a.evpnMu.Unlock()
	f()
}
