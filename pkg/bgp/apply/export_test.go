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

// HeadendV4 returns the trigger entry installed for prefix.
func (f *fakeHeadend) HeadendV4(prefix string) (*bpf.HeadendEntry, bool) {
	e, ok := f.v4created[prefix]
	return e, ok
}

// EcmpGroup returns the members installed for group id.
func (f *fakeHeadend) EcmpGroup(id uint32) []bpf.EcmpPath {
	return f.ecmpGroups[id]
}
