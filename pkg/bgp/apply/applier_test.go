package apply

import (
	"errors"
	"net/netip"
	"testing"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/fib"
	"github.com/takehaya/vinbero/pkg/locator"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// fakeHeadend records headend map calls instead of touching BPF.
type fakeHeadend struct {
	v4created map[string]*bpf.HeadendEntry
	v6created map[string]*bpf.HeadendEntry
	v4deleted []string
	v6deleted []string
	createErr error
}

func newFakeHeadend() *fakeHeadend {
	return &fakeHeadend{
		v4created: map[string]*bpf.HeadendEntry{},
		v6created: map[string]*bpf.HeadendEntry{},
	}
}

func (f *fakeHeadend) CreateHeadendV4(p string, e *bpf.HeadendEntry, _ bpf.OwnerTag) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.v4created[p] = e
	return nil
}

func (f *fakeHeadend) CreateHeadendV6(p string, e *bpf.HeadendEntry, _ bpf.OwnerTag) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.v6created[p] = e
	return nil
}

func (f *fakeHeadend) DeleteHeadendV4(p string, _ bpf.OwnerTag) error {
	f.v4deleted = append(f.v4deleted, p)
	return nil
}

func (f *fakeHeadend) DeleteHeadendV6(p string, _ bpf.OwnerTag) error {
	f.v6deleted = append(f.v6deleted, p)
	return nil
}

// fakeFib records FIB injector calls.
type fakeFib struct {
	added   []fib.Route
	deleted []netip.Prefix
}

func (f *fakeFib) Add(r fib.Route) error       { f.added = append(f.added, r); return nil }
func (f *fakeFib) Delete(p netip.Prefix) error { f.deleted = append(f.deleted, p); return nil }
func (f *fakeFib) List() ([]fib.Route, error)  { return f.added, nil }

// testLocatorManager returns a manager with one Classic locator named
// "LOC1" covering fd00:1:1::/48.
func testLocatorManager(t *testing.T) *locator.Manager {
	t.Helper()
	mgr := locator.NewManager()
	loc := locator.Locator{
		Name:              "LOC1",
		Prefix:            netip.MustParsePrefix("fd00:1:1::/48"),
		BlockLen:          32,
		NodeLen:           16,
		FunctionLen:       16,
		ArgumentLen:       64,
		Behavior:          locator.BehaviorClassic,
		FunctionAutoStart: 0x10,
		FunctionAutoEnd:   0xFFFF,
	}
	if err := mgr.Add(&loc); err != nil {
		t.Fatalf("locator Add: %v", err)
	}
	return mgr
}

func TestApplier_VPNv4Advertise(t *testing.T) {
	fh := newFakeHeadend()
	a := NewApplier(fh, newFakePolicyMap(), testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())

	a.Apply(bgp.RouteEvent{
		Family: bgp.FamilyVPNv4,
		VPN: &bgp.VPNRoute{
			Family:  bgp.FamilyVPNv4,
			Prefix:  "10.0.0.0/24",
			RD:      "65000:100",
			SRv6SID: "fd00:1:1:a::",
		},
	})

	entry, ok := fh.v4created["10.0.0.0/24"]
	if !ok {
		t.Fatalf("CreateHeadendV4 not called; v4created=%v", fh.v4created)
	}
	// SrcAddr must come from the source locator's prefix (fd00:1:1::).
	wantSrc := netip.MustParseAddr("fd00:1:1::").As16()
	if entry.SrcAddr != wantSrc {
		t.Errorf("SrcAddr = %v, want %v", entry.SrcAddr, wantSrc)
	}
	// The single segment / outer destination is the service SID.
	wantSID := netip.MustParseAddr("fd00:1:1:a::").As16()
	if entry.DstAddr != wantSID {
		t.Errorf("DstAddr = %v, want SID %v", entry.DstAddr, wantSID)
	}
	if entry.NumSegments != 1 {
		t.Errorf("NumSegments = %d, want 1", entry.NumSegments)
	}
}

func TestApplier_VPNWithdraw(t *testing.T) {
	fh := newFakeHeadend()
	a := NewApplier(fh, newFakePolicyMap(), testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())

	a.Apply(bgp.RouteEvent{
		Family:     bgp.FamilyVPNv6,
		IsWithdraw: true,
		VPN:        &bgp.VPNRoute{Family: bgp.FamilyVPNv6, Prefix: "2001:db8::/48", RD: "65000:200"},
	})
	if len(fh.v6deleted) != 1 || fh.v6deleted[0] != "2001:db8::/48" {
		t.Errorf("DeleteHeadendV6 = %v, want [2001:db8::/48]", fh.v6deleted)
	}
}

func TestApplier_VPNRouteWithoutSIDSkipped(t *testing.T) {
	fh := newFakeHeadend()
	a := NewApplier(fh, newFakePolicyMap(), testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())

	a.Apply(bgp.RouteEvent{
		Family: bgp.FamilyVPNv4,
		VPN:    &bgp.VPNRoute{Family: bgp.FamilyVPNv4, Prefix: "10.1.0.0/24", RD: "65000:1"},
	})
	if len(fh.v4created) != 0 {
		t.Errorf("a SID-less VPN route must not create a headend entry; got %v", fh.v4created)
	}
}

func TestApplier_MissingSourceLocatorSkips(t *testing.T) {
	fh := newFakeHeadend()
	// srcLocator names a locator the manager does not have.
	a := NewApplier(fh, newFakePolicyMap(), testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "NOPE", 65000, zap.NewNop())

	a.Apply(bgp.RouteEvent{
		Family: bgp.FamilyVPNv4,
		VPN:    &bgp.VPNRoute{Family: bgp.FamilyVPNv4, Prefix: "10.2.0.0/24", RD: "65000:2", SRv6SID: "fd00:1:1:b::"},
	})
	if len(fh.v4created) != 0 {
		t.Errorf("an unresolved source locator must abort the install; got %v", fh.v4created)
	}
}

func TestApplier_UnicastAdvertiseAndWithdraw(t *testing.T) {
	ff := &fakeFib{}
	a := NewApplier(newFakeHeadend(), newFakePolicyMap(), testLocatorManager(t), vrfbgp.NewManager(), ff, "LOC1", 65000, zap.NewNop())

	a.Apply(bgp.RouteEvent{
		Family:  bgp.FamilyIPv6Unicast,
		Unicast: &bgp.UnicastRoute{Prefix: "2001:db8:dead::/64", NextHop: "fd00:f1b::2"},
	})
	if len(ff.added) != 1 {
		t.Fatalf("fib.Add calls = %d, want 1", len(ff.added))
	}
	if ff.added[0].Prefix != netip.MustParsePrefix("2001:db8:dead::/64") {
		t.Errorf("added prefix = %s, want 2001:db8:dead::/64", ff.added[0].Prefix)
	}

	a.Apply(bgp.RouteEvent{
		Family:     bgp.FamilyIPv6Unicast,
		IsWithdraw: true,
		Unicast:    &bgp.UnicastRoute{Prefix: "2001:db8:dead::/64"},
	})
	if len(ff.deleted) != 1 {
		t.Errorf("fib.Delete calls = %d, want 1", len(ff.deleted))
	}
}

// TestApplier_ImportRTFilter confirms that once a VRF binding exists,
// only routes whose RT matches some VRF's import_rts are installed.
func TestApplier_ImportRTFilter(t *testing.T) {
	fh := newFakeHeadend()
	vm := vrfbgp.NewManager()
	if err := vm.Bind(vrfbgp.Binding{VRFName: "vrf-a", ImportRTs: []string{"65000:100"}}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	a := NewApplier(fh, newFakePolicyMap(), testLocatorManager(t), vm, &fakeFib{}, "LOC1", 65000, zap.NewNop())

	// RT 65000:999 matches no VRF import -> dropped.
	a.Apply(bgp.RouteEvent{
		Family: bgp.FamilyVPNv4,
		VPN: &bgp.VPNRoute{
			Family: bgp.FamilyVPNv4, Prefix: "10.9.0.0/24", RD: "65000:9",
			SRv6SID: "fd00:1:1:d::", RTs: []string{"65000:999"},
		},
	})
	if _, ok := fh.v4created["10.9.0.0/24"]; ok {
		t.Errorf("route with an unmatched RT must be dropped")
	}

	// RT 65000:100 matches vrf-a -> accepted.
	a.Apply(bgp.RouteEvent{
		Family: bgp.FamilyVPNv4,
		VPN: &bgp.VPNRoute{
			Family: bgp.FamilyVPNv4, Prefix: "10.10.0.0/24", RD: "65000:10",
			SRv6SID: "fd00:1:1:e::", RTs: []string{"65000:100"},
		},
	})
	if _, ok := fh.v4created["10.10.0.0/24"]; !ok {
		t.Errorf("route with a matched RT must be installed")
	}
}

// TestApplier_CreateErrorLogged confirms a headend write failure does
// not panic the handler (errors are logged, not returned).
func TestApplier_CreateErrorLogged(t *testing.T) {
	fh := newFakeHeadend()
	fh.createErr = errors.New("boom")
	a := NewApplier(fh, newFakePolicyMap(), testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())
	a.Apply(bgp.RouteEvent{
		Family: bgp.FamilyVPNv4,
		VPN:    &bgp.VPNRoute{Family: bgp.FamilyVPNv4, Prefix: "10.3.0.0/24", RD: "65000:3", SRv6SID: "fd00:1:1:c::"},
	})
	// No assertion beyond "did not panic"; the error path is logged.
}
