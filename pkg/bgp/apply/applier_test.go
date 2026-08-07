package apply

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/fib"
	"github.com/takehaya/vinbero/pkg/locator"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// fdbKey / bdPeerKey identify recorded EVPN writes in fakeHeadend.
type fdbKey struct {
	bdID uint16
	mac  string
}
type bdPeerKey struct {
	bdID  uint16
	index uint16
}

// fakeHeadend records headend map calls instead of touching BPF.
type fakeHeadend struct {
	v4created map[string]*bpf.HeadendEntry
	v6created map[string]*bpf.HeadendEntry
	v4deleted []string
	v6deleted []string
	createErr error

	fdb           map[fdbKey]*bpf.FdbEntry
	bdPeers       map[bdPeerKey]*bpf.HeadendEntry
	bdPeerReverse map[bdPeerKey]bool // writeReverse flag passed per peer
	bdPeerErr     error
	fdbErr        error
	fdbDelErr     error
	bdPeerDelErr  error
	esis          map[[bpf.ESILen]byte]*bpf.EsiEntry

	mupUplink map[mupUplinkKey]*bpf.HeadendEntry
}

func newFakeHeadend() *fakeHeadend {
	return &fakeHeadend{
		v4created:     map[string]*bpf.HeadendEntry{},
		v6created:     map[string]*bpf.HeadendEntry{},
		fdb:           map[fdbKey]*bpf.FdbEntry{},
		bdPeers:       map[bdPeerKey]*bpf.HeadendEntry{},
		bdPeerReverse: map[bdPeerKey]bool{},
		esis:          map[[bpf.ESILen]byte]*bpf.EsiEntry{},
	}
}

func (f *fakeHeadend) CreateFdb(bdID uint16, mac net.HardwareAddr, e *bpf.FdbEntry) error {
	if f.fdbErr != nil {
		return f.fdbErr
	}
	f.fdb[fdbKey{bdID, mac.String()}] = e
	return nil
}

func (f *fakeHeadend) DeleteFdb(bdID uint16, mac net.HardwareAddr) error {
	if f.fdbDelErr != nil {
		return f.fdbDelErr
	}
	delete(f.fdb, fdbKey{bdID, mac.String()})
	return nil
}

func (f *fakeHeadend) CreateBdPeer(bdID, index uint16, e *bpf.HeadendEntry, _ [bpf.ESILen]byte, _ [bpf.IPv6AddrLen]byte, writeReverse bool) error {
	if f.bdPeerErr != nil {
		return f.bdPeerErr
	}
	f.bdPeers[bdPeerKey{bdID, index}] = e
	f.bdPeerReverse[bdPeerKey{bdID, index}] = writeReverse
	return nil
}

func (f *fakeHeadend) DeleteBdPeer(bdID, index uint16) error {
	if f.bdPeerDelErr != nil {
		return f.bdPeerDelErr
	}
	delete(f.bdPeers, bdPeerKey{bdID, index})
	return nil
}

// FindFreeBdPeerIndex returns the lowest index not present in bdPeers for bdID,
// mirroring the real map-probing allocator.
func (f *fakeHeadend) FindFreeBdPeerIndex(bdID uint16) uint16 {
	for i := uint16(0); i < bpf.MaxBumNexthops; i++ {
		if _, ok := f.bdPeers[bdPeerKey{bdID, i}]; !ok {
			return i
		}
	}
	return bpf.MaxBumNexthops
}

// GetEsi / SetEsiDfPe model the esi_map for DF election tests. A test seeds an
// ESI (local-attached or not) into f.esis; SetEsiDfPe records the elected DF.
func (f *fakeHeadend) GetEsi(esi [bpf.ESILen]byte) (*bpf.EsiEntry, error) {
	e, ok := f.esis[esi]
	if !ok {
		return nil, errors.New("esi not found")
	}
	return e, nil
}

func (f *fakeHeadend) SetEsiDfPe(esi [bpf.ESILen]byte, dfAddr [bpf.IPv6AddrLen]byte) (*bpf.EsiEntry, error) {
	e, ok := f.esis[esi]
	if !ok {
		return nil, errors.New("esi not found")
	}
	e.DfPeSrcAddr = dfAddr
	return e, nil
}

// no-op SR Policy map ops so fakeHeadend satisfies the applier's dataPlane
// interface; the SR Policy table is unit-tested separately (srpolicy_test).
func (f *fakeHeadend) UpsertSRPolicy(uint32, []netip.Addr) error { return nil }
func (f *fakeHeadend) DeleteSRPolicy(uint32) error               { return nil }
func (f *fakeHeadend) HighestSRPolicyIDInUse() (uint32, error)   { return 0, nil }

// mupUplinkKey records an mup_uplink_v4_map write in fakeHeadend.
type mupUplinkKey struct {
	instance uint32
	endpoint string
	teid     uint32
	teidLen  uint8
}

func (f *fakeHeadend) CreateMupUplinkV4(instance uint32, endpoint string, teid uint32, teidPrefixBits uint8, e *bpf.HeadendEntry) error {
	if f.createErr != nil {
		return f.createErr
	}
	if f.mupUplink == nil {
		f.mupUplink = map[mupUplinkKey]*bpf.HeadendEntry{}
	}
	f.mupUplink[mupUplinkKey{instance, endpoint, teid, teidPrefixBits}] = e
	return nil
}

func (f *fakeHeadend) DeleteMupUplinkV4(instance uint32, endpoint string, teid uint32, teidPrefixBits uint8) error {
	delete(f.mupUplink, mupUplinkKey{instance, endpoint, teid, teidPrefixBits})
	return nil
}

func (f *fakeHeadend) CreateMupUplinkV6(instance uint32, endpoint string, teid uint32, teidPrefixBits uint8, e *bpf.HeadendEntry) error {
	if f.createErr != nil {
		return f.createErr
	}
	if f.mupUplink == nil {
		f.mupUplink = map[mupUplinkKey]*bpf.HeadendEntry{}
	}
	f.mupUplink[mupUplinkKey{instance, endpoint, teid, teidPrefixBits}] = e
	return nil
}

func (f *fakeHeadend) DeleteMupUplinkV6(instance uint32, endpoint string, teid uint32, teidPrefixBits uint8) error {
	delete(f.mupUplink, mupUplinkKey{instance, endpoint, teid, teidPrefixBits})
	return nil
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
	a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())

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
	a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())

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
	a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())

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
	a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "NOPE", 65000, zap.NewNop())

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
	a := NewApplier(newFakeHeadend(), testLocatorManager(t), vrfbgp.NewManager(), ff, "LOC1", 65000, zap.NewNop())

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
	a := NewApplier(fh, testLocatorManager(t), vm, &fakeFib{}, "LOC1", 65000, zap.NewNop())

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

// TestApplier_ImportRTFilterPerFamily confirms the new family-aware filter:
// a vpnv6-only binding does NOT gate a vpnv4 route (vpnv4 stays
// default-allow until its own family binding arrives), and a vpnv4 binding
// only filters the vpnv4 family even when vpnv6 is missing.
func TestApplier_ImportRTFilterPerFamily(t *testing.T) {
	fh := newFakeHeadend()
	vm := vrfbgp.NewManager()
	// Bind only the vpnv6 family explicitly via the new Families form.
	if err := vm.Bind(vrfbgp.Binding{
		VRFName: "vrf-v6only",
		Families: map[bgp.Family]vrfbgp.FamilyPolicy{
			bgp.FamilyVPNv6: {RouteTargets: []vrfbgp.RouteTarget{
				{RT: "65000:600", Direction: vrfbgp.DirectionImport},
			}},
		},
	}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	a := NewApplier(fh, testLocatorManager(t), vm, &fakeFib{}, "LOC1", 65000, zap.NewNop())

	// vpnv4 carries an RT the vpnv6 binding does NOT import, but vpnv4 has
	// no binding so default-allow keeps the route.
	a.Apply(bgp.RouteEvent{
		Family: bgp.FamilyVPNv4,
		VPN: &bgp.VPNRoute{
			Family: bgp.FamilyVPNv4, Prefix: "10.11.0.0/24", RD: "65000:11",
			SRv6SID: "fd00:1:1:f::", RTs: []string{"65000:999"},
		},
	})
	if _, ok := fh.v4created["10.11.0.0/24"]; !ok {
		t.Error("vpnv4 must stay default-allow when only vpnv6 has a binding")
	}

	// vpnv6 with the matching RT is accepted.
	a.Apply(bgp.RouteEvent{
		Family: bgp.FamilyVPNv6,
		VPN: &bgp.VPNRoute{
			Family: bgp.FamilyVPNv6, Prefix: "2001:db8:6::/64", RD: "65000:12",
			SRv6SID: "fd00:1:1:10::", RTs: []string{"65000:600"},
		},
	})
	if _, ok := fh.v6created["2001:db8:6::/64"]; !ok {
		t.Error("vpnv6 must accept a route whose RT the family-bound VRF imports")
	}

	// vpnv6 with a non-matching RT is dropped (the family has a binding now).
	a.Apply(bgp.RouteEvent{
		Family: bgp.FamilyVPNv6,
		VPN: &bgp.VPNRoute{
			Family: bgp.FamilyVPNv6, Prefix: "2001:db8:7::/64", RD: "65000:13",
			SRv6SID: "fd00:1:1:11::", RTs: []string{"65000:999"},
		},
	})
	if _, ok := fh.v6created["2001:db8:7::/64"]; ok {
		t.Error("vpnv6 route with an unmatched RT must be dropped once the family has a binding")
	}
}

// TestApplier_CreateErrorLogged confirms a headend write failure does
// not panic the handler (errors are logged, not returned).
func TestApplier_CreateErrorLogged(t *testing.T) {
	fh := newFakeHeadend()
	fh.createErr = errors.New("boom")
	a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())
	a.Apply(bgp.RouteEvent{
		Family: bgp.FamilyVPNv4,
		VPN:    &bgp.VPNRoute{Family: bgp.FamilyVPNv4, Prefix: "10.3.0.0/24", RD: "65000:3", SRv6SID: "fd00:1:1:c::"},
	})
	// No assertion beyond "did not panic"; the error path is logged.
}

// TestApplier_VPNv4ColorStampsPolicyId covers the color->policy_id steering
// seam in applyVPN: a colored route with a parseable IPv6 next hop must
// stamp a non-zero policy_id on the headend entry, while an un-colored
// route (or one with no usable next hop) must not steer.
func TestApplier_VPNv4ColorStampsPolicyId(t *testing.T) {
	fh := newFakeHeadend()
	a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())

	a.Apply(bgp.RouteEvent{Family: bgp.FamilyVPNv4, VPN: &bgp.VPNRoute{
		Family: bgp.FamilyVPNv4, Prefix: "10.0.0.0/24", RD: "65000:100",
		SRv6SID: "fd00:1:1:a::", Color: 100, NextHop: "2001:db8::2",
	}})
	if e := fh.v4created["10.0.0.0/24"]; e == nil || e.PolicyId == 0 {
		t.Fatalf("colored route should stamp a non-zero policy_id; got %+v", e)
	}

	a.Apply(bgp.RouteEvent{Family: bgp.FamilyVPNv4, VPN: &bgp.VPNRoute{
		Family: bgp.FamilyVPNv4, Prefix: "10.1.0.0/24", RD: "65000:101",
		SRv6SID: "fd00:1:1:b::", // no Color
	}})
	if e := fh.v4created["10.1.0.0/24"]; e == nil || e.PolicyId != 0 {
		t.Errorf("un-colored route must not steer; policy_id = %d", e.PolicyId)
	}

	a.Apply(bgp.RouteEvent{Family: bgp.FamilyVPNv4, VPN: &bgp.VPNRoute{
		Family: bgp.FamilyVPNv4, Prefix: "10.2.0.0/24", RD: "65000:102",
		SRv6SID: "fd00:1:1:c::", Color: 200, NextHop: "", // unparseable next hop
	}})
	if e := fh.v4created["10.2.0.0/24"]; e == nil || e.PolicyId != 0 {
		t.Errorf("colored route with no next hop must not steer; policy_id = %d", e.PolicyId)
	}

	// An IPv4 next hop could never match an IPv6 SR Policy endpoint, so the
	// route must not steer and must not reserve a phantom policy_id.
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyVPNv4, VPN: &bgp.VPNRoute{
		Family: bgp.FamilyVPNv4, Prefix: "10.3.0.0/24", RD: "65000:103",
		SRv6SID: "fd00:1:1:d::", Color: 200, NextHop: "10.9.9.9",
	}})
	if e := fh.v4created["10.3.0.0/24"]; e == nil || e.PolicyId != 0 {
		t.Errorf("colored route with an IPv4 next hop must not steer; policy_id = %d", e.PolicyId)
	}
	if id := a.srPolicy.idOf(200, netip.MustParseAddr("10.9.9.9")); id != 0 {
		t.Errorf("an IPv4 next hop must not reserve a policy_id; got %d", id)
	}
}

// TestApplier_ColorSteerRefcountLifecycle covers the reverse-index refcount
// seam: a colored route reserves a policy_id, a re-advertise of the same
// target must not double-count the reference, and the withdraw must release
// it so the policy is reaped (a leaked reference here would keep the id
// pinned forever).
func TestApplier_ColorSteerRefcountLifecycle(t *testing.T) {
	fh := newFakeHeadend()
	a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())
	ep := netip.MustParseAddr("2001:db8::2")

	colored := func() bgp.RouteEvent {
		return bgp.RouteEvent{Family: bgp.FamilyVPNv4, VPN: &bgp.VPNRoute{
			Family: bgp.FamilyVPNv4, Prefix: "10.0.0.0/24", RD: "65000:100",
			SRv6SID: "fd00:1:1:a::", Color: 100, NextHop: "2001:db8::2",
		}}
	}

	a.Apply(colored())
	id := a.srPolicy.idOf(100, ep)
	if id == 0 {
		t.Fatalf("colored route did not reserve a policy_id")
	}
	if got := fh.v4created["10.0.0.0/24"].PolicyId; got != id {
		t.Fatalf("stamped policy_id %d != reserved %d", got, id)
	}

	// Re-advertise the unchanged route: same id, reference not double-counted.
	a.Apply(colored())
	if got := a.srPolicy.idOf(100, ep); got != id {
		t.Fatalf("policy_id changed on re-advertise: %d -> %d", id, got)
	}

	// Withdraw releases the single reference -> the policy is reaped.
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyVPNv4, IsWithdraw: true, VPN: &bgp.VPNRoute{
		Family: bgp.FamilyVPNv4, Prefix: "10.0.0.0/24", RD: "65000:100",
	}})
	if got := a.srPolicy.idOf(100, ep); got != 0 {
		t.Errorf("policy not reaped after withdraw (idOf=%d); a re-advertise likely leaked a reference", got)
	}
}

// TestApplier_ColorSteerRetarget covers a route changing its steering target
// on re-advertise: the old policy reference is released and the new one
// taken, so the stale {color, endpoint} is reaped.
func TestApplier_ColorSteerRetarget(t *testing.T) {
	fh := newFakeHeadend()
	a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())
	ep1 := netip.MustParseAddr("2001:db8::2")
	ep2 := netip.MustParseAddr("2001:db8::3")

	a.Apply(bgp.RouteEvent{Family: bgp.FamilyVPNv4, VPN: &bgp.VPNRoute{
		Family: bgp.FamilyVPNv4, Prefix: "10.0.0.0/24", RD: "65000:100",
		SRv6SID: "fd00:1:1:a::", Color: 100, NextHop: "2001:db8::2",
	}})
	if a.srPolicy.idOf(100, ep1) == 0 {
		t.Fatalf("first advertise did not reserve a policy_id")
	}

	// Same prefix re-advertised steering to a different next hop.
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyVPNv4, VPN: &bgp.VPNRoute{
		Family: bgp.FamilyVPNv4, Prefix: "10.0.0.0/24", RD: "65000:100",
		SRv6SID: "fd00:1:1:a::", Color: 100, NextHop: "2001:db8::3",
	}})
	if got := a.srPolicy.idOf(100, ep1); got != 0 {
		t.Errorf("stale steering target not released on retarget (idOf=%d)", got)
	}
	if id2 := a.srPolicy.idOf(100, ep2); id2 == 0 {
		t.Errorf("new steering target not referenced after retarget")
	}
}
