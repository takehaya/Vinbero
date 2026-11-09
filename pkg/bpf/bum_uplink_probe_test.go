package bpf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/sys/unix"
)

// inNewNetns moves the test onto a locked OS thread in a fresh network
// namespace with IPv6 forwarding on, restored when the test ends. The probe
// reads the thread's namespace, so a test that runs it stays on this thread.
func inNewNetns(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Skipf("cannot read the network namespace: %v", err)
	}
	created, err := netns.New()
	if err != nil {
		t.Skipf("cannot create a network namespace: %v", err)
	}
	t.Cleanup(func() {
		_ = netns.Set(orig)
		_ = orig.Close()
		_ = created.Close()
		runtime.UnlockOSThread()
	})
	for _, f := range []string{"all", "default"} {
		if err := os.WriteFile("/proc/sys/net/ipv6/conf/"+f+"/forwarding", []byte("1"), 0); err != nil {
			t.Skipf("cannot enable IPv6 forwarding: %v", err)
		}
	}
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
}

// linkUp adds a dummy device, up, with addr (no DAD), and returns its index.
func linkUp(t *testing.T, name, addr string) int {
	t.Helper()
	d := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
	if err := netlink.LinkAdd(d); err != nil {
		t.Skipf("cannot create dummy link: %v", err)
	}
	l, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(l); err != nil {
		t.Fatal(err)
	}
	a, err := netlink.ParseAddr(addr)
	if err != nil {
		t.Fatal(err)
	}
	a.Flags = unix.IFA_F_NODAD
	if err := netlink.AddrAdd(l, a); err != nil {
		t.Fatal(err)
	}
	return l.Attrs().Index
}

func neighAdd(t *testing.T, ifindex int, ip string) {
	t.Helper()
	mac, _ := net.ParseMAC("02:00:00:00:ec:01")
	if err := netlink.NeighAdd(&netlink.Neigh{
		LinkIndex: ifindex, Family: netlink.FAMILY_V6, State: netlink.NUD_PERMANENT,
		IP: net.ParseIP(ip), HardwareAddr: mac,
	}); err != nil {
		t.Fatal(err)
	}
}

type ecmpEnv struct {
	ac, up1, up2 int
	gw1, gw2     net.IP
	src          [IPv6AddrLen]byte
}

// newECMPEnv builds, in a new namespace, an AC and two uplinks with a
// multipath route to fc00:100::/32 through a gateway on each, permanent
// neighbours for both, and a route for each case the probe must refuse.
func newECMPEnv(t *testing.T) *ecmpEnv {
	t.Helper()
	inNewNetns(t)
	e := &ecmpEnv{
		ac:  linkUp(t, "ecmp-ac", "fd00:ac::1/64"),
		up1: linkUp(t, "ecmp-up1", "fd00:a::1/64"),
		up2: linkUp(t, "ecmp-up2", "fd00:b::1/64"),
		gw1: net.ParseIP("fd00:a::2"),
		gw2: net.ParseIP("fd00:b::2"),
	}
	e.src, _ = ParseIPv6("fc00:1::1")
	neighAdd(t, e.up1, e.gw1.String())
	neighAdd(t, e.up2, e.gw2.String())
	_, dst, _ := net.ParseCIDR("fc00:100::/32")
	if err := netlink.RouteAdd(&netlink.Route{Dst: dst, MultiPath: []*netlink.NexthopInfo{
		{LinkIndex: e.up1, Gw: e.gw1},
		{LinkIndex: e.up2, Gw: e.gw2},
	}}); err != nil {
		t.Fatalf("add multipath route: %v", err)
	}
	// On link, no gateway: the next hop is the destination itself.
	_, onlink, _ := net.ParseCIDR("fc00:200::/32")
	if err := netlink.RouteAdd(&netlink.Route{Dst: onlink, LinkIndex: e.up1}); err != nil {
		t.Fatal(err)
	}
	_, hole, _ := net.ParseCIDR("fc00:300::/32")
	if err := netlink.RouteAdd(&netlink.Route{Dst: hole, Type: unix.RTN_BLACKHOLE}); err != nil {
		t.Fatal(err)
	}
	return e
}

func ip16(s string) [IPv6AddrLen]byte {
	b, _ := ParseIPv6(s)
	return b
}

// The probe answers what the FIB answers for this AC, source and first
// segment: uplink and gateway alike, over both uplinks of a multipath
// route.
func TestUplinkProbeMatchesFIB(t *testing.T) {
	e := newECMPEnv(t)
	resolve := ProbeUplinkResolver(newXDPBumHelper(t).objs.BumUplinkProbe)

	used := map[int]int{}
	for i := range 64 {
		dst := fmt.Sprintf("fc00:100:%x::1", i)
		got, err := resolve(UplinkQuery{AC: uint32(e.ac), Src: e.src, Dst: ip16(dst)})
		if err != nil {
			t.Fatalf("probe %s: %v", dst, err)
		}
		routes, err := netlink.RouteGetWithOptions(net.ParseIP(dst), &netlink.RouteGetOptions{
			SrcAddr: net.IP(e.src[:]), IifIndex: e.ac,
		})
		if err != nil || len(routes) == 0 {
			t.Fatalf("RouteGet %s: %v", dst, err)
		}
		if int(got.Ifindex) != routes[0].LinkIndex || !got.Nexthop.Equal(routes[0].Gw) {
			t.Errorf("%s: probe answered %d/%v, kernel %d/%v", dst, got.Ifindex, got.Nexthop, routes[0].LinkIndex, routes[0].Gw)
		}
		used[int(got.Ifindex)]++
	}
	if used[e.up1] == 0 || used[e.up2] == 0 {
		t.Fatalf("64 destinations hashed to one uplink only: %v", used)
	}
}

// An uplink with no neighbour yet (NO_NEIGH) still resolves, with its next
// hop, and a destination the lookup cannot use does not. No subtests: they
// would run on another thread, outside the test's namespace.
func TestUplinkProbeAnswers(t *testing.T) {
	e := newECMPEnv(t)
	resolve := ProbeUplinkResolver(newXDPBumHelper(t).objs.BumUplinkProbe)
	ac := uint32(e.ac)

	// On link, and no neighbour for it either: the NO_NEIGH answer.
	dst := ip16("fc00:200::1")
	got, err := resolve(UplinkQuery{AC: ac, Src: e.src, Dst: dst})
	if err != nil {
		t.Fatalf("on link: %v", err)
	}
	if int(got.Ifindex) != e.up1 || !got.Nexthop.Equal(net.IP(dst[:])) {
		t.Errorf("on link: got %d/%v, want %d/%v", got.Ifindex, got.Nexthop, e.up1, net.IP(dst[:]))
	}

	for _, bad := range []string{"fc00:300::1" /* blackhole */, "2001:db8::1" /* no route */} {
		if up, err := resolve(UplinkQuery{AC: ac, Src: e.src, Dst: ip16(bad)}); err == nil {
			t.Errorf("%s: got %+v, want an error", bad, up)
		}
	}
	if up, err := resolve(UplinkQuery{AC: 12345, Src: e.src, Dst: ip16("fc00:100::1")}); err == nil {
		t.Errorf("an AC that does not exist: got %+v, want an error", up)
	}

	// Asked again after a change, the answer is the current one.
	q := UplinkQuery{AC: ac, Src: e.src, Dst: ip16("fc00:100::1")}
	_, specific, _ := net.ParseCIDR("fc00:100::1/128")
	if err := netlink.RouteAdd(&netlink.Route{Dst: specific, LinkIndex: e.up2, Gw: e.gw2}); err != nil {
		t.Fatal(err)
	}
	after, err := resolve(q)
	if err != nil {
		t.Fatal(err)
	}
	if after.Ifindex != uint32(e.up2) {
		t.Errorf("after a more specific route: uplink %d, want %d", after.Ifindex, e.up2)
	}
}

// The probe's uplink for a peer is the device the egress program's own FIB
// lookup answers, slot by slot, so a BD of peers split over both uplinks
// sends every copy and drops none as a mismatch.
func TestBumEgressFollowsTheProbe(t *testing.T) {
	e := newECMPEnv(t)
	h := newXDPBumHelper(t)
	c := &egressCase{h: h, cpu: pinCPU(t), uplinkOf: map[string]uint32{}}
	c.sync = NewBumDevmapSync(h.objs, func(uint16) uint8 { return BumModeXDP }, nil, nil)
	h.bumAC(1) // lo: forwarding is on for every device of the namespace
	l2 := bumFrame(t)
	resolve := ProbeUplinkResolver(h.objs.BumUplinkProbe)
	mode := vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2

	// Peers that use both uplinks, four each. The hash is random per boot,
	// so pick them by asking the probe, with the peers' source (c.peer).
	peerSrc := ip16("fc00::1")
	var segs [2][]string
	for i := 0; len(segs[0]) < 4 || len(segs[1]) < 4; i++ {
		if i == 1024 {
			t.Fatalf("1024 destinations did not cover both uplinks: %d and %d", len(segs[0]), len(segs[1]))
		}
		dst := fmt.Sprintf("fc00:100:%x::1", i)
		up, err := resolve(UplinkQuery{AC: 1, Src: peerSrc, Dst: ip16(dst)})
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		if up.Ifindex == uint32(e.up2) {
			n = 1
		}
		if len(segs[n]) < 4 {
			segs[n] = append(segs[n], dst)
		}
	}
	slots := append(append([]string{}, segs[0]...), segs[1]...)
	for i, dst := range slots {
		c.peer(t, uint16(i), mode, []string{dst, lastSegment(uint16(i)).String()}, [ESILen]byte{}, false)
	}
	c.ingress(t, l2)

	wantUplink := map[uint16]uint32{}
	flood := devmapEntries(t, h.objs.BumFloodMap, bumTestBD)
	for i := range slots {
		v, ok := flood[BumSlotKeyBase|uint32(i)]
		if !ok {
			t.Fatalf("slot %d has no devmap entry", i)
		}
		wantUplink[uint16(i)] = v.Ifindex
	}
	// One copy per slot, in ascending slot order per uplink (the plan's
	// order), through the device the slot's entry names.
	before := statCount(t, h.mapOps, "BUM_EGRESS_TX")
	for i := range slots {
		ret, out := c.egress(t, 1, wantUplink[uint16(i)], false, l2)
		if ret != XDP_PASS {
			t.Fatalf("copy %d: action = %d, want XDP_PASS (FIB disagrees with the devmap)", i, ret)
		}
		dst := net.IP(out[ethHeaderLen+24 : ethHeaderLen+24+ipv6AddrLen])
		if !dst.Equal(net.ParseIP(slots[i])) {
			t.Errorf("copy %d: destination %v, want %s", i, dst, slots[i])
		}
	}
	if n := statCount(t, h.mapOps, "BUM_UPLINK_MISMATCH"); n != 0 {
		t.Errorf("BUM_UPLINK_MISMATCH = %d, want 0", n)
	}
	if n := statCount(t, h.mapOps, "BUM_EGRESS_TX"); n != before+uint64(len(slots)) {
		t.Errorf("BUM_EGRESS_TX = %d, want %d", n, before+uint64(len(slots)))
	}
}

// The lookup input is the AC and the peer's encap source and first segment,
// for every AC; a BD whose ACs disagree is warned about once and recovers.
func TestBumResolverQueriesEachAC(t *testing.T) {
	h := newXDPBumHelper(t)
	core, logs := observer.New(zap.WarnLevel)
	var queries []UplinkQuery
	split := true
	var bdAC2 uint32
	upA, upB := dummyIfindex(t, "bumq-up1"), dummyIfindex(t, "bumq-up2")
	s := NewBumDevmapSync(h.objs, func(uint16) uint8 { return BumModeXDP }, func(q UplinkQuery) (BumUplink, error) {
		queries = append(queries, q)
		up := BumUplink{Ifindex: upA, Nexthop: net.ParseIP("fd00::1")}
		if split && q.AC == bdAC2 {
			up.Ifindex = upB
		}
		return up, nil
	}, zap.New(core))
	h.mapOps.SetBumDevmapSync(s)
	t.Cleanup(func() { h.mapOps.SetBumDevmapSync(nil) })

	ifA, ifB := dummyIfindex(t, "bumq-a"), dummyIfindex(t, "bumq-b")
	first, second := min(ifA, ifB), max(ifA, ifB)
	bdAC2 = second
	h.bumAC(ifB)
	h.bumAC(ifA)
	src, _ := ParseIPv6("fc00:1::5")
	segs, n, _ := ParseSegments([]string{"fc00:100:1::1", "fc00:ff::1"})
	if err := h.mapOps.CreateBdPeer(bumTestBD, 0, &HeadendEntry{
		Mode: uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2), NumSegments: n,
		SrcAddr: src, Segments: segs,
	}, [ESILen]byte{}, [IPv6AddrLen]byte{}, false); err != nil {
		t.Fatal(err)
	}

	queries = nil
	if err := s.SyncBD(bumTestBD); err != nil {
		t.Fatal(err)
	}
	want := []UplinkQuery{{AC: first, Src: src, Dst: segs[0]}, {AC: second, Src: src, Dst: segs[0]}}
	if !slices.Equal(queries, want) {
		t.Fatalf("queries = %+v, want %+v", queries, want)
	}
	// One devmap cannot serve the split: the BD takes the tc path, warned
	// about once, like the other BDs xdp mode cannot serve.
	if got := devmapEntries(t, h.objs.BumFloodMap, bumTestBD); got != nil {
		t.Fatalf("split ACs got a flood devmap: %v", got)
	}
	warned := func() int { return logs.FilterMessageSnippet("replicates BUM in tc mode").Len() }
	if warned() != 1 {
		t.Fatalf("split ACs warned %d times, want 1", warned())
	}
	if !s.retryPending() {
		t.Error("a split BD is not retried")
	}
	if err := s.SyncBD(bumTestBD); err != nil {
		t.Fatal(err)
	}
	if warned() != 1 {
		t.Errorf("a rebuild warned again: %d warnings", warned())
	}

	// The ACs agree again: back in xdp mode.
	split = false
	if err := s.SyncBD(bumTestBD); err != nil {
		t.Fatal(err)
	}
	flood := devmapEntries(t, h.objs.BumFloodMap, bumTestBD)
	if flood[BumSlotKeyBase].Ifindex != upA {
		t.Errorf("slot uplink = %d, want %d", flood[BumSlotKeyBase].Ifindex, upA)
	}
	if s.retryPending() {
		t.Error("nothing is left out, yet a retry is pending")
	}
	if warned() != 1 {
		t.Errorf("after the ACs agree: %d warnings, want still 1", warned())
	}
}

// ACs that pick different next hops on one uplink fit one devmap: no tc
// path, no warning, and both next hops are kept resolved.
func TestBumACsDifferingOnlyInNexthopStayInXDP(t *testing.T) {
	h := newXDPBumHelper(t)
	core, logs := observer.New(zap.WarnLevel)
	up := dummyIfindex(t, "bumn-up")
	ifA, ifB := dummyIfindex(t, "bumn-a"), dummyIfindex(t, "bumn-b")
	nhFor := map[uint32]net.IP{min(ifA, ifB): net.ParseIP("fd00::1"), max(ifA, ifB): net.ParseIP("fd00::2")}
	s := NewBumDevmapSync(h.objs, func(uint16) uint8 { return BumModeXDP }, func(q UplinkQuery) (BumUplink, error) {
		return BumUplink{Ifindex: up, Nexthop: nhFor[q.AC]}, nil
	}, zap.New(core))
	var kept []string
	s.SetNeighKeeper(func(_ uint32, nh net.IP) error { kept = append(kept, nh.String()); return nil })
	h.mapOps.SetBumDevmapSync(s)
	t.Cleanup(func() { h.mapOps.SetBumDevmapSync(nil) })
	h.bumAC(ifA)
	h.bumAC(ifB)
	createFloodPeer(t, h, 0)
	if err := s.SyncBD(bumTestBD); err != nil {
		t.Fatal(err)
	}
	if got := devmapEntries(t, h.objs.BumFloodMap, bumTestBD)[BumSlotKeyBase].Ifindex; got != up {
		t.Errorf("slot uplink = %d, want %d", got, up)
	}
	if logs.Len() != 0 {
		t.Errorf("warned: %v", logs.All())
	}
	if !slices.Contains(kept, "fd00::1") || !slices.Contains(kept, "fd00::2") {
		t.Errorf("kept next hops = %v, want both", kept)
	}
}

// An AC whose device is gone does not take the peers down with it: the
// other AC answers.
func TestBumResolverSkipsFailingAC(t *testing.T) {
	h := newXDPBumHelper(t)
	var failAC uint32
	up := dummyIfindex(t, "bumf-up")
	s := NewBumDevmapSync(h.objs, func(uint16) uint8 { return BumModeXDP }, func(q UplinkQuery) (BumUplink, error) {
		if q.AC == failAC {
			return BumUplink{}, fmt.Errorf("bpf_fib_lookup: no device %d: %w", q.AC, unix.ENODEV)
		}
		return BumUplink{Ifindex: up, Nexthop: net.ParseIP("fd00::1")}, nil
	}, zap.NewNop())
	h.mapOps.SetBumDevmapSync(s)
	t.Cleanup(func() { h.mapOps.SetBumDevmapSync(nil) })

	ifA, ifB := dummyIfindex(t, "bumf-a"), dummyIfindex(t, "bumf-b")
	failAC = min(ifA, ifB) // the AC that answers first fails
	h.bumAC(ifA)
	h.bumAC(ifB)
	src, _ := ParseIPv6("fc00:1::5")
	segs, n, _ := ParseSegments([]string{"fc00:100:1::1"})
	if err := h.mapOps.CreateBdPeer(bumTestBD, 0, &HeadendEntry{
		Mode: uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2), NumSegments: n,
		SrcAddr: src, Segments: segs,
	}, [ESILen]byte{}, [IPv6AddrLen]byte{}, false); err != nil {
		t.Fatal(err)
	}
	if err := s.SyncBD(bumTestBD); err != nil {
		t.Fatal(err)
	}
	flood := devmapEntries(t, h.objs.BumFloodMap, bumTestBD)
	if flood[BumSlotKeyBase].Ifindex != up {
		t.Fatalf("slot 0 entry = %+v, want uplink %d from the AC that answered", flood[BumSlotKeyBase], up)
	}
}

// An AC that has no usable route, unlike one whose device is gone, is a
// split: the BD takes the tc path.
func TestBumACWithoutRouteFallsBackToTC(t *testing.T) {
	h := newXDPBumHelper(t)
	core, logs := observer.New(zap.WarnLevel)
	up := dummyIfindex(t, "bumr-up")
	var noRoute uint32
	s := NewBumDevmapSync(h.objs, func(uint16) uint8 { return BumModeXDP }, func(q UplinkQuery) (BumUplink, error) {
		if q.AC == noRoute {
			return BumUplink{}, errors.New("no usable route")
		}
		return BumUplink{Ifindex: up, Nexthop: net.ParseIP("fd00::1")}, nil
	}, zap.New(core))
	h.mapOps.SetBumDevmapSync(s)
	t.Cleanup(func() { h.mapOps.SetBumDevmapSync(nil) })

	ifA, ifB := dummyIfindex(t, "bumr-a"), dummyIfindex(t, "bumr-b")
	noRoute = max(ifA, ifB)
	h.bumAC(ifA)
	h.bumAC(ifB)
	src, _ := ParseIPv6("fc00:1::5")
	segs, n, _ := ParseSegments([]string{"fc00:100:1::1"})
	if err := h.mapOps.CreateBdPeer(bumTestBD, 0, &HeadendEntry{
		Mode: uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2), NumSegments: n,
		SrcAddr: src, Segments: segs,
	}, [ESILen]byte{}, [IPv6AddrLen]byte{}, false); err != nil {
		t.Fatal(err)
	}
	if err := s.SyncBD(bumTestBD); err != nil {
		t.Fatal(err)
	}
	if got := devmapEntries(t, h.objs.BumFloodMap, bumTestBD); got != nil {
		t.Errorf("flood devmap = %v, want none", got)
	}
	if n := logs.FilterMessageSnippet("replicates BUM in tc mode").Len(); n != 1 {
		t.Errorf("warned %d times, want 1", n)
	}
}

// createFloodPeer adds flood peer index of bumTestBD.
func createFloodPeer(t *testing.T, h *xdpTestHelper, index uint16) {
	t.Helper()
	src, _ := ParseIPv6("fc00:1::5")
	segs, n, _ := ParseSegments([]string{fmt.Sprintf("fc00:100:%x::1", index+1)})
	if err := h.mapOps.CreateBdPeer(bumTestBD, index, &HeadendEntry{
		Mode: uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2), NumSegments: n,
		SrcAddr: src, Segments: segs,
	}, [ESILen]byte{}, [IPv6AddrLen]byte{}, false); err != nil {
		t.Fatal(err)
	}
}

// waitUntil polls cond for up to five seconds.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatal(what)
}

// startWatch runs watchRoutes on a subscription that never delivers an
// event, so whatever the test sees came from the retry.
func startWatch(t *testing.T, s *BumDevmapSync) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go s.watchRoutes(ctx, &routeSub{
		routes:   make(chan netlink.RouteUpdate),
		nexthops: make(chan struct{}),
		done:     make(chan struct{}),
	}, time.Millisecond)
}

// A slot a failed lookup left out comes back with no event at all. Until it
// does, the retries neither replace the devmap nor repeat the warning, and
// once nothing is left out they stop.
func TestBumRetriesExcludedSlot(t *testing.T) {
	h := newXDPBumHelper(t)
	core, logs := observer.New(zap.WarnLevel)
	up := dummyIfindex(t, "bumx-up")
	var failing atomic.Bool
	var calls atomic.Int64
	failing.Store(true)
	s := NewBumDevmapSync(h.objs, func(uint16) uint8 { return BumModeXDP }, func(UplinkQuery) (BumUplink, error) {
		calls.Add(1)
		if failing.Load() {
			return BumUplink{}, errors.New("bpf_fib_lookup returned 5")
		}
		return BumUplink{Ifindex: up, Nexthop: net.ParseIP("fd00::1")}, nil
	}, zap.New(core))
	s.retryPoll = 5 * time.Millisecond
	h.bumAC(1)
	createFloodPeer(t, h, 0)
	if err := s.SyncBD(bumTestBD); err != nil {
		t.Fatal(err)
	}
	if !s.retryPending() {
		t.Fatal("an excluded slot is not retried")
	}
	var innerBefore ebpf.MapID
	if err := h.objs.BumFloodMap.Lookup(uint32(bumTestBD), &innerBefore); err != nil {
		t.Fatal(err)
	}

	startWatch(t, s)
	start := calls.Load()
	waitUntil(t, "no retries while a slot is left out", func() bool { return calls.Load() >= start+5 })
	var inner ebpf.MapID
	if err := h.objs.BumFloodMap.Lookup(uint32(bumTestBD), &inner); err != nil {
		t.Fatal(err)
	}
	if inner != innerBefore {
		t.Errorf("a retry with the same result replaced the devmap: %d -> %d", innerBefore, inner)
	}
	if n := logs.FilterMessageSnippet("slot left out").Len(); n != 1 {
		t.Errorf("the persistent failure warned %d times, want 1", n)
	}

	failing.Store(false)
	// retryPending takes the rebuild's lock, so once it is false the new
	// devmap is installed and no swap can free it under the read below.
	waitUntil(t, "the slot did not come back", func() bool { return !s.retryPending() })
	if got := devmapEntries(t, h.objs.BumFloodMap, bumTestBD)[BumSlotKeyBase].Ifindex; got != up {
		t.Errorf("slot uplink = %d, want %d", got, up)
	}
	settled := calls.Load()
	time.Sleep(50 * time.Millisecond)
	if calls.Load() != settled {
		t.Errorf("retried %d times with nothing left out", calls.Load()-settled)
	}
}

// A BD on the tc path because its ACs disagree returns to xdp mode with no
// event too.
func TestBumRetriesSplitACs(t *testing.T) {
	h := newXDPBumHelper(t)
	upA, upB := dummyIfindex(t, "bumy-up1"), dummyIfindex(t, "bumy-up2")
	ifA, ifB := dummyIfindex(t, "bumy-a"), dummyIfindex(t, "bumy-b")
	var split atomic.Bool
	split.Store(true)
	s := NewBumDevmapSync(h.objs, func(uint16) uint8 { return BumModeXDP }, func(q UplinkQuery) (BumUplink, error) {
		up := upA
		if split.Load() && q.AC == max(ifA, ifB) {
			up = upB
		}
		return BumUplink{Ifindex: up, Nexthop: net.ParseIP("fd00::1")}, nil
	}, zap.NewNop())
	s.retryPoll = 5 * time.Millisecond
	h.bumAC(ifA)
	h.bumAC(ifB)
	createFloodPeer(t, h, 0)
	if err := s.SyncBD(bumTestBD); err != nil {
		t.Fatal(err)
	}
	if got := devmapEntries(t, h.objs.BumFloodMap, bumTestBD); got != nil {
		t.Fatalf("split ACs got a flood devmap: %v", got)
	}
	startWatch(t, s)
	split.Store(false)
	waitUntil(t, "the BD did not return to xdp mode", func() bool { return !s.retryPending() })
	if got := devmapEntries(t, h.objs.BumFloodMap, bumTestBD)[BumSlotKeyBase].Ifindex; got != upA {
		t.Errorf("slot uplink = %d, want %d", got, upA)
	}
}

// A BD on the tc path still keeps every AC's next hop resolved: the tc path
// drops a copy whose next hop is unresolved.
func TestBumSplitFallbackKeepsEveryNexthop(t *testing.T) {
	h := newXDPBumHelper(t)
	upA, upB := dummyIfindex(t, "bumk-up1"), dummyIfindex(t, "bumk-up2")
	ifA, ifB := dummyIfindex(t, "bumk-a"), dummyIfindex(t, "bumk-b")
	s := NewBumDevmapSync(h.objs, func(uint16) uint8 { return BumModeXDP }, func(q UplinkQuery) (BumUplink, error) {
		if q.AC == min(ifA, ifB) {
			return BumUplink{Ifindex: upA, Nexthop: net.ParseIP("fd00:a::2")}, nil
		}
		return BumUplink{Ifindex: upB, Nexthop: net.ParseIP("fd00:b::2")}, nil
	}, zap.NewNop())
	var kept []string
	s.SetNeighKeeper(func(ifindex uint32, nh net.IP) error {
		kept = append(kept, fmt.Sprintf("%d/%s", ifindex, nh))
		return nil
	})
	h.bumAC(ifA)
	h.bumAC(ifB)
	createFloodPeer(t, h, 0)
	if err := s.SyncBD(bumTestBD); err != nil {
		t.Fatal(err)
	}
	if got := devmapEntries(t, h.objs.BumFloodMap, bumTestBD); got != nil {
		t.Fatalf("split ACs got a flood devmap: %v", got)
	}
	for _, want := range []string{fmt.Sprintf("%d/fd00:a::2", upA), fmt.Sprintf("%d/fd00:b::2", upB)} {
		if !slices.Contains(kept, want) {
			t.Errorf("kept next hops = %v, missing %s", kept, want)
		}
	}
}

// Unregistering a device removes its entries from the devmaps, and moving
// it to another namespace and back unregisters it without changing its
// ifindex. The inputs of a rebuild are then the same as before, and the
// rebuild must put the entries back all the same (bum_tx_map too).
func TestBumRebuildRestoresEntriesTheKernelRemoved(t *testing.T) {
	h := newXDPTestHelperWithConstants(t, xdpBumNativeConstants)
	up := dummyIfindex(t, "bumr2-up")
	ac := dummyIfindex(t, "bumr2-ac")
	s := NewBumDevmapSync(h.objs, func(uint16) uint8 { return BumModeXDP },
		func(UplinkQuery) (BumUplink, error) { return BumUplink{Ifindex: up}, nil }, zap.NewNop())
	s.SetNativeXDP(true)
	h.bumAC(ac)
	createFloodPeer(t, h, 0)
	if err := s.SyncBD(bumTestBD); err != nil {
		t.Fatal(err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Skipf("cannot read the network namespace: %v", err)
	}
	defer func() { _ = orig.Close() }()
	other, err := netns.New()
	if err != nil {
		t.Skipf("cannot create a network namespace: %v", err)
	}
	defer func() { _ = other.Close() }()
	if err := netns.Set(orig); err != nil {
		t.Fatal(err)
	}
	move := func(from netns.NsHandle, to netns.NsHandle) {
		t.Helper()
		if err := netns.Set(from); err != nil {
			t.Fatal(err)
		}
		link, err := netlink.LinkByName("bumr2-ac")
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetNsFd(link, int(to)); err != nil {
			t.Fatal(err)
		}
		if err := netns.Set(orig); err != nil {
			t.Fatal(err)
		}
	}
	move(orig, other)
	if _, there := devmapEntries(t, h.objs.BumFloodMap, bumTestBD)[ac]; there {
		t.Fatal("the kernel kept the entry of an unregistered device: this test proves nothing")
	}
	move(other, orig)
	link, err := netlink.LinkByName("bumr2-ac")
	if err != nil {
		t.Fatal(err)
	}
	if uint32(link.Attrs().Index) != ac {
		t.Skipf("the device came back as ifindex %d, not %d", link.Attrs().Index, ac)
	}

	if err := s.SyncBD(bumTestBD); err != nil {
		t.Fatal(err)
	}
	if _, there := devmapEntries(t, h.objs.BumFloodMap, bumTestBD)[ac]; !there {
		t.Error("the AC is still missing from the flood devmap")
	}
	if _, there := devmapEntries(t, h.objs.BumLocalMap, bumTestBD)[ac]; !there {
		t.Error("the AC is still missing from the local devmap")
	}
	var v devmapVal
	if err := h.objs.BumTxMap.Lookup(ac, &v); err != nil {
		t.Errorf("the AC is still missing from bum_tx_map: %v", err)
	}
}

// A slot whose uplink device is gone cannot be added. Rebuilds with nothing
// new then neither replace the devmaps nor repeat the warning, and the slot
// comes back when the device does.
func TestBumRebuildLeavesFailedPutsAlone(t *testing.T) {
	h := newXDPBumHelper(t)
	core, logs := observer.New(zap.WarnLevel)
	const absent = uint32(54321)
	s := NewBumDevmapSync(h.objs, func(uint16) uint8 { return BumModeXDP },
		func(UplinkQuery) (BumUplink, error) { return BumUplink{Ifindex: absent}, nil }, zap.New(core))
	h.bumAC(1)
	createFloodPeer(t, h, 0)
	innerID := func() ebpf.MapID {
		t.Helper()
		var id ebpf.MapID
		if err := h.objs.BumFloodMap.Lookup(uint32(bumTestBD), &id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	if err := s.SyncBD(bumTestBD); err != nil {
		t.Fatal(err)
	}
	first := innerID()
	if err := s.SyncBD(bumTestBD); err != nil {
		t.Fatal(err)
	}
	if got := innerID(); got != first {
		t.Errorf("a rebuild with nothing new replaced the devmap: %d -> %d", first, got)
	}
	if n := logs.FilterMessageSnippet("cannot add a flood slot").Len(); n != 1 {
		t.Errorf("warned %d times, want 1", n)
	}

	d := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "bumabs", Index: int(absent)}}
	if err := netlink.LinkAdd(d); err != nil {
		t.Skipf("cannot create a dummy with a chosen ifindex: %v", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(d) })
	if err := s.SyncBD(bumTestBD); err != nil {
		t.Fatal(err)
	}
	if got := devmapEntries(t, h.objs.BumFloodMap, bumTestBD)[BumSlotKeyBase].Ifindex; got != absent {
		t.Errorf("after the device appeared: slot uplink = %d, want %d", got, absent)
	}
}

// A next hop shared by many peers and BDs is looked after once per rebuild,
// also when the devmaps are unchanged.
func TestBumRebuildDedupesNexthops(t *testing.T) {
	h := newXDPBumHelper(t)
	up := dummyIfindex(t, "bumd-up")
	s := NewBumDevmapSync(h.objs, func(uint16) uint8 { return BumModeXDP },
		func(UplinkQuery) (BumUplink, error) {
			return BumUplink{Ifindex: up, Nexthop: net.ParseIP("fd00::1")}, nil
		}, zap.NewNop())
	kept := 0
	s.SetNeighKeeper(func(uint32, net.IP) error { kept++; return nil })
	const otherBD = uint16(101)
	src, _ := ParseIPv6("fc00::1")
	segs, n, _ := ParseSegments([]string{"fc00::200"})
	h.bumAC(1)
	h.createHeadendL2Entry(1, 101, src, segs, n, otherBD)
	createFloodPeer(t, h, 0)
	createFloodPeer(t, h, 1)
	if err := h.mapOps.CreateBdPeer(otherBD, 0, &HeadendEntry{
		Mode: uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2), NumSegments: n,
		SrcAddr: src, Segments: segs,
	}, [ESILen]byte{}, [IPv6AddrLen]byte{}, false); err != nil {
		t.Fatal(err)
	}
	for pass, what := range []string{"first build", "unchanged"} {
		kept = 0
		if err := s.SyncAll(); err != nil {
			t.Fatal(err)
		}
		if kept != 1 {
			t.Errorf("pass %d (%s): kept %d times, want 1", pass, what, kept)
		}
	}
}

// A BD xdp mode cannot serve for its configuration does not come back by
// retrying, so its left-out slot does not keep the retry going.
func TestBumUnservableBDIsNotRetried(t *testing.T) {
	h := newXDPBumHelper(t)
	s := NewBumDevmapSync(h.objs, func(uint16) uint8 { return BumModeXDP },
		func(UplinkQuery) (BumUplink, error) { return BumUplink{}, errors.New("bpf_fib_lookup returned 5") }, zap.NewNop())
	src, _ := ParseIPv6("fc00::1")
	segs, n, _ := ParseSegments([]string{"fc00::200"})
	h.createHeadendL2Entry(1, 100, src, segs, n, bumTestBD)
	h.createHeadendL2Entry(1, 200, src, segs, n, bumTestBD) // mixed VLANs
	createFloodPeer(t, h, 0)
	if err := s.SyncBD(bumTestBD); err != nil {
		t.Fatal(err)
	}
	if got := devmapEntries(t, h.objs.BumFloodMap, bumTestBD); got != nil {
		t.Fatalf("flood devmap = %v, want none", got)
	}
	if s.retryPending() {
		t.Error("an unservable BD keeps the retry going")
	}
}

// A left-out slot whose peer is deleted did not recover: nothing says so.
func TestBumDeletedPeerIsNotReportedAsRecovered(t *testing.T) {
	h := newXDPBumHelper(t)
	core, logs := observer.New(zap.InfoLevel)
	s := NewBumDevmapSync(h.objs, func(uint16) uint8 { return BumModeXDP },
		func(UplinkQuery) (BumUplink, error) { return BumUplink{}, errors.New("bpf_fib_lookup returned 5") }, zap.New(core))
	h.bumAC(1)
	createFloodPeer(t, h, 0)
	if err := s.SyncBD(bumTestBD); err != nil {
		t.Fatal(err)
	}
	if err := h.objs.BdPeerMap.Delete(&BdPeerKey{BdId: bumTestBD, Index: 0}); err != nil {
		t.Fatal(err)
	}
	if err := s.SyncBD(bumTestBD); err != nil {
		t.Fatal(err)
	}
	if n := logs.FilterMessageSnippet("no longer left out").Len(); n != 0 {
		t.Errorf("a deleted peer was reported as recovered %d times", n)
	}
	if s.retryPending() {
		t.Error("a deleted peer keeps the retry going")
	}
}

// A rebuild that would produce the same devmaps leaves them in place and
// only keeps the next hops resolved; a changed answer replaces them.
func TestBumRebuildSkipsUnchangedDevmaps(t *testing.T) {
	h := newXDPBumHelper(t)
	upA, upB := dummyIfindex(t, "bums-up1"), dummyIfindex(t, "bums-up2")
	cur := upA
	s := NewBumDevmapSync(h.objs, func(uint16) uint8 { return BumModeXDP }, func(UplinkQuery) (BumUplink, error) {
		return BumUplink{Ifindex: cur, Nexthop: net.ParseIP("fd00::1")}, nil
	}, zap.NewNop())
	kept := 0
	s.SetNeighKeeper(func(uint32, net.IP) error { kept++; return nil })
	h.bumAC(1)
	src, _ := ParseIPv6("fc00:1::5")
	segs, n, _ := ParseSegments([]string{"fc00:100:1::1"})
	if err := h.mapOps.CreateBdPeer(bumTestBD, 0, &HeadendEntry{
		Mode: uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2), NumSegments: n,
		SrcAddr: src, Segments: segs,
	}, [ESILen]byte{}, [IPv6AddrLen]byte{}, false); err != nil {
		t.Fatal(err)
	}
	innerID := func() ebpf.MapID {
		t.Helper()
		var id ebpf.MapID
		if err := h.objs.BumFloodMap.Lookup(uint32(bumTestBD), &id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	if err := s.SyncBD(bumTestBD); err != nil {
		t.Fatal(err)
	}
	first := innerID()
	keptBefore := kept

	if err := s.SyncBD(bumTestBD); err != nil {
		t.Fatal(err)
	}
	if got := innerID(); got != first {
		t.Errorf("devmap replaced by a rebuild with the same answers: %d -> %d", first, got)
	}
	if kept <= keptBefore {
		t.Error("the skipped rebuild did not keep the next hops resolved")
	}

	cur = upB
	if err := s.SyncBD(bumTestBD); err != nil {
		t.Fatal(err)
	}
	if got := innerID(); got == first {
		t.Error("devmap not replaced after the uplink changed")
	}
	if got := devmapEntries(t, h.objs.BumFloodMap, bumTestBD)[BumSlotKeyBase].Ifindex; got != upB {
		t.Errorf("slot uplink = %d, want %d", got, upB)
	}
}

// watchRebuilds runs watchRoutes on a fake subscription and returns a
// function waiting for the next rebuild.
func watchRebuilds(t *testing.T, s *BumDevmapSync, resolved chan struct{}) (sub *routeSub, wait func(string)) {
	t.Helper()
	sub = &routeSub{
		routes:   make(chan netlink.RouteUpdate, 1),
		nexthops: make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go s.watchRoutes(ctx, sub, 10*time.Millisecond)
	return sub, func(what string) {
		t.Helper()
		select {
		case <-resolved:
		case <-time.After(5 * time.Second):
			t.Fatalf("no rebuild after %s", what)
		}
		// Drain the resolver calls of this rebuild (one per peer and AC).
		for {
			select {
			case <-resolved:
			case <-time.After(50 * time.Millisecond):
				return
			}
		}
	}
}

// A rebuild follows a route update, a nexthop object update, and a rise of
// the egress program's resync counter: everything the kernel does not send
// an event for. Without a rise a poll does nothing.
func TestBumWatchRebuilds(t *testing.T) {
	h := newXDPBumHelper(t)
	resolved := make(chan struct{}, 64)
	s := NewBumDevmapSync(h.objs, func(uint16) uint8 { return BumModeXDP }, func(UplinkQuery) (BumUplink, error) {
		resolved <- struct{}{}
		return BumUplink{Ifindex: 1}, nil
	}, zap.NewNop())
	s.resyncPoll = 5 * time.Millisecond
	h.bumAC(1)
	src, _ := ParseIPv6("fc00::1")
	segs, n, _ := ParseSegments([]string{"fc00::200"})
	if err := h.mapOps.CreateBdPeer(bumTestBD, 0, &HeadendEntry{
		Mode: uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2), NumSegments: n,
		SrcAddr: src, Segments: segs,
	}, [ESILen]byte{}, [IPv6AddrLen]byte{}, false); err != nil {
		t.Fatal(err)
	}
	s.uplinkResyncRose()
	sub, wait := watchRebuilds(t, s, resolved)

	sub.routes <- netlink.RouteUpdate{}
	wait("a route update")
	sub.nexthops <- struct{}{}
	wait("a nexthop update")

	raise := func(n uint64) {
		t.Helper()
		perCPU := make([]uint64, possibleCPUs(t))
		perCPU[0] = n
		if err := h.objs.BumUplinkResync.Put(uint32(0), perCPU); err != nil {
			t.Fatal(err)
		}
	}
	raise(1)
	wait("the resync counter rose")
	raise(1) // no rise: a poll must not rebuild
	select {
	case <-resolved:
		t.Error("rebuilt although the counter did not rise")
	case <-time.After(100 * time.Millisecond):
	}
	raise(2)
	wait("the resync counter rose again")
}

func possibleCPUs(t *testing.T) int {
	t.Helper()
	n, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// The nexthop group of RTNLGRP_NEXTHOP delivers an event for a nexthop
// object: there is no netlink library API to check this with.
func TestBumSubscribesToNexthops(t *testing.T) {
	inNewNetns(t)
	linkUp(t, "nhsub-up", "fd00:c::1/64")
	s := &BumDevmapSync{logger: zap.NewNop()}
	sub, err := s.subscribeRoutes()
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	t.Cleanup(func() { close(sub.done) })

	out, err := exec.Command("ip", "nexthop", "add", "id", "42", "dev", "nhsub-up").CombinedOutput()
	if err != nil {
		t.Skipf("cannot add a nexthop object: %v: %s", err, out)
	}
	select {
	case <-sub.nexthops:
	case <-time.After(5 * time.Second):
		t.Fatal("no event on the nexthop subscription")
	}
}
