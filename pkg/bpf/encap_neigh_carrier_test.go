package bpf

import (
	"context"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// runKeeperHere runs what Run runs (a sweep, the subscriptions and the
// watch) on a thread in the calling thread's network namespace: the keeper's
// netlink calls act on the namespace of the thread they run on. The watch
// stops when the test ends.
func runKeeperHere(t *testing.T, k *EncapNeighKeeper) {
	t.Helper()
	ns, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan error, 1)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		// Never unlocked: the thread ends with the goroutine.
		runtime.LockOSThread()
		if err := netns.Set(ns); err != nil {
			started <- err
			return
		}
		if _, err := k.Sweep(); err != nil {
			t.Logf("initial sweep: %v", err)
		}
		routes, neighs, links, err := k.subscribe()
		started <- err
		if err == nil {
			k.watch(ctx, routes, neighs, links)
		}
	}()
	if err := <-started; err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		<-stopped
		_ = ns.Close()
	})
}

// carrierFlapBound is how soon after the uplink gets its carrier back its
// failed next hop must be resolved and the encapsulation redirected again.
// A pass waits for the debounce (200 ms) and the gateway answers at once;
// the kernel's own re-probe of a failed managed entry comes up to
// interval_probe_time_ms (5 s) later, and an entry nothing makes again after
// the flush waits for the resweep (30 s).
const carrierFlapBound = time.Second

// flapTimeline records, for a failure message, what the keeper and the
// neighbour entry did since the carrier came back.
type flapTimeline struct {
	mu    sync.Mutex
	start time.Time
	lines []string
}

func (l *flapTimeline) reset() {
	l.mu.Lock()
	l.start, l.lines = time.Now(), nil
	l.mu.Unlock()
}

func (l *flapTimeline) add(format string, args ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, fmt.Sprintf("%7.3fs ", time.Since(l.start).Seconds())+fmt.Sprintf(format, args...))
	l.mu.Unlock()
}

func (l *flapTimeline) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// noTentativeAddrs waits until no address in the namespace is tentative: a
// finished DAD adds a local route, and the route change would make the
// keeper re-resolve, and so make a flushed entry again, by chance.
func noTentativeAddrs(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		addrs, err := netlink.AddrList(nil, netlink.FAMILY_V6)
		if err != nil {
			t.Fatal(err)
		}
		tentative := slices.ContainsFunc(addrs, func(a netlink.Addr) bool { return a.Flags&unix.IFA_F_TENTATIVE != 0 })
		if !tentative {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("addresses still tentative after 10s: %v", addrs)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// A device that loses its carrier flushes its neighbours, managed ones
// included. The keeper makes the uplink's next hop managed again while the
// carrier is down, whoever made the entry managed first (the keeper itself,
// or the BUM flood slots before the keeper started); the entry fails while
// the carrier stays down. Once the carrier is back the keeper marks it
// managed again, so the kernel probes it at once: the tenant encapsulation,
// which cannot solicit the gateway by itself, is redirected again within
// carrierFlapBound of every flap.
func TestEncapNeighKeeperCarrierFlap(t *testing.T) {
	for _, tc := range []struct {
		name     string
		bumFirst bool
	}{{"keeper's entry", false}, {"BUM flood slots' entry", true}} {
		t.Run(tc.name, func(t *testing.T) {
			h := newXDPTestHelper(t)
			e := newEncapNeighEnv(t)
			h.headendVRFs = []uint32{1}
			src, _ := ParseIPv6("fc00:e01::1")
			segments, numSegments, _ := ParseSegments([]string{"fc00:e00::1"})
			h.createHeadendEntry("10.99.0.0/24", src, [16]byte{}, segments, numSegments, true)
			if err := h.mapOps.SetIngressPolicy(true, false, 0); err != nil {
				t.Fatal(err)
			}
			if err := h.mapOps.SetIngressVrf(map[IngressACKey]uint32{{Ifindex: e.tenant}: 1}); err != nil {
				t.Fatal(err)
			}
			pkt, err := buildSimpleIPv4Packet(net.ParseIP("10.98.0.1"), net.ParseIP("10.99.0.1"))
			if err != nil {
				t.Fatal(err)
			}
			redirected := func() bool {
				ret, out := h.runOnIfindex(slices.Clone(pkt), e.tenant)
				return ret == XDP_REDIRECT && slices.Equal(out[0:6], []byte(e.peerMAC))
			}
			var tl flapTimeline
			lastState := ""
			// entry samples the next hop's entry and records a change.
			entry := func() (netlink.Neigh, bool) {
				n, ok := e.neigh(e.gw1)
				st := "absent"
				if ok {
					st = fmt.Sprintf("state %#x managed %v", n.State, neighManaged(n))
				}
				if st != lastState {
					tl.add("entry %s", st)
					lastState = st
				}
				return n, ok
			}
			// waitEntry waits up to limit for the next hop's entry to be
			// managed and in one of states, and returns how long that took.
			waitEntry := func(limit time.Duration, states int, alsoRedirected bool) (time.Duration, bool) {
				start := time.Now()
				for time.Since(start) < limit {
					if n, ok := entry(); ok && neighManaged(n) && n.State&states != 0 && (!alsoRedirected || redirected()) {
						return time.Since(start), true
					}
					time.Sleep(10 * time.Millisecond)
				}
				return time.Since(start), false
			}
			const resolvedStates = netlink.NUD_REACHABLE | netlink.NUD_STALE | netlink.NUD_DELAY | netlink.NUD_PROBE

			if tc.bumFirst {
				key := neighKey(uint32(e.uplink), e.gw1)
				t.Cleanup(func() { bumNeighClaims.Delete(key) })
				if err := KeepNeighResolved(uint32(e.uplink), e.gw1); err != nil {
					t.Fatal(err)
				}
			}
			k := NewEncapNeighKeeper(h.mapOps, zap.NewNop())
			set := k.neigh.setManaged
			k.neigh.setManaged = func(ifindex uint32, ip net.IP) error {
				err := set(ifindex, ip)
				tl.add("keeper marks %s managed: %v", ip, err)
				return err
			}
			runKeeperHere(t, k)
			k.mu.Lock()
			_, owned := k.owned[neighKey(uint32(e.uplink), e.gw1)]
			k.mu.Unlock()
			if owned == tc.bumFirst {
				t.Fatalf("keeper owns the entry: %v, want %v", owned, !tc.bumFirst)
			}
			if _, ok := waitEntry(10*time.Second, resolvedStates, true); !ok {
				t.Fatal("the next hop is not resolved before the first flap")
			}
			noTentativeAddrs(t)

			for cycle := 1; cycle <= 3; cycle++ {
				tl.reset()
				e.setPeerLink(t, false)
				tl.add("carrier down")
				// The kernel flushes the entry, the keeper makes it again
				// and it fails after 3 probes 1 s apart.
				if _, ok := waitEntry(10*time.Second, netlink.NUD_FAILED, false); !ok {
					t.Errorf("cycle %d: with the carrier down the next hop's entry was not made managed again and failed:\n%s", cycle, &tl)
				}
				tl.reset()
				e.setPeerLink(t, true)
				tl.add("carrier up")
				took, ok := waitEntry(35*time.Second, resolvedStates, true)
				t.Logf("cycle %d: resolved and redirected %v after the carrier came back", cycle, took.Round(time.Millisecond))
				if !ok || took > carrierFlapBound {
					t.Errorf("cycle %d: recovered %v in %v, want within %v:\n%s", cycle, ok, took.Round(time.Millisecond), carrierFlapBound, &tl)
				}
			}
		})
	}
}

// A deleted entry of a next hop in the set is made again whoever made it
// managed first; the keeper then owns it, but never removes one the BUM
// flood slots hold. A deletion of an unrelated entry asks for no pass. When
// a device with next hops gets its carrier back, the unresolved managed
// entries on it are marked again, and only those: not a resolved one, not
// one without extern_learn (someone else's flags), not one on another
// device; a device without next hops asks for no pass.
func TestEncapNeighKeeperWatchFlushAndCarrier(t *testing.T) {
	main := []netlink.Route{
		route("fc00:1::/32", "fe80::1", 2),
		route("fc00:2::/32", "fe80::2", 2),
		route("fc00:3::/32", "fe80::3", 3),
	}
	walk := []netip.Addr{netip.MustParseAddr("fc00:1::1"), netip.MustParseAddr("fc00:2::1"), netip.MustParseAddr("fc00:3::1")}
	bum := neighKey(2, net.ParseIP("fe80::2"))
	nt := &fakeNeighTable{entries: map[string]netlink.Neigh{
		bum: {LinkIndex: 2, IP: net.ParseIP("fe80::2"), State: netlink.NUD_REACHABLE,
			Flags: netlink.NTF_EXT_LEARNED, FlagsExt: netlink.NTF_EXT_MANAGED},
	}}
	bumNeighClaims.Store(bum, struct{}{})
	t.Cleanup(func() { bumNeighClaims.Delete(bum) })
	k, _ := newFakeKeeper(t, &main, &walk, nt, zap.NewNop())
	if _, err := k.Sweep(); err != nil {
		t.Fatal(err)
	}
	if got := slices.Sorted(maps.Keys(k.owned)); !slices.Equal(got, []string{"2/fe80::1", "3/fe80::3"}) {
		t.Fatalf("owned = %v, want the two the keeper made", got)
	}
	sets := make(chan string, 16)
	set := k.neigh.setManaged
	k.neigh.setManaged = func(ifindex uint32, ip net.IP) error {
		err := set(ifindex, ip)
		sets <- neighKey(ifindex, ip)
		return err
	}
	// expect waits for the marks want and then for a debounce more, to
	// catch any mark beyond them.
	expect := func(what string, want ...string) {
		t.Helper()
		var got []string
		deadline := time.After(2 * time.Second)
		for len(got) < len(want) {
			select {
			case s := <-sets:
				got = append(got, s)
			case <-deadline:
				t.Fatalf("%s: marked %v, want %v", what, got, want)
			}
		}
		select {
		case s := <-sets:
			got = append(got, s)
		case <-time.After(3 * encapNeighDebounce):
		}
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Fatalf("%s: marked %v, want %v", what, got, want)
		}
	}

	var (
		neighs *neighSub
		links  *linkSub
		stop   func()
	)
	start := func() { // with new subscriptions: the watch closes them
		routes := &routeSub{routes: make(chan netlink.RouteUpdate), nexthops: make(chan struct{}), done: make(chan struct{})}
		neighs = &neighSub{updates: make(chan netlink.NeighUpdate), done: make(chan struct{})}
		links = &linkSub{updates: make(chan netlink.LinkUpdate), done: make(chan struct{})}
		ctx, cancel := context.WithCancel(context.Background())
		stopped := make(chan struct{})
		go func() { defer close(stopped); k.watch(ctx, routes, neighs, links) }()
		stop = func() { cancel(); <-stopped }
	}
	del := func(ifindex int, ip string) {
		neighs.updates <- netlink.NeighUpdate{Type: unix.RTM_DELNEIGH, Neigh: netlink.Neigh{LinkIndex: ifindex, IP: net.ParseIP(ip)}}
	}
	link := func(ifindex int32, flags uint32) {
		u := netlink.LinkUpdate{Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK}}
		u.IfInfomsg = *nl.NewIfInfomsg(unix.AF_UNSPEC)
		u.Index, u.Flags = ifindex, flags
		links.updates <- u
	}

	// The carrier went down: the kernel flushed the entries on device 2,
	// each deletion seen on its own here.
	delete(nt.entries, bum)
	start()
	del(2, "fe80::9") // not a next hop of the set
	expect("an unrelated deletion")
	del(2, "fe80::2")
	expect("the flushed BUM next hop", bum)
	delete(nt.entries, "2/fe80::1")
	del(2, "fe80::1")
	expect("the flushed next hop of the keeper", "2/fe80::1")
	link(2, unix.IFF_UP) // no carrier
	link(4, unix.IFF_UP)
	stop()

	// While the carrier was down the entries failed, device 3's too, but
	// the BUM next hop resolved; one more next hop on device 2 carries
	// someone else's flags.
	state := func(key string, s int) {
		n := nt.entries[key]
		n.State = s
		nt.entries[key] = n
	}
	state("2/fe80::1", netlink.NUD_FAILED)
	state("3/fe80::3", netlink.NUD_FAILED)
	state(bum, netlink.NUD_REACHABLE)
	nt.entries["2/fe80::4"] = netlink.Neigh{LinkIndex: 2, IP: net.ParseIP("fe80::4"), State: netlink.NUD_FAILED, FlagsExt: netlink.NTF_EXT_MANAGED}
	main = append(main, route("fc00:4::/32", "fe80::4", 2))
	walk = append(walk, netip.MustParseAddr("fc00:4::1"))
	if _, err := k.Sweep(); err != nil {
		t.Fatal(err)
	}
	start()
	link(4, unix.IFF_UP|unix.IFF_LOWER_UP) // no next hop on it
	expect("a carrier on a device without next hops")
	link(2, unix.IFF_UP|unix.IFF_LOWER_UP)
	expect("the carrier back on device 2", "2/fe80::1")
	link(2, unix.IFF_UP|unix.IFF_LOWER_UP) // still up: not a change
	expect("a link update with the carrier still up")
	// The entry was still probing and fails now: marked once more, and only
	// on the first failure; a failure on a device whose carrier did not
	// come back asks for nothing.
	failedNow := func(ifindex int, ip string) {
		neighs.updates <- netlink.NeighUpdate{Type: unix.RTM_NEWNEIGH,
			Neigh: netlink.Neigh{LinkIndex: ifindex, IP: net.ParseIP(ip), State: netlink.NUD_FAILED}}
	}
	failedNow(3, "fe80::3")
	expect("a failure on a device whose carrier did not come back")
	failedNow(2, "fe80::1")
	expect("the first failure after the carrier came back", "2/fe80::1")
	failedNow(2, "fe80::1")
	expect("a second failure")
	// Down and up again: armed again.
	link(2, unix.IFF_UP)
	link(2, unix.IFF_UP|unix.IFF_LOWER_UP)
	expect("the carrier back again", "2/fe80::1")
	link(2, unix.IFF_UP)
	failedNow(2, "fe80::1")
	expect("a failure after the carrier went down again")
	stop()
	if _, mine := k.owned[bum]; !mine {
		t.Errorf("the keeper does not own the BUM next hop it made again")
	}
	if _, mine := k.owned["2/fe80::4"]; mine {
		t.Errorf("the keeper owns an entry someone else made")
	}

	// No destination uses the BUM next hop any more: the keeper stops
	// owning it and leaves the entry.
	walk = []netip.Addr{netip.MustParseAddr("fc00:1::1")}
	for range sweepsBeforeRelease {
		if _, err := k.Sweep(); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := nt.entries[bum]; !ok {
		t.Errorf("the BUM next hop's entry was removed")
	}
	if _, mine := k.owned[bum]; mine {
		t.Errorf("the keeper still owns the BUM next hop")
	}
}

// A destination a sweep drops and a write puts back before its next hop is
// given back keeps its device among those whose carrier the watch follows.
func TestEncapNeighKeeperRescueKeepsDevice(t *testing.T) {
	a, b := netip.MustParseAddr("fc00:1::1"), netip.MustParseAddr("fc00:2::1")
	main := []netlink.Route{route("fc00:1::/32", "fe80::1", 2), route("fc00:2::/32", "fe80::2", 3)}
	walk := []netip.Addr{a, b}
	nt := &fakeNeighTable{entries: map[string]netlink.Neigh{}}
	k, _ := newFakeKeeper(t, &main, &walk, nt, zap.NewNop())
	if _, err := k.Sweep(); err != nil {
		t.Fatal(err)
	}
	walk = []netip.Addr{a}
	if _, err := k.Sweep(); err != nil { // the first miss
		t.Fatal(err)
	}
	k.res.dumpMain = func() ([]netlink.Route, error) {
		k.Notify([]netip.Addr{b}) // written after the walk
		return main, nil
	}
	if _, err := k.Sweep(); err != nil {
		t.Fatal(err)
	}
	if _, ok := k.dests[b]; !ok {
		t.Fatal("fc00:2::1 was not put back")
	}
	if !k.hasNexthopsOn(3) || !k.keepsNeigh(3, net.ParseIP("fe80::2")) {
		t.Errorf("after the rescue the watch does not follow device 3 (%v) or its next hop (%v)",
			k.hasNexthopsOn(3), k.keepsNeigh(3, net.ParseIP("fe80::2")))
	}
}

// A device's carrier comes back when it is up with a carrier and was not,
// or had not been seen; a bridge port's message and a deleted device do not
// count, and a device seen again after its deletion is new.
func TestCarrierStateCameUp(t *testing.T) {
	c := carrierState{}
	upd := func(typ uint16, family int, ifindex int32, flags uint32) netlink.LinkUpdate {
		u := netlink.LinkUpdate{Header: unix.NlMsghdr{Type: typ}}
		u.IfInfomsg = *nl.NewIfInfomsg(family)
		u.Index, u.Flags = ifindex, flags
		return u
	}
	const on = unix.IFF_UP | unix.IFF_LOWER_UP
	for i, step := range []struct {
		u    netlink.LinkUpdate
		want bool
	}{
		{upd(unix.RTM_NEWLINK, unix.AF_UNSPEC, 5, on), true}, // not seen before
		{upd(unix.RTM_NEWLINK, unix.AF_UNSPEC, 5, on), false},
		{upd(unix.RTM_NEWLINK, unix.AF_UNSPEC, 5, unix.IFF_UP), false},
		{upd(unix.RTM_NEWLINK, unix.AF_BRIDGE, 5, on), false},
		{upd(unix.RTM_NEWLINK, unix.AF_UNSPEC, 5, unix.IFF_LOWER_UP), false}, // admin down
		{upd(unix.RTM_NEWLINK, unix.AF_UNSPEC, 5, on), true},
		{upd(unix.RTM_NEWLINK, unix.AF_UNSPEC, 6, on), true},
		{upd(unix.RTM_DELLINK, unix.AF_UNSPEC, 5, on), false},
		{upd(unix.RTM_NEWLINK, unix.AF_UNSPEC, 5, on), true},
		{upd(unix.RTM_NEWLINK, unix.AF_UNSPEC, 6, on), false},
	} {
		if got := c.cameUp(step.u); got != step.want {
			t.Errorf("step %d: cameUp = %v, want %v", i, got, step.want)
		}
	}
}
