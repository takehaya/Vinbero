package bpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/vinbero/pkg/fibmode"
	"github.com/vishvananda/netlink"
)

// The global VRF's lookups in internal.bpf.fib_lookup_global "auto": in a
// namespace pkg/fibmode finds eligible, the direct lookup must give the
// answer of the full one for every destination. Each destination below is
// sent through vinbero_main twice, once with fib_global_mode_map at the
// full lookup and once at the direct lookup, and the verdict and the whole
// output frame (next hop MAC, output device MAC, rewritten headers) must be
// the same. The lookups run in End.DT4 / End.DT6 (decapsulated packet, on the
// ingress port or on a VRF device) and in H.Encaps (outer header, on a port
// enslaved to a VRF device), the paths srv6_fib_global_flags serves.

const fibAutoConst = "fib_lookup_global_auto"

// ipCmd runs ip(8) in the test's namespace (the locked thread's).
func ipCmd(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
	}
}

// ipTry is ipCmd for a setup the kernel may lack (IPv6 subtrees); it
// reports whether the command worked.
func ipTry(args ...string) bool {
	return exec.Command("ip", args...).Run() == nil
}

func sysctlSet(t *testing.T, path, v string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(v), 0); err != nil {
		t.Skipf("%s: %v", path, err)
	}
}

type fibEqEnv struct {
	in, up, up2 int
	srcSubtrees bool // the kernel took the source-specific IPv6 routes
	vrf         int  // VRF device, 0 without
	ten         int  // port enslaved to the VRF
}

// newFibEqEnv builds the namespace the destinations are looked up in.
// history "rule-added-deleted" adds and removes an ip rule first, so the
// kernel's full lookup walks the rules; "never" leaves the kernel's fast
// path; withVRF adds a VRF device with a closed table and an enslaved port.
func newFibEqEnv(t *testing.T, history string, withVRF bool) *fibEqEnv {
	t.Helper()
	inNewNetns(t)
	for _, f := range []string{"all", "default"} {
		sysctlSet(t, "/proc/sys/net/ipv4/conf/"+f+"/forwarding", "1")
	}
	e := &fibEqEnv{
		in:  linkUp(t, "feq-in", "fd00:9::1/64"),
		up:  linkUp(t, "feq-up", "fd00:e::1/64"),
		up2: linkUp(t, "feq-up2", "fd00:f::1/64"),
	}
	ipCmd(t, "addr", "add", "198.51.100.1/24", "dev", "feq-in")
	ipCmd(t, "addr", "add", "192.0.2.1/24", "dev", "feq-up")
	ipCmd(t, "addr", "add", "203.0.113.1/24", "dev", "feq-up2")
	ipCmd(t, "addr", "add", "10.255.0.1/32", "dev", "lo")
	ipCmd(t, "addr", "add", "2001:db8:ff::1/128", "dev", "lo")
	for _, n := range [][3]string{
		{"fd00:e::2", "02:00:00:00:e0:02", "feq-up"},
		{"fd00:e::3", "02:00:00:00:e0:03", "feq-up"},
		{"fd00:f::2", "02:00:00:00:f0:02", "feq-up2"},
		{"192.0.2.2", "02:00:00:00:e4:02", "feq-up"},
		{"203.0.113.2", "02:00:00:00:f4:02", "feq-up2"},
	} {
		ipCmd(t, "neigh", "replace", n[0], "lladdr", n[1], "dev", n[2], "nud", "permanent")
	}
	for _, r := range [][]string{
		{"-6", "route", "add", "fc00:e00::/32", "via", "fd00:e::2", "dev", "feq-up"},
		{"-6", "route", "add", "fc00:e10::/48", "nexthop", "via", "fd00:e::2", "dev", "feq-up", "nexthop", "via", "fd00:f::2", "dev", "feq-up2"},
		{"-6", "route", "add", "blackhole", "fc00:e20::/48"},
		{"-6", "route", "add", "unreachable", "fc00:e21::/48"},
		{"-6", "route", "add", "prohibit", "fc00:e22::/48"},
		{"-6", "route", "add", "throw", "fc00:e40::/48"},
		{"-6", "route", "add", "default", "via", "fd00:f::2", "dev", "feq-up2"},
		{"route", "add", "10.97.0.0/24", "via", "192.0.2.2", "dev", "feq-up"},
		{"route", "add", "10.95.0.0/24", "nexthop", "via", "192.0.2.2", "dev", "feq-up", "nexthop", "via", "203.0.113.2", "dev", "feq-up2"},
		{"route", "add", "blackhole", "10.96.1.0/24"},
		{"route", "add", "unreachable", "10.96.2.0/24"},
		{"route", "add", "prohibit", "10.96.3.0/24"},
		{"route", "add", "throw", "10.94.0.0/24"},
		{"route", "add", "default", "via", "203.0.113.2", "dev", "feq-up2"},
	} {
		ipCmd(t, r...)
	}
	// An IPv4-mapped IPv6 address in the local table.
	ipCmd(t, "-6", "route", "add", "local", "::ffff:198.18.0.1/128", "dev", "lo", "table", "local")
	// Source-specific IPv6 routes need CONFIG_IPV6_SUBTREES.
	e.srcSubtrees = ipTry("-6", "route", "add", "fc00:e30::/48", "from", "2001:db8:5::/48", "via", "fd00:e::3", "dev", "feq-up") &&
		ipTry("-6", "route", "add", "fc00:e30::/48", "via", "fd00:e::2", "dev", "feq-up")
	if history == "rule-added-deleted" {
		for _, fam := range []string{"-4", "-6"} {
			ipCmd(t, fam, "rule", "add", "pref", "100", "lookup", "100")
			ipCmd(t, fam, "rule", "del", "pref", "100")
		}
	}
	if withVRF {
		if !ipTry("link", "add", "feq-vrf", "type", "vrf", "table", "100") {
			t.Skip("kernel lacks the vrf module")
		}
		ipCmd(t, "link", "set", "feq-vrf", "up")
		sysctlSet(t, "/proc/sys/net/ipv4/conf/feq-vrf/forwarding", "1")
		sysctlSet(t, "/proc/sys/net/ipv6/conf/feq-vrf/forwarding", "1")
		ipCmd(t, "route", "add", "unreachable", "default", "table", "100", "metric", "4278198272")
		ipCmd(t, "-6", "route", "add", "unreachable", "default", "table", "100", "metric", "4278198272")
		ipCmd(t, "route", "add", "10.98.0.0/24", "via", "192.0.2.2", "dev", "feq-up", "onlink", "table", "100")
		ipCmd(t, "-6", "route", "add", "fd00:d::/64", "via", "fd00:e::2", "dev", "feq-up", "onlink", "table", "100")
		e.ten = linkUp(t, "feq-ten", "fd00:a::1/64")
		ipCmd(t, "link", "set", "feq-ten", "master", "feq-vrf")
		ipCmd(t, "addr", "add", "10.80.0.1/24", "dev", "feq-ten")
		_ = ipTry("-6", "addr", "add", "fd00:a::1/64", "dev", "feq-ten", "nodad")
		l, err := netlink.LinkByName("feq-vrf")
		if err != nil {
			t.Fatal(err)
		}
		e.vrf = l.Attrs().Index
	}
	return e
}

// fibEqCase is one lookup: the packet and the device it arrives on.
type fibEqCase struct {
	name    string
	pkt     []byte
	ifindex int
}

func dt4Case(t *testing.T, sid, src, dst string, ifindex int) fibEqCase {
	t.Helper()
	pkt, err := buildSRv6PacketWithInnerIPv4(net.ParseIP("fd00:9::9"), net.ParseIP(sid),
		[]net.IP{net.ParseIP(sid)}, 0, net.ParseIP(src).To4(), net.ParseIP(dst).To4())
	if err != nil {
		t.Fatal(err)
	}
	return fibEqCase{name: fmt.Sprintf("End.DT4 %s %s->%s", sid, src, dst), pkt: pkt, ifindex: ifindex}
}

func dt6Case(t *testing.T, sid, src, dst string, ifindex int) fibEqCase {
	t.Helper()
	pkt, err := buildEncapsulatedPacket(net.ParseIP("fd00:9::9"), net.ParseIP(sid),
		[]net.IP{net.ParseIP(sid)}, 0, net.ParseIP(src), net.ParseIP(dst), innerTypeIPv6)
	if err != nil {
		t.Fatal(err)
	}
	return fibEqCase{name: fmt.Sprintf("End.DT6 %s %s->%s", sid, src, dst), pkt: pkt, ifindex: ifindex}
}

// gtp4eCase is an End.M.GTP4.E packet whose GTP-U outer IPv4 destination is
// dst: its lookup runs on the ingress port, and its verdict keeps the
// kernel hand-off (XDP_PASS) apart from a drop, which End.DT4 does not.
func gtp4eCase(t *testing.T, dst string, ifindex int) fibEqCase {
	t.Helper()
	da := net.ParseIP("fc00:47::").To16()
	copy(da[7:11], net.ParseIP(dst).To4())
	da[11] = 1 << 2 // QFI 1
	da[15] = 7      // TEID
	pkt, err := buildSRv6PacketWithInnerIPv4(net.ParseIP("fd00:9::9"), net.IP(da), []net.IP{net.IP(da)}, 0,
		net.ParseIP("172.16.0.1").To4(), net.ParseIP("172.16.0.2").To4())
	if err != nil {
		t.Fatal(err)
	}
	return fibEqCase{name: "End.M.GTP4.E to " + dst, pkt: pkt, ifindex: ifindex}
}

// endXNexthops are the adjacencies End.X resolves (endpoint_resolve_adjacency),
// one SID each: fc00:dd::<index+1>.
var endXNexthops = []string{"fd00:e::2", "fd00:e::7", "fd00:e::1", "2001:db8:ff::1", "fc00:e00::1", "fc00:e20::1"}

func endXCase(t *testing.T, i, ifindex int) fibEqCase {
	t.Helper()
	sid := fmt.Sprintf("fc00:dd::%x", i+1)
	pkt, err := buildSRv6Packet(net.ParseIP("2001:db8:6::1"), net.ParseIP(sid),
		[]net.IP{net.ParseIP("fc00:e00::99"), net.ParseIP(sid)}, 1)
	if err != nil {
		t.Fatal(err)
	}
	return fibEqCase{name: "End.X to " + endXNexthops[i], pkt: pkt, ifindex: ifindex}
}

// probeCase is an IPv6 lookup through bum_uplink_probe, which hands back
// bpf_fib_lookup's own return code, the output ifindex and the next hop.
type probeCase struct {
	src, dst string
	ifindex  int
}

func (h *xdpTestHelper) probe(c probeCase) (ret int32, ifindex uint32, nexthop net.IP) {
	h.t.Helper()
	in := make([]byte, uplinkProbeIOLen)
	copy(in[0:16], net.ParseIP(c.src).To16())
	copy(in[16:32], net.ParseIP(c.dst).To16())
	binary.NativeEndian.PutUint32(in[32:], uint32(c.ifindex))
	out := make([]byte, uplinkProbeIOLen)
	if _, err := h.objs.BumUplinkProbe.Run(&ebpf.RunOptions{Data: in, DataOut: out}); err != nil {
		h.t.Fatal(err)
	}
	return int32(binary.NativeEndian.Uint32(out[36:])), binary.NativeEndian.Uint32(out[32:]), net.IP(append([]byte(nil), out[16:32]...))
}

func checkSameProbe(t *testing.T, h *xdpTestHelper, cases []probeCase) {
	t.Helper()
	rets := map[int32]int{}
	for _, c := range cases {
		if err := h.mapOps.SetFibGlobalMode(false, false); err != nil {
			t.Fatal(err)
		}
		r0, if0, nh0 := h.probe(c)
		if err := h.mapOps.SetFibGlobalMode(true, true); err != nil {
			t.Fatal(err)
		}
		r1, if1, nh1 := h.probe(c)
		if err := h.mapOps.SetFibGlobalMode(false, false); err != nil {
			t.Fatal(err)
		}
		rets[r0]++
		if r0 != r1 || if0 != if1 || !nh0.Equal(nh1) {
			t.Errorf("probe %s -> %s on ifindex %d: full lookup returns %d, ifindex %d, next hop %s; direct %d, %d, %s",
				c.src, c.dst, c.ifindex, r0, if0, nh0, r1, if1, nh1)
		}
	}
	t.Logf("%d probed lookups, bpf_fib_lookup results of the full lookup: %v", len(cases), rets)
}

// Destinations of the global VRF's lookups.
var (
	globalV4Dsts = []string{
		"10.97.0.1",       // via a gateway
		"192.0.2.2",       // on link, neighbour known
		"192.0.2.9",       // on link, no neighbour
		"192.0.2.1",       // the node's own address
		"192.0.2.255",     // subnet broadcast (local table)
		"10.255.0.1",      // a /32 on lo: only the local table has it, the default route covers it
		"127.0.0.1",       // loopback
		"127.1.2.3",       // 127.0.0.0/8
		"10.96.1.1",       // blackhole
		"10.96.2.1",       // unreachable
		"10.96.3.1",       // prohibit
		"10.94.0.1",       // throw
		"8.8.8.8",         // default route
		"224.0.0.5",       // multicast
		"255.255.255.255", // limited broadcast
	}
	globalV6Dsts = []string{
		"fc00:e00::1",        // via a gateway
		"fd00:e::2",          // on link, neighbour known
		"fd00:e::7",          // on link, no neighbour
		"fd00:e::1",          // the node's own address
		"fd00:e::",           // subnet-router anycast (local table)
		"2001:db8:ff::1",     // a /128 on lo
		"::ffff:198.18.0.1",  // IPv4-mapped, in the local table
		"::1",                // loopback
		"ff02::1",            // multicast, link scope
		"ff0e::5",            // multicast, global scope: the default route covers it
		"fc00:e20::1",        // blackhole
		"fc00:e21::1",        // unreachable
		"fc00:e22::1",        // prohibit
		"fc00:e40::1",        // throw
		"2001:db8:abcd::1",   // default route
		"fe80::1",            // link-local
		"fc00:e30::1",        // source-specific route, another source
		"2001:db8:ffff::abc", // default route again
	}
	// Lookups on the VRF device, and on the port enslaved to it.
	vrfV4Dsts = []string{
		"10.98.0.1",  // route in the VRF table
		"10.98.9.9",  // the VRF table's unreachable default
		"10.80.0.1",  // the VRF's own address (in the VRF table)
		"10.80.0.9",  // the VRF's connected subnet, no neighbour
		"10.97.0.1",  // only the main table has it
		"192.0.2.1",  // a global address of the node (local table)
		"10.255.0.1", // a /32 on lo
		"127.0.0.1",
	}
	vrfV6Dsts = []string{
		"fd00:d::1", "fd00:dd::1", "fd00:a::1", "fd00:a::9", "fc00:e00::1", "fd00:e::1", "2001:db8:ff::1", "ff0e::5",
	}
)

// globalCases are the lookups of the global VRF on the ingress port.
func (e *fibEqEnv) globalCases(t *testing.T) ([]fibEqCase, []probeCase) {
	const dt4, dt6 = "fc00:d4::1", "fc00:d6::1"
	var cs []fibEqCase
	var ps []probeCase
	for _, dst := range globalV4Dsts {
		cs = append(cs, dt4Case(t, dt4, "198.51.100.7", dst, e.in), gtp4eCase(t, dst, e.in))
	}
	for i := 1; i <= 8; i++ { // multipath: the hash takes source and destination
		cs = append(cs, dt4Case(t, dt4, fmt.Sprintf("198.51.100.%d", 10+i), fmt.Sprintf("10.95.0.%d", i), e.in),
			gtp4eCase(t, fmt.Sprintf("10.95.0.%d", i), e.in))
	}
	for _, dst := range globalV6Dsts {
		cs = append(cs, dt6Case(t, dt6, "2001:db8:6::1", dst, e.in))
		ps = append(ps, probeCase{"2001:db8:6::1", dst, e.in})
	}
	for i := 1; i <= 8; i++ {
		src, dst := fmt.Sprintf("2001:db8:6::%x", 0x10+i), fmt.Sprintf("fc00:e10::%x", i)
		cs = append(cs, dt6Case(t, dt6, src, dst, e.in))
		ps = append(ps, probeCase{src, dst, e.in})
	}
	for i := range endXNexthops {
		cs = append(cs, endXCase(t, i, e.in))
	}
	if e.srcSubtrees { // the source-specific route, from its source
		cs = append(cs, dt6Case(t, dt6, "2001:db8:5::1", "fc00:e30::1", e.in))
		ps = append(ps, probeCase{"2001:db8:5::1", "fc00:e30::1", e.in})
	}
	return cs, ps
}

// vrfCases are the lookups on the VRF device (End.DT4/DT6 bound to the
// VRF) and on the enslaved port (End.DT4/DT6 without a VRF, decapsulated on
// the port, which l3mdev takes to the VRF table).
func (e *fibEqEnv) vrfCases(t *testing.T) ([]fibEqCase, []probeCase) {
	var cs []fibEqCase
	var ps []probeCase
	for _, dst := range vrfV4Dsts {
		cs = append(cs, dt4Case(t, "fc00:d4::2", "198.51.100.7", dst, e.in), dt4Case(t, "fc00:d4::1", "198.51.100.7", dst, e.ten))
	}
	for _, dst := range vrfV6Dsts {
		cs = append(cs, dt6Case(t, "fc00:d6::2", "2001:db8:6::1", dst, e.in), dt6Case(t, "fc00:d6::1", "2001:db8:6::1", dst, e.ten))
		ps = append(ps, probeCase{"2001:db8:6::1", dst, e.vrf}, probeCase{"2001:db8:6::1", dst, e.ten})
	}
	return cs, ps
}

// fibEqHelper loads the auto program and installs the SIDs the cases use.
func fibEqHelper(t *testing.T, e *fibEqEnv) *xdpTestHelper {
	t.Helper()
	h := newXDPTestHelperWithConstants(t, map[string]any{fibAutoConst: uint8(1)})
	h.createSidFunction("fc00:d4::1/128", actionEndDT4)
	h.createSidFunction("fc00:d6::1/128", actionEndDT6)
	h.createSidFunctionGTP4E("fc00:47::/56", [4]byte{198, 51, 100, 1}, 7)
	for i, nh := range endXNexthops {
		a, err := ParseIPv6(nh)
		if err != nil {
			t.Fatal(err)
		}
		h.createSidFunctionWithNexthop(fmt.Sprintf("fc00:dd::%x/128", i+1), actionEndX, a)
	}
	if e.vrf != 0 {
		h.createSidFunctionWithVRF("fc00:d4::2/128", actionEndDT4, uint32(e.vrf))
		h.createSidFunctionWithVRF("fc00:d6::2/128", actionEndDT6, uint32(e.vrf))
	}
	return h
}

// decide reads the namespace as the daemon does and writes the local
// addresses of the decision; the families must be eligible.
func decideEligible(t *testing.T, h *xdpTestHelper) fibmode.Decision {
	t.Helper()
	s, err := fibmode.Read()
	if err != nil {
		t.Fatalf("read the namespace: %v", err)
	}
	d := fibmode.Decide(s)
	if !d.V4.Direct || !d.V6.Direct {
		t.Fatalf("namespace not eligible for the direct lookup: IPv4 %q, IPv6 %q", d.V4.Why, d.V6.Why)
	}
	if err := h.mapOps.SyncFibLocal(d.V4.Local, d.V6.Local); err != nil {
		t.Fatal(err)
	}
	return d
}

func (h *xdpTestHelper) runBoth(c fibEqCase) (full, direct struct {
	ret uint32
	out []byte
}) {
	h.t.Helper()
	if err := h.mapOps.SetFibGlobalMode(false, false); err != nil {
		h.t.Fatal(err)
	}
	full.ret, full.out = h.runOnIfindex(append([]byte(nil), c.pkt...), uint32(c.ifindex))
	if err := h.mapOps.SetFibGlobalMode(true, true); err != nil {
		h.t.Fatal(err)
	}
	direct.ret, direct.out = h.runOnIfindex(append([]byte(nil), c.pkt...), uint32(c.ifindex))
	if err := h.mapOps.SetFibGlobalMode(false, false); err != nil {
		h.t.Fatal(err)
	}
	return full, direct
}

func checkSame(t *testing.T, h *xdpTestHelper, cases []fibEqCase) {
	t.Helper()
	verdicts := map[uint32]int{}
	for _, c := range cases {
		full, direct := h.runBoth(c)
		verdicts[full.ret]++
		if full.ret != direct.ret || !bytes.Equal(full.out, direct.out) {
			t.Errorf("%s (ifindex %d): full lookup gives verdict %d, frame %x; direct gives %d, frame %x",
				c.name, c.ifindex, full.ret, head(full.out), direct.ret, head(direct.out))
		}
	}
	t.Logf("%d lookups, verdicts of the full lookup: %v", len(cases), verdicts)
}

func head(b []byte) []byte {
	if len(b) > 64 {
		return b[:64]
	}
	return b
}

func TestFibGlobalDirectMatchesFullLookup(t *testing.T) {
	for _, tc := range []struct {
		history string
		vrf     bool
	}{{"never", false}, {"rule-added-deleted", false}, {"vrf-present", true}} {
		t.Run(tc.history, func(t *testing.T) {
			e := newFibEqEnv(t, tc.history, tc.vrf)
			h := fibEqHelper(t, e)
			decideEligible(t, h)
			cases, probes := e.globalCases(t)
			if tc.vrf {
				c, p := e.vrfCases(t)
				cases, probes = append(cases, c...), append(probes, p...)
			}
			checkSame(t, h, cases)
			checkSameProbe(t, h, probes)
			// The multipath flows do spread over both paths.
			outs := map[uint32]bool{}
			for i := 1; i <= 8; i++ {
				_, ifx, _ := h.probe(probeCase{fmt.Sprintf("2001:db8:6::%x", 0x10+i), fmt.Sprintf("fc00:e10::%x", i), e.in})
				outs[ifx] = true
			}
			if len(outs) < 2 {
				t.Errorf("the multipath flows all leave by %v; the multipath cases test one path only", outs)
			}
		})
	}
}

// The comparison can tell the two lookups apart: with the local addresses
// left out of the map, the direct lookup forwards a packet for the node's
// own /32 on lo to the default gateway, which the full lookup hands to the
// kernel (End.M.GTP4.E keeps that verdict).
func TestFibGlobalDirectNeedsTheLocalAddresses(t *testing.T) {
	e := newFibEqEnv(t, "rule-added-deleted", false)
	h := fibEqHelper(t, e)
	decideEligible(t, h)
	if err := h.mapOps.SyncFibLocal(nil, nil); err != nil {
		t.Fatal(err)
	}
	full, direct := h.runBoth(gtp4eCase(t, "10.255.0.1", e.in))
	if full.ret != XDP_PASS || direct.ret != XDP_REDIRECT {
		t.Fatalf("without the local addresses: full lookup verdict %d, direct %d; want %d and %d", full.ret, direct.ret, XDP_PASS, XDP_REDIRECT)
	}
}

// Each namespace below has something the direct lookup would not follow,
// and the daemon's decision keeps the family on the full lookup. Where the
// difference shows in a packet, forcing the direct lookup anyway gives a
// different answer, which is what the full lookup protects.
func TestFibGlobalDirectExcludedSetups(t *testing.T) {
	cases := []struct {
		name   string
		v6     bool // the family the setup is for
		setup  [][]string
		probe  func(t *testing.T, e *fibEqEnv) fibEqCase
		reason string
	}{
		{
			name: "policy rule", setup: [][]string{
				{"route", "add", "10.97.0.0/24", "via", "203.0.113.2", "dev", "feq-up2", "table", "200"},
				{"rule", "add", "pref", "100", "to", "10.97.0.0/24", "lookup", "200"},
			},
			probe: func(t *testing.T, e *fibEqEnv) fibEqCase {
				return dt4Case(t, "fc00:d4::1", "198.51.100.7", "10.97.0.1", e.in)
			},
			reason: "ip rule 100",
		},
		{
			name: "IPv6 policy rule", v6: true, setup: [][]string{
				{"-6", "route", "add", "fc00:e00::/32", "via", "fd00:f::2", "dev", "feq-up2", "table", "200"},
				{"-6", "rule", "add", "pref", "100", "from", "2001:db8:6::/48", "lookup", "200"},
			},
			probe: func(t *testing.T, e *fibEqEnv) fibEqCase {
				return dt6Case(t, "fc00:d6::1", "2001:db8:6::1", "fc00:e00::1", e.in)
			},
			reason: "ip rule 100",
		},
		{
			name: "rule with a selector the kernel added later (ipproto)", setup: [][]string{
				{"rule", "add", "pref", "100", "ipproto", "tcp", "lookup", "main"},
			},
			reason: "ip rule 100",
		},
		{
			name: "rule with an action other than a lookup", v6: true, setup: [][]string{
				{"-6", "rule", "add", "pref", "100", "to", "fc00:e00::/32", "unreachable"},
			},
			probe: func(t *testing.T, e *fibEqEnv) fibEqCase {
				return dt6Case(t, "fc00:d6::1", "2001:db8:6::1", "fc00:e00::1", e.in)
			},
			reason: "ip rule 100",
		},
		{
			name: "local route to a prefix (AnyIP)", setup: [][]string{
				{"route", "add", "local", "10.200.0.0/16", "dev", "lo", "table", "local"},
			},
			probe: func(t *testing.T, e *fibEqEnv) fibEqCase {
				return dt4Case(t, "fc00:d4::1", "198.51.100.7", "10.200.0.1", e.in)
			},
			reason: "local table has a route to 10.200.0.0/16",
		},
		{
			name: "route in the default table", setup: [][]string{
				{"route", "add", "10.93.0.0/24", "via", "192.0.2.2", "dev", "feq-up", "table", "default"},
			},
			reason: "default table (253)",
		},
		{
			name: "VRF table without an unreachable default", setup: [][]string{
				{"link", "add", "feq-vrf2", "type", "vrf", "table", "102"},
			},
			reason: "does not end in an unreachable default",
		},
		{
			name: "throw route in a VRF table", setup: [][]string{
				{"link", "add", "feq-vrf3", "type", "vrf", "table", "103"},
				{"route", "add", "unreachable", "default", "table", "103"},
				{"-6", "route", "add", "unreachable", "default", "table", "103"},
				{"route", "add", "throw", "10.97.0.0/24", "table", "103"},
			},
			reason: "throw route",
		},
		{
			name: "VRF table closed through a nexthop object", setup: [][]string{
				{"link", "add", "feq-vrf5", "type", "vrf", "table", "105"},
				{"nexthop", "add", "id", "51", "blackhole"},
				{"route", "add", "default", "nhid", "51", "table", "105"},
				{"-6", "nexthop", "add", "id", "52", "blackhole"},
				{"-6", "route", "add", "default", "nhid", "52", "table", "105"},
			},
			reason: "blackhole nexthop",
		},
		{
			name: "VRF device without the l3mdev rule", v6: true, setup: [][]string{
				{"link", "add", "feq-vrf4", "type", "vrf", "table", "104"},
				{"route", "add", "unreachable", "default", "table", "104"},
				{"-6", "route", "add", "unreachable", "default", "table", "104"},
				{"-6", "rule", "del", "pref", "1000"},
			},
			reason: "no l3mdev rule",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newFibEqEnv(t, "rule-added-deleted", false)
			h := fibEqHelper(t, e)
			for _, args := range c.setup {
				if strings.Contains(strings.Join(args, " "), "type vrf") && !ipTry(args...) {
					t.Skip("kernel lacks the vrf module")
				} else if !strings.Contains(strings.Join(args, " "), "type vrf") {
					ipCmd(t, args...)
				}
			}
			s, err := fibmode.Read()
			if err != nil {
				t.Fatalf("read the namespace: %v", err)
			}
			d := fibmode.Decide(s)
			f := d.V4
			if c.v6 {
				f = d.V6
			}
			if f.Direct || !strings.Contains(f.Why, c.reason) {
				t.Fatalf("decision direct=%v why %q, want the full lookup because of %q", f.Direct, f.Why, c.reason)
			}
			if c.probe == nil {
				return
			}
			// Force the direct lookup to show what the decision avoids.
			local4, local6 := d.V4.Local, d.V6.Local
			if err := h.mapOps.SyncFibLocal(local4, local6); err != nil {
				t.Fatal(err)
			}
			full, direct := h.runBoth(c.probe(t, e))
			if full.ret == direct.ret && bytes.Equal(full.out, direct.out) {
				t.Fatalf("forced direct lookup gives the full lookup's answer (verdict %d); the setup shows nothing", full.ret)
			}
		})
	}
}
