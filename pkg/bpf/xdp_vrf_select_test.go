package bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// vrfSelectEnv puts the same destinations in three tables, each with its own
// next hop: the tables of two VRF devices (through a port enslaved to each)
// and the main table (through a port in no VRF). A lookup that runs in VRF A
// redirects to macA, in VRF B to macB, and in the ingress context of a
// packet that came in on lo (the main table) to macMain. A test that asserts
// the next-hop MAC therefore tells which table the data plane looked the
// packet up in, instead of seeing the same verdict for every table.
type vrfSelectEnv struct {
	vrfA, vrfB          uint32 // VRF device ifindexes
	macA, macB, macMain net.HardwareAddr
}

// The destinations every table of vrfSelectEnv routes.
const (
	vrfSelDst4 = "198.51.100.7"
	vrfSelDst6 = "2001:db8:5e::7"
)

func newVrfSelectEnv(t *testing.T) *vrfSelectEnv {
	t.Helper()
	enableIPForwarding(t)
	e := &vrfSelectEnv{}
	var err error
	e.macA, _ = net.ParseMAC("02:5e:00:00:00:0a")
	e.macB, _ = net.ParseMAC("02:5e:00:00:00:0b")
	e.macMain, _ = net.ParseMAC("02:5e:00:00:00:0f")
	if e.vrfA, err = vrfSelectTable(t, "vsel-a", 111, 0xa, e.macA); err != nil {
		t.Fatal(err)
	}
	if e.vrfB, err = vrfSelectTable(t, "vsel-b", 112, 0xb, e.macB); err != nil {
		t.Fatal(err)
	}
	if _, err = vrfSelectTable(t, "vsel-m", 0, 0xf, e.macMain); err != nil {
		t.Fatal(err)
	}
	return e
}

// vrfSelectTable adds a port with a resolved gateway (fd00:5e:<n>::2 and
// 10.250.<n>.2, both at mac) and routes the test destinations through it
// (vrfSelDst4/6, and the SID spaces whose addresses the endpoint tests
// forward to after an SRH step or a shift). With table 0 the port stays in
// no VRF and the routes go to the main table; otherwise the port is
// enslaved to a new VRF device of that table, whose ifindex it returns.
func vrfSelectTable(t *testing.T, name string, table uint32, n int, mac net.HardwareAddr) (uint32, error) {
	t.Helper()
	var vrfIdx uint32
	var vrf netlink.Link
	if table != 0 {
		if err := netlink.LinkAdd(&netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: name + "-vrf"}, Table: table}); err != nil {
			if errors.Is(err, unix.EOPNOTSUPP) {
				t.Skipf("kernel lacks the vrf module: %v", err)
			}
			return 0, err
		}
		var err error
		if vrf, err = netlink.LinkByName(name + "-vrf"); err != nil {
			return 0, err
		}
		t.Cleanup(func() { _ = netlink.LinkDel(vrf) })
		if err := netlink.LinkSetUp(vrf); err != nil {
			return 0, err
		}
		vrfIdx = uint32(vrf.Attrs().Index)
	}
	portMAC, _ := net.ParseMAC("02:5e:00:00:01:00")
	portMAC[5] = byte(n)
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name + "-p", HardwareAddr: portMAC}}); err != nil {
		return 0, err
	}
	port, err := netlink.LinkByName(name + "-p")
	if err != nil {
		return 0, err
	}
	t.Cleanup(func() { _ = netlink.LinkDel(port) })
	if vrf != nil {
		if err := netlink.LinkSetMaster(port, vrf); err != nil {
			return 0, err
		}
	}
	if err := netlink.LinkSetUp(port); err != nil {
		return 0, err
	}
	gw6 := net.ParseIP("fd00:5e::2")
	gw6[5] = byte(n)
	gw4 := net.IPv4(10, 250, byte(n), 2).To4()
	for _, a := range []*net.IPNet{
		{IP: net.ParseIP("fd00:5e::1"), Mask: net.CIDRMask(64, 128)},
		{IP: net.IPv4(10, 250, byte(n), 1).To4(), Mask: net.CIDRMask(24, 32)},
	} {
		if a.IP.To4() == nil {
			a.IP[5] = byte(n)
		}
		if err := netlink.AddrAdd(port, &netlink.Addr{IPNet: a, Flags: unix.IFA_F_NODAD}); err != nil {
			return 0, err
		}
	}
	for _, nb := range []struct {
		ip     net.IP
		family int
	}{{gw6, netlink.FAMILY_V6}, {gw4, netlink.FAMILY_V4}} {
		if err := netlink.NeighAdd(&netlink.Neigh{
			LinkIndex: port.Attrs().Index, Family: nb.family, State: netlink.NUD_PERMANENT,
			IP: nb.ip, HardwareAddr: mac,
		}); err != nil {
			return 0, err
		}
	}
	for _, r := range []struct {
		dst string
		gw  net.IP
	}{
		{"2001:db8:5e::/48", gw6},    // vrfSelDst6
		{"198.51.100.0/24", gw4},     // vrfSelDst4
		{"fd00:5e:100::/40", gw6},    // vrfSelSID, End.T SIDs, uT shift targets
		{"fd00:aabb:ccdd::/48", gw6}, // End.T(REP) block (replDA)
	} {
		_, dst, _ := net.ParseCIDR(r.dst)
		route := &netlink.Route{LinkIndex: port.Attrs().Index, Dst: dst, Gw: r.gw}
		if table != 0 {
			route.Table = int(table)
		}
		if err := netlink.RouteAdd(route); err != nil {
			return 0, err
		}
	}
	return vrfIdx, nil
}

// enableIPForwarding turns IPv4 and IPv6 forwarding on for the test
// namespace and restores them when the test ends: bpf_fib_lookup answers
// FWD_DISABLED for either family while its forwarding is off.
func enableIPForwarding(t *testing.T) {
	t.Helper()
	enableIPv6Forwarding(t)
	for _, fwd := range []string{
		"/proc/sys/net/ipv4/conf/default/forwarding",
		"/proc/sys/net/ipv4/conf/all/forwarding",
	} {
		prev, err := os.ReadFile(fwd)
		if err != nil {
			t.Fatalf("read %s: %v", fwd, err)
		}
		if err := os.WriteFile(fwd, []byte("1"), 0); err != nil {
			t.Fatalf("enable IPv4 forwarding (%s): %v", fwd, err)
		}
		fwd := fwd
		t.Cleanup(func() { _ = os.WriteFile(fwd, prev, 0) })
	}
}

// table names the table a redirect's next-hop MAC belongs to.
func (e *vrfSelectEnv) table(ret uint32, out []byte) string {
	if ret != XDP_REDIRECT {
		return "no redirect"
	}
	switch {
	case bytes.Equal(out[0:6], e.macA):
		return "VRF A"
	case bytes.Equal(out[0:6], e.macB):
		return "VRF B"
	case bytes.Equal(out[0:6], e.macMain):
		return "main"
	}
	return "unknown next hop " + net.HardwareAddr(out[0:6]).String()
}

// decapPacket builds an encapsulated packet for sid carrying an IPv4 or
// IPv6 packet to the vrfSelectEnv destination, with an SRH (SL 0) or
// without one (reduced encapsulation).
func decapPacket(t *testing.T, sid net.IP, inner4, noSRH bool) (pkt []byte, innerSrc, innerDst net.IP) {
	t.Helper()
	outerSrc := net.ParseIP("fd00:1:1::1")
	innerSrc, innerDst, innerType := net.ParseIP("2001:db8:41::1"), net.ParseIP(vrfSelDst6), innerTypeIPv6
	if inner4 {
		innerSrc, innerDst, innerType = net.ParseIP("10.0.0.1"), net.ParseIP(vrfSelDst4), innerTypeIPv4
	}
	var err error
	if noSRH {
		pkt, err = buildEncapsulatedPacketNoSRH(outerSrc, sid, innerSrc, innerDst, innerType)
	} else {
		pkt, err = buildEncapsulatedPacket(outerSrc, sid, []net.IP{sid}, 0, innerSrc, innerDst, innerType)
	}
	if err != nil {
		t.Fatal(err)
	}
	return pkt, innerSrc, innerDst
}

// vrfSelSID returns the n-th SID of a vrfSelectEnv test.
func vrfSelSID(n int) net.IP {
	sid := net.ParseIP("fd00:5e:100::")
	sid[14], sid[15] = byte(n>>8), byte(n)
	return sid
}

// The decapsulating behaviours look the inner packet up in the VRF the SID
// is bound to, on the SRH path and on the reduced-encapsulation (no SRH)
// path. Each row is sent once bound to VRF A, once to VRF B and once to no
// VRF; the destination is routed in all three tables with a different next
// hop, so a lookup in the ingress context or in the other VRF redirects to
// the wrong MAC instead of ending in the same drop.
func TestXDPProgDecapVRFSelection(t *testing.T) {
	h := newXDPTestHelper(t)
	e := newVrfSelectEnv(t)

	rows := []struct {
		name   string
		action uint8
		inner4 bool
		noSRH  bool
	}{
		{"End.DT4", actionEndDT4, true, false},
		{"End.DT6", actionEndDT6, false, false},
		{"End.DT46 IPv4 inner", actionEndDT46, true, false},
		{"End.DT46 IPv6 inner", actionEndDT46, false, false},
		{"End.DT4 no SRH", actionEndDT4, true, true},
		{"End.DT6 no SRH", actionEndDT6, false, true},
		{"End.DT46 no SRH IPv4 inner", actionEndDT46, true, true},
		{"End.DT46 no SRH IPv6 inner", actionEndDT46, false, true},
	}
	binds := []struct {
		name string
		vrf  uint32
		want string
	}{
		{"VRF A", e.vrfA, "VRF A"},
		{"VRF B", e.vrfB, "VRF B"},
		{"no VRF", 0, "main"},
	}
	n := 0
	for _, r := range rows {
		for _, b := range binds {
			n++
			sid := vrfSelSID(n)
			t.Run(r.name+" bound to "+b.name, func(t *testing.T) {
				h.createSidFunctionWithVRF(sid.String()+"/128", r.action, b.vrf)
				pkt, innerSrc, innerDst := decapPacket(t, sid, r.inner4, r.noSRH)
				ret, out := h.run(pkt)
				if got := e.table(ret, out); got != b.want {
					t.Errorf("ret %d, next hop from %s, want XDP_REDIRECT to the %s next hop", ret, got, b.want)
				}
				verifyDecapsulated(t, out, innerSrc, innerDst, r.inner4)
			})
		}
	}
}

// A plugin SID that hands its packet to a built-in decapsulation (the
// built-in program in the plugin's slot) is looked up in the VRF of its
// grant, never in the VRF its raw aux bytes name (the other VRF here) nor
// in the ingress context.
func TestXDPProgPluginDecapVRFSelection(t *testing.T) {
	const pluginSlot = uint32(32) // an endpoint plugin slot (>= ENDPOINT_PLUGIN_BASE)
	h := newXDPTestHelper(t)
	e := newVrfSelectEnv(t)

	rows := []struct {
		name   string
		prog   *ebpf.Program
		inner4 bool
		noSRH  bool
	}{
		{"End.DT4", h.objs.TailcallEndpointEndDt4, true, false},
		{"End.DT6", h.objs.TailcallEndpointEndDt6, false, false},
		{"End.DT46 IPv4 inner", h.objs.TailcallEndpointEndDt46, true, false},
		{"End.DT46 IPv6 inner", h.objs.TailcallEndpointEndDt46, false, false},
		{"End.DX4", h.objs.TailcallEndpointEndDx4, true, false},
		{"End.DX6", h.objs.TailcallEndpointEndDx6, false, false},
		{"End.DT4 no SRH", h.objs.TailcallEndpointEndDt4, true, true},
		{"End.DT6 no SRH", h.objs.TailcallEndpointEndDt6, false, true},
		{"End.DT46 no SRH IPv4 inner", h.objs.TailcallEndpointEndDt46, true, true},
		{"End.DT46 no SRH IPv6 inner", h.objs.TailcallEndpointEndDt46, false, true},
		{"End.DX4 no SRH", h.objs.TailcallEndpointEndDx4, true, true},
		{"End.DX6 no SRH", h.objs.TailcallEndpointEndDx6, false, true},
	}
	grants := []struct {
		name       string
		grant, raw uint32
		want       string
	}{
		{"VRF A", e.vrfA, e.vrfB, "VRF A"},
		{"VRF B", e.vrfB, e.vrfA, "VRF B"},
	}
	t.Cleanup(func() { _ = h.objs.SidEndpointProgs.Delete(pluginSlot) })
	n := 0
	for _, r := range rows {
		for _, g := range grants {
			n++
			sid := vrfSelSID(n)
			t.Run(r.name+" granted "+g.name, func(t *testing.T) {
				if err := h.objs.SidEndpointProgs.Update(pluginSlot, r.prog, ebpf.UpdateAny); err != nil {
					t.Fatalf("load the built-in into the plugin slot: %v", err)
				}
				entry := &SidFunctionEntry{Action: uint8(pluginSlot)}
				if err := h.mapOps.CreateSidFunction(sid.String()+"/128", entry, NewSidAuxL3Vrf(g.raw), OwnerRPC); err != nil {
					t.Fatalf("create plugin SID: %v", err)
				}
				h.grantPluginEndtVrf(uint32(entry.AuxIndex), g.grant)
				pkt, innerSrc, innerDst := decapPacket(t, sid, r.inner4, r.noSRH)
				ret, out := h.run(pkt)
				if got := e.table(ret, out); got != g.want {
					t.Errorf("ret %d, next hop from %s, want XDP_REDIRECT to the %s next hop", ret, got, g.want)
				}
				verifyDecapsulated(t, out, innerSrc, innerDst, r.inner4)
			})
		}
	}
}

// The endpoint behaviours bound to a table (End.T, uT, End.T with
// REPLACE-CSID) forward in the VRF of their aux on every path that ends in
// a FIB lookup: the SRH step, the SL=0 USD and USP flavors, the uSID shift,
// the no-SRH USD decapsulation and each REPLACE-CSID advance. Each row is
// sent bound to VRF A, to VRF B and to no VRF (the ingress context, the
// main table here); the looked-up address has a different next hop in each
// table.
func TestXDPProgEndpointVRFSelection(t *testing.T) {
	h := newXDPTestHelper(t)
	e := newVrfSelectEnv(t)
	src := net.ParseIP("fd00:1:1::1")
	inner := func(v4 bool) (net.IP, net.IP, innerPacketType) {
		if v4 {
			return net.ParseIP("10.0.0.1"), net.ParseIP(vrfSelDst4), innerTypeIPv4
		}
		return net.ParseIP("2001:db8:41::1"), net.ParseIP(vrfSelDst6), innerTypeIPv6
	}
	sidFn := func(t *testing.T, prefix string, action, flavor uint8, aux *SidAuxEntry) {
		t.Helper()
		if err := h.mapOps.CreateSidFunction(prefix, &SidFunctionEntry{Action: action, Flavor: flavor}, aux, OwnerRPC); err != nil {
			t.Fatalf("create SID %s: %v", prefix, err)
		}
	}
	// endT installs End.T SID fd00:5e:1<n>::1 (inside a routed prefix, for
	// USP) and returns it.
	endT := func(t *testing.T, n int, flavor uint8, vrf uint32) net.IP {
		sid := net.ParseIP(fmt.Sprintf("fd00:5e:1%02x::1", n))
		sidFn(t, sid.String()+"/128", actionEndT, flavor, NewSidAuxL3Vrf(vrf))
		return sid
	}
	// uT installs the F3216 uT SID fd00:5e:2<n>::/48; a DA fd00:5e:2<n>:101::
	// shifts to fd00:5e:101::, inside a routed prefix.
	uT := func(t *testing.T, n int, flavor uint8, vrf uint32) net.IP {
		sid := net.ParseIP(fmt.Sprintf("fd00:5e:2%02x::", n))
		sidFn(t, sid.String()+"/48", actionEndUt, flavor, NewSidAuxUsidVrf(vrf, usidBlockLenBytes))
		return sid
	}
	// tRep installs End.T(REP) for C-SID 0x5e0000<n> (LNFL 32) and returns
	// the C-SID; replDA addresses it.
	tRep := func(t *testing.T, n int, flavor uint8, vrf uint32) uint32 {
		csid := uint32(0x5e000000 | n)
		sidFn(t, replDA(csid, 0).String()+"/80", actionEndReplace, flavor, NewSidAuxReplaceVrf(vrf, replBlockBytes, 4))
		return csid
	}
	encap := func(da net.IP, segs []net.IP, v4 bool) ([]byte, error) {
		s, d, typ := inner(v4)
		if segs == nil {
			return buildEncapsulatedPacketNoSRH(src, da, s, d, typ)
		}
		return buildEncapsulatedPacket(src, da, segs, 0, s, d, typ)
	}
	zero := mkContainer32(0, 0, 0, 0)

	rows := []struct {
		name string
		pkt  func(t *testing.T, n int, vrf uint32) ([]byte, error)
	}{
		{"End.T SRH step", func(t *testing.T, n int, vrf uint32) ([]byte, error) {
			sid := endT(t, n, 0, vrf)
			return buildSRv6Packet(src, sid, []net.IP{net.ParseIP(vrfSelDst6), sid}, 1)
		}},
		{"End.T USD IPv4 inner", func(t *testing.T, n int, vrf uint32) ([]byte, error) {
			sid := endT(t, n, flavorUSD, vrf)
			return encap(sid, []net.IP{sid}, true)
		}},
		{"End.T USD IPv6 inner", func(t *testing.T, n int, vrf uint32) ([]byte, error) {
			sid := endT(t, n, flavorUSD, vrf)
			return encap(sid, []net.IP{sid}, false)
		}},
		{"End.T USP", func(t *testing.T, n int, vrf uint32) ([]byte, error) {
			sid := endT(t, n, flavorUSP, vrf)
			return buildSRv6Packet(src, sid, []net.IP{sid}, 0)
		}},
		{"uT shift", func(t *testing.T, n int, vrf uint32) ([]byte, error) {
			da := append(net.IP{}, uT(t, n, 0, vrf)...)
			da[6], da[7] = 0x01, 0x01 // next uSID 0x0101: shifts to fd00:5e:101::
			return buildUsidIPv6Packet(src, da, 64)
		}},
		{"uT USD no SRH IPv4 inner", func(t *testing.T, n int, vrf uint32) ([]byte, error) {
			return encap(uT(t, n, flavorUSD, vrf), nil, true)
		}},
		{"uT USD no SRH IPv6 inner", func(t *testing.T, n int, vrf uint32) ([]byte, error) {
			return encap(uT(t, n, flavorUSD, vrf), nil, false)
		}},
		{"uT USD SRH", func(t *testing.T, n int, vrf uint32) ([]byte, error) {
			sid := uT(t, n, flavorUSD, vrf)
			return encap(sid, []net.IP{sid}, false)
		}},
		{"End.T(REP) advance within a container", func(t *testing.T, n int, vrf uint32) ([]byte, error) {
			csid := tRep(t, n, 0, vrf)
			segs := []net.IP{zero, mkContainer32(0x510500aa, 0x510500bb, 0x510500cc, 0x510500dd)}
			return buildSRv6Packet(src, replDA(csid, 2), segs, 1)
		}},
		{"End.T(REP) cross into the next container", func(t *testing.T, n int, vrf uint32) ([]byte, error) {
			csid := tRep(t, n, 0, vrf)
			segs := []net.IP{mkContainer32(0x52060011, 0x52060022, 0x52060033, 0x52060044), zero}
			return buildSRv6Packet(src, replDA(csid, 0), segs, 1)
		}},
		{"End.T(REP) early container end loads the next SID", func(t *testing.T, n int, vrf uint32) ([]byte, error) {
			csid := tRep(t, n, 0, vrf)
			segs := []net.IP{net.ParseIP(vrfSelDst6), mkContainer32(0x510500aa, 0, 0x510500cc, 0x510500dd)}
			return buildSRv6Packet(src, replDA(csid, 2), segs, 1)
		}},
		{"End.T(REP) USD IPv4 inner", func(t *testing.T, n int, vrf uint32) ([]byte, error) {
			return encap(replDA(tRep(t, n, flavorUSD, vrf), 0), []net.IP{zero}, true)
		}},
		{"End.T(REP) USD IPv6 inner", func(t *testing.T, n int, vrf uint32) ([]byte, error) {
			return encap(replDA(tRep(t, n, flavorUSD, vrf), 0), []net.IP{zero}, false)
		}},
		{"End.T(REP) USP", func(t *testing.T, n int, vrf uint32) ([]byte, error) {
			csid := tRep(t, n, flavorUSP, vrf)
			return buildSRv6Packet(src, replDA(csid, 0), []net.IP{zero}, 0)
		}},
		{"End.T(REP) USD no SRH IPv4 inner", func(t *testing.T, n int, vrf uint32) ([]byte, error) {
			return encap(replDA(tRep(t, n, flavorUSD, vrf), 0), nil, true)
		}},
		{"End.T(REP) USD no SRH IPv6 inner", func(t *testing.T, n int, vrf uint32) ([]byte, error) {
			return encap(replDA(tRep(t, n, flavorUSD, vrf), 0), nil, false)
		}},
	}
	binds := []struct {
		name string
		vrf  uint32
		want string
	}{
		{"VRF A", e.vrfA, "VRF A"},
		{"VRF B", e.vrfB, "VRF B"},
		{"no VRF", 0, "main"},
	}
	n := 0
	for _, r := range rows {
		for _, b := range binds {
			n++
			t.Run(r.name+" bound to "+b.name, func(t *testing.T) {
				pkt, err := r.pkt(t, n, b.vrf)
				if err != nil {
					t.Fatal(err)
				}
				ret, out := h.run(pkt)
				if got := e.table(ret, out); got != b.want {
					t.Errorf("ret %d, next hop from %s, want XDP_REDIRECT to the %s next hop", ret, got, b.want)
				}
			})
		}
	}
}

// The front door classifies a frame by {ingress ifindex, outermost VLAN} and
// the packet is matched in that VRF's headend table only. The same prefix
// is installed in three VRFs with a different segment each, so the outer
// destination tells which VRF a frame was classified into: untagged, with a
// mapped tag, with a mapped outer tag of a QinQ frame, and with a tag mapped
// explicitly to the global VRF.
func TestXDPProgIngressVrfSelectsHeadendVRF(t *testing.T) {
	h := newXDPTestHelper(t)
	const ifidx = 1 // the test-run ingress (lo)
	src, _ := ParseIPv6("fc00::1")
	seg := map[uint32]string{0: "fc00:a::1", 7: "fc00:b::1", 8: "fc00:c::1"}
	for vrf, s := range seg {
		segments, n, err := ParseSegments([]string{s})
		if err != nil {
			t.Fatal(err)
		}
		entry := &HeadendEntry{
			Mode:        uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS),
			NumSegments: n, SrcAddr: src, Segments: segments,
		}
		if err := h.mapOps.CreateHeadendV4In(vrf, "10.99.0.0/24", entry, OwnerRPC); err != nil {
			t.Fatal(err)
		}
		if err := h.mapOps.CreateHeadendV6In(vrf, "2001:db8:99::/64", entry, OwnerRPC); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.mapOps.SetIngressPolicy(true, false, 0); err != nil {
		t.Fatal(err)
	}
	if err := h.mapOps.SetIngressVrf(map[IngressACKey]uint32{
		{Ifindex: ifidx, VlanId: 0}:  7,
		{Ifindex: ifidx, VlanId: 10}: 8,
		{Ifindex: ifidx, VlanId: 20}: 0,
	}); err != nil {
		t.Fatal(err)
	}
	v4, err := buildSimpleIPv4Packet(net.ParseIP("10.98.0.1"), net.ParseIP("10.99.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	v6, err := buildSimpleIPv6Packet(net.ParseIP("2001:db8:97::1"), net.ParseIP("2001:db8:99::1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fam := range []struct {
		name string
		pkt  []byte
	}{{"IPv4", v4}, {"IPv6", v6}} {
		for _, c := range []struct {
			name string
			tags []uint16 // outermost first
			vrf  uint32
		}{
			{"untagged", nil, 7},
			{"tag 10", []uint16{10}, 8},
			{"QinQ, outer tag 10", []uint16{10, 99}, 8},
			{"tag 20, mapped to the global VRF", []uint16{20}, 0},
			{"QinQ, outer tag 20", []uint16{20, 10}, 0},
		} {
			t.Run(fam.name+" "+c.name, func(t *testing.T) {
				pkt := fam.pkt
				for i := len(c.tags) - 1; i >= 0; i-- {
					pkt = withVlanTag(pkt, c.tags[i])
				}
				// The encapsulation replaces the tags with the outer IPv6 header.
				_, out := h.runOnIfindex(pkt, ifidx)
				if binary.BigEndian.Uint16(out[12:14]) != 0x86dd || bytes.Equal(out[:len(pkt)], pkt) {
					t.Fatalf("not encapsulated: %x", out[:ethHeaderLen+8])
				}
				if got := outerDA(out, ethHeaderLen); !got.Equal(net.ParseIP(seg[c.vrf])) {
					t.Errorf("outer DA %v, want %s (the entry of vrf %d)", got, seg[c.vrf], c.vrf)
				}
			})
		}
	}
}

// The IPv6 F-TEID uplink (H.M.GTP6.D with BGP MUP sessions) is looked up
// under the packet's ingress VRF, like the IPv4 one: the same {endpoint,
// TEID} in two VRFs picks each VRF's direct SID, and a VRF with a gate but no
// session leaves the packet alone instead of borrowing another VRF's.
func TestXDPProgHMGtp6DTeidVRFScope(t *testing.T) {
	h := newXDPTestHelper(t)
	const ifidx = 1
	const n3Endpoint = "2001:db8:e::1"
	const teid = uint32(0x12345678)
	src, _ := ParseIPv6("fd00:200::1")
	direct := map[uint32]string{0: "fd00:d:a::1", 1: "fd00:d:b::2"}
	for _, vrf := range []uint32{0, 1, 2} {
		if err := h.mapOps.CreateHeadendV6In(vrf, "2001:db8:e::/64", &HeadendEntry{Mode: modeHMGTP6DTeid}, OwnerRPC); err != nil {
			t.Fatal(err)
		}
	}
	for vrf, sid := range direct {
		segs, n, _ := ParseSegments([]string{sid})
		entry := &HeadendEntry{Mode: modeHEncaps, NumSegments: n, SrcAddr: src, Segments: segs, ArgsOffset: MupArgsOffsetNone}
		if err := h.mapOps.CreateMupUplinkV6(vrf, n3Endpoint, teid, 32, entry); err != nil {
			t.Fatal(err)
		}
	}
	pkt, err := buildGTPUv6Packet(net.ParseIP("2001:db8:1::9"), net.ParseIP(n3Endpoint), teid, 0,
		net.ParseIP("172.16.0.1").To4(), net.ParseIP("172.16.0.2").To4())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.mapOps.SetIngressPolicy(true, false, 0); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		acs  map[IngressACKey]uint32
		want string // outer DA; "" = not encapsulated
	}{
		{"unmapped AC: global VRF", map[IngressACKey]uint32{}, direct[0]},
		{"AC in vrf 1", map[IngressACKey]uint32{{Ifindex: ifidx}: 1}, direct[1]},
		{"AC in vrf 2, which has no session", map[IngressACKey]uint32{{Ifindex: ifidx}: 2}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := h.mapOps.SetIngressVrf(c.acs); err != nil {
				t.Fatal(err)
			}
			ret, out := h.runOnIfindex(pkt, ifidx)
			if c.want == "" {
				if ret != XDP_PASS || !bytes.Equal(out[:len(pkt)], pkt) {
					t.Errorf("ret %d, want XDP_PASS with the frame untouched", ret)
				}
				return
			}
			if got := outerDA(out, ethHeaderLen); !got.Equal(net.ParseIP(c.want)) {
				t.Errorf("ret %d outer DA %v, want %s", ret, got, c.want)
			}
		})
	}
}

// TestXDPProgEncapOuterLookupFromTenantVRF, for the other headends that
// build an outer header for a packet of a tenant AC: H.Encaps.L2.Red (one and two
// segments), H.Encaps of a single-tagged and of a QinQ frame, H.M.GTP6.D,
// the End.AS (IPv4, IPv6, Ethernet), End.AD and End.AM return circuits, and
// an L2 and an End.AS circuit on a VLAN tag the front door has no AC for
// (the frame keeps the tenant VRF of the port's untagged AC). From the tenant VRF the outer
// header resolves through the main table; the same packets with the port's
// ACs in vrf 0 take the ingress-device lookup and stop at the VRF table, so
// a lookup in the wrong context drops instead of redirecting.
func TestXDPProgEncapOuterLookupFromTenantVRFOtherHeadends(t *testing.T) {
	h := newXDPTestHelper(t)
	e := newEncapVrfEnv(t)
	h.headendVRFs = []uint32{0, 1}
	src, _ := ParseIPv6("fc00:e01::1")
	sid1, _ := ParseIPv6("fc00:e00::1")
	segs1, n1, _ := ParseSegments([]string{"fc00:e00::1"})
	segs2, n2, _ := ParseSegments([]string{"fc00:e00::1", "fc00:e00::2"})
	const (
		vlanL2Red1 = 11
		vlanL2Red2 = 12
		vlanAS     = 13
		vlanAD     = 14
		vlanAM     = 15
		vlanNoAC   = 16 // an L2 circuit, but no front-door AC for the tag
		vlanAS6    = 17
		vlanASEth  = 18
		vlanL3     = 19
		vlanASNoAC = 20 // an End.AS circuit, but no front-door AC for the tag
	)
	red := vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2_RED
	h.createHeadendL2EntryWithMode(e.tenant, vlanL2Red1, src, segs1, n1, 0, red)
	h.createHeadendL2EntryWithMode(e.tenant, vlanL2Red2, src, segs2, n2, 0, red)
	h.createHeadendL2Entry(e.tenant, vlanNoAC, src, segs1, n1, 0)
	h.createHeadendEntry("10.99.0.0/24", src, [16]byte{}, segs1, n1, true)

	for _, vrf := range h.headendVRFs {
		if err := h.mapOps.CreateHeadendV6In(vrf, "2001:db8:e::/64", &HeadendEntry{Mode: modeHMGTP6DTeid}, OwnerRPC); err != nil {
			t.Fatal(err)
		}
		if err := h.mapOps.CreateMupUplinkV6(vrf, "2001:db8:e::1", 0x12345678, 32, &HeadendEntry{
			Mode: modeHEncaps, NumSegments: n1, SrcAddr: src, Segments: segs1, ArgsOffset: MupArgsOffsetNone,
		}); err != nil {
			t.Fatal(err)
		}
	}

	for vlan, mask := range map[uint16]uint8{
		vlanAS: SvcInnerIPv4, vlanAS6: SvcInnerIPv6, vlanASEth: SvcInnerEthernet, vlanASNoAC: SvcInnerIPv4,
	} {
		if _, err := h.mapOps.CreateServiceIngress(e.tenant, vlan, &ServiceIngressEntry{
			Behavior: SvcRetAS, InnerTypeMask: mask,
			Encap: HeadendEntry{Mode: modeHEncaps, NumSegments: n1, SrcAddr: src, Segments: segs1},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.mapOps.CreateServiceIngress(e.tenant, vlanAD, &ServiceIngressEntry{
		Behavior: SvcRetAD, InnerTypeMask: SvcInnerIPv4,
	}); err != nil {
		t.Fatal(err)
	}
	// The AD cache row the forward direction would have written: outer IPv6
	// (40) + SRH with one segment (24), DA = that segment.
	ad := AdCacheVal{HdrLen: 64, Valid: 1}
	ad.Hdr[0] = 0x60
	ad.Hdr[6], ad.Hdr[7] = 43, 64
	copy(ad.Hdr[8:24], src[:])
	copy(ad.Hdr[24:40], sid1[:])
	copy(ad.Hdr[40:48], []byte{4, 2, 4, 0, 0, 0, 0, 0}) // IPIP, 2 x 8 bytes, type 4, SL 0
	copy(ad.Hdr[48:64], sid1[:])
	if err := h.objs.AdCacheMap.Put(&ServiceIngressKey{Ifindex: e.tenant, VlanId: vlanAD}, &ad); err != nil {
		t.Fatal(err)
	}
	if _, err := h.mapOps.CreateServiceIngress(e.tenant, vlanAM, &ServiceIngressEntry{
		Behavior: SvcRetAM, InnerTypeMask: SvcInnerIPv6,
	}); err != nil {
		t.Fatal(err)
	}

	if err := h.mapOps.SetIngressPolicy(true, false, 0); err != nil {
		t.Fatal(err)
	}
	setTenantVrf := func(vrfID uint32) {
		t.Helper()
		acs := map[IngressACKey]uint32{}
		for _, vlan := range []uint16{0, vlanL2Red1, vlanL2Red2, vlanAS, vlanAD, vlanAM, vlanAS6, vlanASEth, vlanL3} {
			acs[IngressACKey{Ifindex: e.tenant, VlanId: vlan}] = vrfID
		}
		if err := h.mapOps.SetIngressVrf(acs); err != nil {
			t.Fatalf("SetIngressVrf: %v", err)
		}
	}

	mustPkt := func(pkt []byte, err error) []byte {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return pkt
	}
	v4 := func(vlan uint16) []byte {
		return mustPkt(buildVlanTaggedIPv4Packet(vlan, net.ParseIP("10.98.0.1"), net.ParseIP("10.97.0.1")))
	}
	v6 := func(vlan uint16) []byte {
		return mustPkt(buildVlanTaggedIPv6Packet(vlan, net.ParseIP("2001:db8:98::1"), net.ParseIP("2001:db8:97::1")))
	}
	// Headend packets to 10.99.0.0/24, once single-tagged and once QinQ:
	// the L3 headend bodies take the outer VRF for each L3 offset.
	l3 := mustPkt(buildSimpleIPv4Packet(net.ParseIP("10.98.0.1"), net.ParseIP("10.99.0.1")))
	// End.AM return: the service hands back the masqueraded packet (DA =
	// Segment List[0]); de-masquerading restores Segment List[SL].
	am := withVlanTag(mustPkt(buildSRv6Packet(net.ParseIP("fc00::1"), net.ParseIP("fc00:e00::3"),
		[]net.IP{net.ParseIP("fc00:e00::3"), net.ParseIP("fc00:e00::4"), net.ParseIP("fc00:a15a::1")}, 1)), vlanAM)
	gtp6 := mustPkt(buildGTPUv6Packet(net.ParseIP("2001:db8:1::9"), net.ParseIP("2001:db8:e::1"), 0x12345678, 0,
		net.ParseIP("172.16.0.1").To4(), net.ParseIP("172.16.0.2").To4()))
	cases := []struct {
		name string
		pkt  []byte
	}{
		{"H.Encaps.L2.Red (one segment)", v4(vlanL2Red1)},
		{"H.Encaps.L2.Red (two segments)", v4(vlanL2Red2)},
		{"H.M.GTP6.D", gtp6},
		{"End.AS return (IPv4)", v4(vlanAS)},
		{"End.AS return (IPv6)", v6(vlanAS6)},
		{"End.AS return (Ethernet circuit)", v4(vlanASEth)},
		{"End.AS return on a tag with no AC", v4(vlanASNoAC)},
		{"H.Encaps (single-tagged)", withVlanTag(l3, vlanL3)},
		{"H.Encaps (QinQ)", withVlanTag(withVlanTag(l3, 5), vlanL3)},
		{"End.AD return", v4(vlanAD)},
		{"End.AM return", am},
		{"H.Encaps.L2 on a tag with no AC", v4(vlanNoAC)},
	}

	// No subtests: they would run on another thread, outside the namespace.
	setTenantVrf(1)
	for _, c := range cases {
		ret, out := h.runOnIfindex(c.pkt, e.tenant)
		if !e.redirectedToGateway(ret, out) {
			t.Errorf("%s from the tenant AC: ret %d dst MAC %x, want XDP_REDIRECT to the underlay gateway %s",
				c.name, ret, out[0:6], e.gwMAC)
		}
	}
	setTenantVrf(0)
	for _, c := range cases {
		if ret, _ := h.runOnIfindex(c.pkt, e.tenant); ret == XDP_REDIRECT {
			t.Errorf("%s from the enslaved port in vrf 0: XDP_REDIRECT, want the ingress-device lookup to stop at the VRF table", c.name)
		}
	}
}

// A plugin SID whose program hands the packet to the built-in End.T has no
// VRF grant for it: the built-in gets no aux, so the plugin's raw aux bytes
// (an l3vrf view naming VRF A or VRF B here) never choose the table the
// packet is forwarded in.
func TestXDPProgPluginEndTIgnoresRawAuxVRF(t *testing.T) {
	const pluginSlot = uint32(32)
	h := newXDPTestHelper(t)
	e := newVrfSelectEnv(t)
	if err := h.objs.SidEndpointProgs.Update(pluginSlot, h.objs.TailcallEndpointEndT, ebpf.UpdateAny); err != nil {
		t.Fatalf("load End.T into the plugin slot: %v", err)
	}
	t.Cleanup(func() { _ = h.objs.SidEndpointProgs.Delete(pluginSlot) })
	for i, raw := range []struct {
		name string
		vrf  uint32
	}{{"VRF A", e.vrfA}, {"VRF B", e.vrfB}} {
		t.Run("raw aux names "+raw.name, func(t *testing.T) {
			sid := net.ParseIP(fmt.Sprintf("fd00:5e:1%02x::1", 0xf0+i))
			if err := h.mapOps.CreateSidFunction(sid.String()+"/128", &SidFunctionEntry{Action: uint8(pluginSlot)},
				NewSidAuxL3Vrf(raw.vrf), OwnerRPC); err != nil {
				t.Fatal(err)
			}
			pkt, err := buildSRv6Packet(net.ParseIP("fd00:1:1::1"), sid, []net.IP{net.ParseIP(vrfSelDst6), sid}, 1)
			if err != nil {
				t.Fatal(err)
			}
			ret, out := h.run(pkt)
			if got := e.table(ret, out); got == "VRF A" || got == "VRF B" {
				t.Errorf("ret %d, forwarded in %s: the plugin's raw aux chose the table", ret, got)
			}
		})
	}
}
