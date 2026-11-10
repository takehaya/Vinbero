package bpf

import (
	"bytes"
	"errors"
	"net"
	"testing"

	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// encapVrfEnv is a namespace where an encapsulation's outer header can only
// resolve through the main table: the route to the SIDs (fc00:e00::/32) is
// in main, and the VRF table of the port the tenant packets arrive on ends
// in an unreachable default, as Vinbero leaves the tables it manages.
type encapVrfEnv struct {
	tenant uint32 // enslaved to the VRF device
	global uint32 // in no VRF
	gwMAC  net.HardwareAddr
}

func newEncapVrfEnv(t *testing.T) *encapVrfEnv {
	t.Helper()
	inNewNetns(t)
	up := linkUp(t, "evrf-up", "fd00:e::1/64")
	neighAdd(t, up, "fd00:e::2")
	_, sids, _ := net.ParseCIDR("fc00:e00::/32")
	if err := netlink.RouteAdd(&netlink.Route{Dst: sids, Gw: net.ParseIP("fd00:e::2"), LinkIndex: up}); err != nil {
		t.Fatalf("underlay route: %v", err)
	}

	if err := netlink.LinkAdd(&netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "evrf-vrf"}, Table: 100}); err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) {
			t.Skipf("kernel lacks the vrf module: %v", err)
		}
		t.Fatalf("add VRF: %v", err)
	}
	vrf, err := netlink.LinkByName("evrf-vrf")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(vrf); err != nil {
		t.Fatal(err)
	}
	for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
		_, dst, _ := net.ParseCIDR(cidr)
		if err := netlink.RouteAdd(&netlink.Route{
			Table: 100, Type: unix.RTN_UNREACHABLE, Dst: dst, Priority: 4278198272,
		}); err != nil {
			t.Fatalf("unreachable default %s: %v", cidr, err)
		}
	}
	tenant := linkUp(t, "evrf-ten", "fd00:f::1/64")
	ten, _ := netlink.LinkByName("evrf-ten")
	if err := netlink.LinkSetMaster(ten, vrf); err != nil {
		t.Fatalf("enslave: %v", err)
	}
	if err := netlink.LinkSetUp(ten); err != nil {
		t.Fatal(err)
	}
	mac, _ := net.ParseMAC("02:00:00:00:ec:01") // neighAdd's MAC
	return &encapVrfEnv{
		tenant: uint32(tenant),
		global: uint32(linkUp(t, "evrf-glob", "fd00:9::1/64")),
		gwMAC:  mac,
	}
}

// redirectedToGateway reports whether the encapsulated frame was sent to the
// underlay gateway, the next hop only the main table knows.
func (e *encapVrfEnv) redirectedToGateway(ret uint32, out []byte) bool {
	return ret == XDP_REDIRECT && bytes.Equal(out[0:6], e.gwMAC)
}

// A packet from a tenant AC on a port enslaved to a VRF device is
// encapsulated with its outer header resolved in the main table, for every
// headend that builds one: the lookup through the port would stop at the VRF
// table's unreachable default. A packet from a port in no VRF (vrf 0) keeps
// the ingress-device lookup, which reaches main through the ip rules. An
// enslaved port the front door leaves in vrf 0 keeps it too, and its outer
// header stops at the VRF table: such a port has to be an AC of its VRF.
func TestXDPProgEncapOuterLookupFromTenantVRF(t *testing.T) {
	h := newXDPTestHelper(t)
	e := newEncapVrfEnv(t)

	srcAddr, _ := ParseIPv6("fc00:e01::1")
	segments, numSegments, _ := ParseSegments([]string{"fc00:e00::1"})
	h.createHeadendEntry("10.99.0.0/24", srcAddr, [16]byte{}, segments, numSegments, true)
	h.createHeadendEntry("2001:db8:99::/64", srcAddr, [16]byte{}, segments, numSegments, false)
	h.createHeadendEntryWithMode("2001:db8:98::/64", srcAddr, [16]byte{}, segments, numSegments, false,
		vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_INSERT)
	const l2Vlan = 10
	h.createHeadendL2Entry(e.tenant, l2Vlan, srcAddr, segments, numSegments, 0)
	h.createHeadendEntryGTP("192.0.2.0/24", srcAddr, segments, numSegments, 7)

	if err := h.mapOps.SetIngressPolicy(true, false, 0); err != nil {
		t.Fatalf("SetIngressPolicy: %v", err)
	}
	setTenantVrf := func(vrfID uint32) {
		t.Helper()
		if err := h.mapOps.SetIngressVrf(map[IngressACKey]uint32{
			{Ifindex: e.tenant, VlanId: 0}:      vrfID,
			{Ifindex: e.tenant, VlanId: l2Vlan}: vrfID,
		}); err != nil {
			t.Fatalf("SetIngressVrf: %v", err)
		}
	}

	v4, err := buildSimpleIPv4Packet(net.ParseIP("10.98.0.1"), net.ParseIP("10.99.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	v6, err := buildSimpleIPv6Packet(net.ParseIP("2001:db8:97::1"), net.ParseIP("2001:db8:99::1"))
	if err != nil {
		t.Fatal(err)
	}
	insert, err := buildSimpleIPv6Packet(net.ParseIP("2001:db8:97::1"), net.ParseIP("2001:db8:98::1"))
	if err != nil {
		t.Fatal(err)
	}
	gtp, err := buildGTPUv4Packet(net.ParseIP("10.0.0.1").To4(), net.ParseIP("192.0.2.100").To4(),
		0x12345678, 9, net.ParseIP("172.16.0.1").To4(), net.ParseIP("172.16.0.2").To4())
	if err != nil {
		t.Fatal(err)
	}
	l2, err := buildVlanTaggedIPv4Packet(l2Vlan, net.ParseIP("10.98.0.1"), net.ParseIP("10.97.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		pkt  []byte
	}{
		{"H.Encaps (IPv4)", v4},
		{"H.Encaps (IPv6)", v6},
		{"H.Insert", insert},
		{"H.M.GTP4.D", gtp},
		{"H.Encaps.L2", l2},
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

	for _, c := range cases[:4] { // the L2 circuit lives on the tenant port
		ret, out := h.runOnIfindex(c.pkt, e.global)
		if !e.redirectedToGateway(ret, out) {
			t.Errorf("%s from a port in no VRF: ret %d dst MAC %x, want XDP_REDIRECT to the underlay gateway %s",
				c.name, ret, out[0:6], e.gwMAC)
		}
	}

	setTenantVrf(0)
	if ret, _ := h.runOnIfindex(v4, e.tenant); ret != XDP_DROP {
		t.Errorf("H.Encaps from the enslaved port in vrf 0: ret %d, want XDP_DROP at the VRF table", ret)
	}
}
