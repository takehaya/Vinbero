package cni

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// withHostAndPodNetns runs the test with the calling thread in a fresh
// "host" namespace and returns the path of a named "pod" namespace. Needs
// root.
func withHostAndPodNetns(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root (netns, veth and VRF devices)")
	}
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	podName := fmt.Sprintf("vbcni-test-%d", os.Getpid())
	pod, err := netns.NewNamed(podName) // switches the thread into it
	if err != nil {
		_ = orig.Close()
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	host, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = netns.Set(orig)
		_ = netns.DeleteNamed(podName)
		_ = pod.Close()
		_ = host.Close()
		_ = orig.Close()
		runtime.UnlockOSThread()
	})
	return "/var/run/netns/" + podName
}

func TestKernelNetopsLifecycle(t *testing.T) {
	podNS := withHostAndPodNetns(t)
	if err := netlink.LinkAdd(&netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "tenant-a"}, Table: 100}); err != nil {
		t.Skipf("no VRF support: %v", err)
	}
	k := kernelNetops{}
	host, tmp := vethNames("c1", "net1")
	veth, err := k.CreateVeth(podNS, "net1", host, tmp, 1436)
	if err != nil {
		t.Fatalf("CreateVeth: %v", err)
	}
	if _, err := k.CreateVeth(podNS, "net1", host, tmp, 1436); err == nil {
		t.Error("CreateVeth over an existing pod interface succeeded")
	}
	podIP := netip.MustParseAddr("10.100.1.5")
	pc := PodConfig{
		Netns: podNS, IfName: "net1", Address: podIP,
		Routes: []netip.Prefix{netip.MustParsePrefix("10.100.0.0/16")}, GwMAC: veth.HostMAC,
	}
	if err := k.ConfigurePod(pc); err != nil {
		t.Fatalf("ConfigurePod: %v", err)
	}
	if err := k.ConfigurePod(pc); err != nil {
		t.Fatalf("ConfigurePod again: %v", err)
	}
	hc := HostConfig{Veth: host, VRF: "tenant-a", TableID: 100, PodIP: podIP, PodMAC: veth.PodMAC}
	if err := k.CheckHost(hc); err == nil {
		t.Error("CheckHost before setup succeeded")
	}
	if err := k.EnslaveHost(host, "tenant-a"); err != nil {
		t.Fatalf("EnslaveHost: %v", err)
	}
	for range 2 {
		if err := k.AddHostRoute(hc); err != nil {
			t.Fatalf("AddHostRoute: %v", err)
		}
	}
	if err := k.CheckPod(pc); err != nil {
		t.Errorf("CheckPod: %v", err)
	}
	if err := k.CheckHost(hc); err != nil {
		t.Errorf("CheckHost: %v", err)
	}

	// Pod side: /32, a permanent gateway neighbour, the subnet via it.
	h, closeNS, err := openNetns(podNS)
	if err != nil {
		t.Fatal(err)
	}
	defer closeNS()
	pl, err := h.LinkByName("net1")
	if err != nil {
		t.Fatal(err)
	}
	if pl.Attrs().MTU != 1436 {
		t.Errorf("pod MTU = %d", pl.Attrs().MTU)
	}
	addrs, _ := h.AddrList(pl, unix.AF_INET)
	if len(addrs) != 1 || addrs[0].IPNet.String() != "10.100.1.5/32" {
		t.Errorf("pod addresses = %v", addrs)
	}
	neighs, _ := h.NeighList(pl.Attrs().Index, unix.AF_INET)
	if len(neighs) != 1 || neighs[0].State != netlink.NUD_PERMANENT || neighs[0].HardwareAddr.String() != veth.HostMAC.String() {
		t.Errorf("pod neighbours = %v", neighs)
	}
	routes, _ := h.RouteList(pl, unix.AF_INET)
	var subnet bool
	for _, r := range routes {
		if r.Dst != nil && r.Dst.String() == "10.100.0.0/16" && r.Gw.Equal(net.IP(podGateway.AsSlice())) {
			subnet = true
		}
	}
	if !subnet {
		t.Errorf("pod routes = %v", routes)
	}

	// Host side: the static /32 in the VRF table and a permanent neighbour.
	hl, _ := netlink.LinkByName(host)
	rs, _ := netlink.RouteListFiltered(unix.AF_INET, &netlink.Route{Table: 100}, netlink.RT_FILTER_TABLE)
	if len(rs) != 1 || rs[0].Protocol != unix.RTPROT_STATIC || rs[0].LinkIndex != hl.Attrs().Index {
		t.Errorf("table 100 = %v", rs)
	}
	hn, _ := netlink.NeighList(hl.Attrs().Index, unix.AF_INET)
	if len(hn) != 1 || hn[0].State != netlink.NUD_PERMANENT {
		t.Errorf("host neighbours = %v", hn)
	}

	for range 2 {
		if err := k.DelHostRoute(hc); err != nil {
			t.Fatalf("DelHostRoute: %v", err)
		}
	}
	if err := k.CheckHost(hc); err == nil {
		t.Error("CheckHost after DelHostRoute succeeded")
	}
	for range 2 {
		if err := k.DeleteVeth(podNS, "net1", host); err != nil {
			t.Fatalf("DeleteVeth: %v", err)
		}
	}
	if _, err := netlink.LinkByName(host); err == nil {
		t.Error("host veth survived DeleteVeth")
	}
	if err := k.DelHostRoute(hc); err != nil {
		t.Errorf("DelHostRoute without the veth: %v", err)
	}
	if err := k.DeleteVeth("/var/run/netns/vbcni-test-missing", "net1", host); err != nil {
		t.Errorf("DeleteVeth with a missing netns: %v", err)
	}
}
