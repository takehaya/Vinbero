package cni

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// userNetlinkSockets counts the userspace netlink sockets of the network
// namespace at path by protocol (/proc/thread-self/net/netlink: Eth is the
// protocol, Pid the port id, 0 for the kernel's own). The calling thread is
// moved there for the read and back.
func userNetlinkSockets(t *testing.T, path string) map[int]int {
	t.Helper()
	cur, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cur.Close() }()
	ns, err := netns.GetFromPath(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ns.Close() }()
	if err := netns.Set(ns); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := netns.Set(cur); err != nil {
			t.Fatal(err)
		}
	}()
	f, err := os.Open("/proc/thread-self/net/netlink")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	out := map[int]int{}
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		proto, err1 := strconv.Atoi(fields[1])
		pid, err2 := strconv.ParseUint(fields[2], 10, 32)
		if err1 != nil || err2 != nil || pid == 0 {
			continue
		}
		out[proto]++
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// The handle the plugin opens in a pod namespace has a route socket only. A
// handle opened with no family list also opens an XFRM and a netfilter
// socket in the pod namespace on every ADD and DEL, and opening the XFRM one
// makes the kernel load xfrm_user when it is a module. Counting sockets holds
// on a kernel with those built in.
func TestOpenNetnsOpensOnlyRouteSockets(t *testing.T) {
	podNS := withHostAndPodNetns(t)
	before := userNetlinkSockets(t, podNS)
	_, closeNS, err := openNetns(podNS)
	if err != nil {
		t.Fatal(err)
	}
	defer closeNS()
	after := userNetlinkSockets(t, podNS)
	if after[unix.NETLINK_ROUTE] <= before[unix.NETLINK_ROUTE] {
		t.Fatalf("no route socket opened (before %v, after %v): the count does not see the handle", before, after)
	}
	for proto, n := range after {
		if proto != unix.NETLINK_ROUTE && n > before[proto] {
			t.Errorf("openNetns opened %d socket(s) of netlink protocol %d (before %v, after %v)", n-before[proto], proto, before, after)
		}
	}
}
