package vinbero

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// userNetlinkSockets counts the userspace netlink sockets of the calling
// thread's network namespace by protocol (/proc/thread-self/net/netlink:
// Eth is the protocol, Pid the port id, 0 for the kernel's own).
func userNetlinkSockets(t *testing.T) map[int]int {
	t.Helper()
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

// The link watcher's handle opens a route socket only. A handle opened with
// no family list also opens an XFRM and a netfilter socket, and opening the
// XFRM one makes the kernel load xfrm_user (and xfrm_algo) when it is a
// module. The test counts sockets rather than modules so that it holds on a
// kernel with those built in.
func TestWatchDevicesOpensOnlyRouteSockets_Kernel(t *testing.T) {
	withKernelNetns(t)
	v := newKernelVinbero(t, filepath.Join(t.TempDir(), "state.json"))
	defer func() { _ = v.Close() }()
	before := userNetlinkSockets(t)
	if err := v.WatchDevices(); err != nil {
		t.Fatalf("WatchDevices: %v", err)
	}
	after := userNetlinkSockets(t)
	if after[unix.NETLINK_ROUTE] <= before[unix.NETLINK_ROUTE] {
		t.Fatalf("no route socket opened (before %v, after %v): the count does not see the handle", before, after)
	}
	for proto, n := range after {
		if proto != unix.NETLINK_ROUTE && n > before[proto] {
			t.Errorf("WatchDevices opened %d socket(s) of netlink protocol %d (before %v, after %v)", n-before[proto], proto, before, after)
		}
	}
}
