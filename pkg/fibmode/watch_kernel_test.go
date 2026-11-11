package fibmode

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netns"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// inNewNetns moves the test's thread into a new network namespace with lo
// up, or skips without the privilege.
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
	ip(t, "link", "set", "lo", "up")
}

func ip(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
	}
}

// userNetlinkSockets counts the namespace's userspace netlink sockets by
// protocol.
func userNetlinkSockets(t *testing.T) map[int]int {
	t.Helper()
	f, err := os.Open("/proc/thread-self/net/netlink")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	out := map[int]int{}
	sc := bufio.NewScanner(f)
	sc.Scan()
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
	return out
}

// waitFor polls the maps every 20µs until the mode is (v4, v6) and returns
// how long that took.
func waitFor(t *testing.T, m *fakeMaps, v4, v6 bool, what string) time.Duration {
	t.Helper()
	start := time.Now()
	for time.Since(start) < 5*time.Second {
		if a, b := m.mode(); a == v4 && b == v6 {
			return time.Since(start)
		}
		time.Sleep(20 * time.Microsecond)
	}
	a, b := m.mode()
	t.Fatalf("%s: mode IPv4=%v IPv6=%v after 5s, want %v %v", what, a, b, v4, v6)
	return 0
}

// The watcher in a real namespace: a fresh namespace is eligible; a policy
// rule takes its family to the full lookup as soon as the rule is in, and
// removing it brings the direct lookup back; a rule with a selector, a VRF
// whose table is open, and a VRF table without the l3mdev rule keep the
// full lookup. The time from `ip rule add` returning to the map write is
// the switching window the docs state.
func TestWatcherKernel(t *testing.T) {
	inNewNetns(t)
	m := &fakeMaps{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	before := userNetlinkSockets(t)
	w := New(m, zap.NewNop())
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, m, true, true, "fresh namespace")
	for proto, n := range userNetlinkSockets(t) {
		if proto != unix.NETLINK_ROUTE && n > before[proto] {
			t.Errorf("the watcher opened %d socket(s) of netlink protocol %d", n-before[proto], proto)
		}
	}

	var windows []time.Duration
	for i := 0; i < 20; i++ {
		ip(t, "rule", "add", "pref", "100", "from", "10.0.0.0/8", "lookup", "200")
		windows = append(windows, waitFor(t, m, false, true, "IPv4 policy rule"))
		ip(t, "rule", "del", "pref", "100")
		waitFor(t, m, true, true, "IPv4 policy rule removed")
		ip(t, "-6", "rule", "add", "pref", "100", "from", "2001:db8::/32", "lookup", "200")
		windows = append(windows, waitFor(t, m, true, false, "IPv6 policy rule"))
		ip(t, "-6", "rule", "del", "pref", "100")
		waitFor(t, m, true, true, "IPv6 policy rule removed")
	}
	slices.Sort(windows)
	t.Logf("switching window over %d rule adds: median %v, max %v", len(windows), windows[len(windows)/2], windows[len(windows)-1])

	ip(t, "rule", "add", "pref", "100", "ipproto", "udp", "lookup", "main")
	waitFor(t, m, false, true, "rule with an ipproto selector")
	ip(t, "rule", "del", "pref", "100")
	waitFor(t, m, true, true, "selector rule removed")

	if exec.Command("ip", "link", "add", "fmvrf", "type", "vrf", "table", "100").Run() != nil {
		t.Log("kernel lacks the vrf module; VRF part skipped")
		return
	}
	waitFor(t, m, false, false, "VRF with an open table")
	ip(t, "route", "add", "unreachable", "default", "table", "100", "metric", "4278198272")
	ip(t, "-6", "route", "add", "unreachable", "default", "table", "100", "metric", "4278198272")
	waitFor(t, m, true, true, "VRF table closed")
	ip(t, "route", "add", "throw", "10.9.0.0/24", "table", "100")
	waitFor(t, m, false, true, "IPv4 throw route in the VRF table")
	ip(t, "route", "del", "throw", "10.9.0.0/24", "table", "100")
	waitFor(t, m, true, true, "throw route removed")
	ip(t, "-6", "rule", "del", "pref", "1000")
	waitFor(t, m, true, false, "IPv6 l3mdev rule removed while the VRF exists")
	ip(t, "-6", "rule", "add", "pref", "1000", "l3mdev")
	waitFor(t, m, true, true, "l3mdev rule back")
	ip(t, "link", "del", "fmvrf")
	waitFor(t, m, true, true, "VRF gone, l3mdev rules left")
	ip(t, "route", "add", "local", "10.201.0.0/16", "dev", "lo", "table", "local")
	waitFor(t, m, false, true, "local route to a prefix")

	cancel()
	waitFor(t, m, false, false, "watcher stopped")
}
