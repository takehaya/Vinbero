package bpf

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Programs run by BPF_PROG_TEST_RUN do their bpf_fib_lookup in the network
// namespace of the test process, so a test that reaches the FIB would see the
// routes and the forwarding sysctls of whatever machine it runs on: a host
// with an IPv6 default route, a resolved gateway and forwarding on turns an
// XDP_PASS into an XDP_REDIRECT. To keep every test independent of the host,
// TestMain runs the whole test binary in a network namespace of its own that
// starts empty: loopback up, no routes, IPv4 and IPv6 forwarding off. A test
// that needs more builds it there (veth pairs, addresses, forwarding on) and
// restores it, as it always had to.
//
// The binary re-executes itself in the new namespace (the namespace is
// entered by unshare(2) before exec, so every thread of the child is in it)
// and returns the child's exit status. The child gets the same arguments, so
// -test.run, -test.v, -test.count and the coverage flags reach it unchanged.
const isolatedNetnsEnv = "VINBERO_BPF_TEST_ISOLATED_NETNS"

// isolatedSysctls are set, then read back, in the new namespace. "default"
// is what devices created later inherit and "all" what existing ones follow,
// so both are written, "all" last.
var isolatedSysctls = []string{
	"/proc/sys/net/ipv4/conf/default/forwarding",
	"/proc/sys/net/ipv4/conf/all/forwarding",
	"/proc/sys/net/ipv6/conf/default/forwarding",
	"/proc/sys/net/ipv6/conf/all/forwarding",
}

func TestMain(m *testing.M) {
	if os.Getenv(isolatedNetnsEnv) == "" {
		if code, ok := runInIsolatedNetns(); ok {
			os.Exit(code)
		}
		// Not isolated: the caller lacks CAP_SYS_ADMIN, so no test that
		// needs the kernel's BPF test-run can run either.
		fmt.Fprintln(os.Stderr, "pkg/bpf tests: cannot create a network namespace (not root); running in the caller's namespace")
		os.Exit(m.Run())
	}
	if err := prepareIsolatedNetns(); err != nil {
		fmt.Fprintln(os.Stderr, "pkg/bpf tests: prepare the isolated network namespace:", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// runInIsolatedNetns runs this binary again in a new network namespace and
// returns its exit status. ok is false only when the caller is not root and
// the kernel refused the namespace (EPERM); every other failure, and any
// failure as root, ends the process, because carrying on in the host's
// namespace is exactly what this exists to prevent.
func runInIsolatedNetns() (code int, ok bool) {
	exe, err := os.Executable()
	if err != nil {
		fatalIsolation(err)
	}
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Args[0] = os.Args[0]
	cmd.Env = append(os.Environ(), isolatedNetnsEnv+"=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Unshareflags: syscall.CLONE_NEWNET,
		// The child must not outlive a parent that was killed. Pdeathsig
		// follows the thread that forked it, so keep this goroutine on it.
		Pdeathsig: syscall.SIGKILL,
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)
	defer signal.Stop(sigs)

	if err := cmd.Start(); err != nil {
		if os.Geteuid() != 0 && errors.Is(err, syscall.EPERM) {
			return 0, false
		}
		fatalIsolation(err)
	}
	go func() {
		for s := range sigs {
			_ = cmd.Process.Signal(s)
		}
	}()
	err = cmd.Wait()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, true
	case errors.As(err, &ee):
		if ws, isWait := ee.Sys().(syscall.WaitStatus); isWait && ws.Signaled() {
			// Same convention as a shell: 128 + signal.
			return 128 + int(ws.Signal()), true
		}
		return ee.ExitCode(), true
	default:
		fatalIsolation(err)
		return 1, true
	}
}

func fatalIsolation(err error) {
	fmt.Fprintln(os.Stderr, "pkg/bpf tests: cannot run the tests in an isolated network namespace:", err)
	os.Exit(1)
}

// prepareIsolatedNetns brings loopback up and pins the forwarding sysctls,
// then checks that the namespace has no routes of its own.
func prepareIsolatedNetns() error {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("find lo: %w", err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		return fmt.Errorf("set lo up: %w", err)
	}
	for _, p := range isolatedSysctls {
		if err := os.WriteFile(p, []byte("0"), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", p, err)
		}
	}
	for _, p := range isolatedSysctls {
		v, err := os.ReadFile(p)
		if err != nil || strings.TrimSpace(string(v)) != "0" {
			return fmt.Errorf("%s must be 0, got %q (%v)", p, v, err)
		}
	}
	// A fresh namespace has no route besides loopback's own; any other means
	// it is not the empty one this was meant to start in. (Down tunnel
	// fallback devices such as tunl0 and sit0 may exist and are harmless.)
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := netlink.RouteListFiltered(fam, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return fmt.Errorf("list routes: %w", err)
		}
		for _, r := range routes {
			if r.LinkIndex != lo.Attrs().Index {
				return fmt.Errorf("the namespace is not empty: route %v", r)
			}
		}
	}
	return nil
}
