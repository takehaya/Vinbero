package vinbero

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/takehaya/vinbero/pkg/config"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"go.uber.org/zap"
)

// withKernelNetns runs the test in a fresh network namespace so the veths
// and attachments cannot touch the host. Needs root.
func withKernelNetns(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root (netns, BPF load and XDP attach)")
	}
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("netns.Get: %v", err)
	}
	ns, err := netns.New()
	if err != nil {
		_ = orig.Close()
		runtime.UnlockOSThread()
		t.Fatalf("netns.New: %v", err)
	}
	t.Cleanup(func() {
		_ = netns.Set(orig)
		_ = orig.Close()
		_ = ns.Close()
		runtime.UnlockOSThread()
	})
}

func addVeth(t *testing.T, name, peer string) {
	t.Helper()
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: peer}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("veth add %s: %v", name, err)
	}
	for _, n := range []string{name, peer} {
		l, err := netlink.LinkByName(n)
		if err != nil {
			t.Fatalf("LinkByName %s: %v", n, err)
		}
		if err := netlink.LinkSetUp(l); err != nil {
			t.Fatalf("set %s up: %v", n, err)
		}
	}
}

// attachedPrograms reports whether name carries an XDP program and how many
// TCX ingress programs it has.
func attachedPrograms(t *testing.T, name string) (bool, int) {
	t.Helper()
	l, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("LinkByName %s: %v", name, err)
	}
	xdp := l.Attrs().Xdp != nil && l.Attrs().Xdp.Attached
	res, err := link.QueryPrograms(link.QueryOptions{Target: l.Attrs().Index, Attach: ebpf.AttachTCXIngress})
	if err != nil {
		t.Fatalf("query TCX on %s: %v", name, err)
	}
	return xdp, len(res.Programs)
}

func newKernelVinbero(t *testing.T, statePath string, devices ...string) *Vinbero {
	t.Helper()
	yaml := "internal:\n  bpf:\n    device_mode: generic\n  devices:\n"
	for _, d := range devices {
		yaml += fmt.Sprintf("    - %s\n", d)
	}
	yaml += fmt.Sprintf("settings:\n  state_path: %s\n", statePath)
	cfg, err := config.Load(yaml)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	v, err := NewVinbero(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewVinbero: %v", err)
	}
	if err := v.AttachConfigDevices(); err != nil {
		_ = v.Close()
		t.Fatalf("AttachConfigDevices: %v", err)
	}
	if err := v.InitResourceManager(); err != nil {
		_ = v.Close()
		t.Fatalf("InitResourceManager: %v", err)
	}
	return v
}

// Attach and detach put the XDP + TCX pair on a veth and take it off again;
// a restart attaches the recorded device again; a vanished veth detaches.
func TestDeviceAttach_Kernel(t *testing.T) {
	withKernelNetns(t)
	addVeth(t, "kda0", "kda0p")
	addVeth(t, "kdb0", "kdb0p")
	statePath := filepath.Join(t.TempDir(), "state.json")

	v := newKernelVinbero(t, statePath, "kda0")
	if xdp, tc := attachedPrograms(t, "kda0"); !xdp || tc != 1 {
		t.Fatalf("config device: xdp=%v tcx=%d", xdp, tc)
	}
	if _, err := v.AttachDevice("kdb0", ""); err != nil {
		t.Fatalf("AttachDevice: %v", err)
	}
	if _, err := v.AttachDevice("kdb0", "generic"); err != nil {
		t.Fatalf("idempotent AttachDevice: %v", err)
	}
	if xdp, tc := attachedPrograms(t, "kdb0"); !xdp || tc != 1 {
		t.Fatalf("runtime device: xdp=%v tcx=%d, want one of each", xdp, tc)
	}
	if _, err := v.AttachDevice("kdb0", "driver"); !errors.Is(err, ErrModeConflict) {
		t.Errorf("mode change = %v, want ErrModeConflict", err)
	}
	if err := v.DetachDevice("kdb0"); err != nil {
		t.Fatalf("DetachDevice: %v", err)
	}
	if xdp, tc := attachedPrograms(t, "kdb0"); xdp || tc != 0 {
		t.Errorf("after detach: xdp=%v tcx=%d", xdp, tc)
	}

	// Restart: the runtime device comes back from the state file.
	if _, err := v.AttachDevice("kdb0", ""); err != nil {
		t.Fatalf("AttachDevice: %v", err)
	}
	if err := v.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if xdp, tc := attachedPrograms(t, "kdb0"); xdp || tc != 0 {
		t.Fatalf("after Close: xdp=%v tcx=%d", xdp, tc)
	}
	v = newKernelVinbero(t, statePath, "kda0")
	defer func() { _ = v.Close() }()
	if err := v.ReconcileDevices(); err != nil {
		t.Fatalf("ReconcileDevices: %v", err)
	}
	if xdp, tc := attachedPrograms(t, "kdb0"); !xdp || tc != 1 {
		t.Fatalf("after reconcile: xdp=%v tcx=%d", xdp, tc)
	}

	// The veth disappears (its pod was deleted): detach still succeeds.
	l, err := netlink.LinkByName("kdb0")
	if err != nil {
		t.Fatalf("LinkByName: %v", err)
	}
	if err := netlink.LinkDel(l); err != nil {
		t.Fatalf("LinkDel: %v", err)
	}
	if err := v.DetachDevice("kdb0"); err != nil {
		t.Errorf("detach of a deleted veth: %v", err)
	}
	if got := v.GetResourceManager().ListDevices(); len(got) != 0 {
		t.Errorf("state devices = %v", got)
	}
}

// A device recorded in the state file whose interface is gone at boot is
// dropped, not fatal.
func TestReconcileDevices_Kernel_VanishedInterface(t *testing.T) {
	withKernelNetns(t)
	addVeth(t, "kdc0", "kdc0p")
	statePath := filepath.Join(t.TempDir(), "state.json")
	v := newKernelVinbero(t, statePath)
	if _, err := v.AttachDevice("kdc0", ""); err != nil {
		t.Fatalf("AttachDevice: %v", err)
	}
	if err := v.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	l, err := netlink.LinkByName("kdc0")
	if err != nil {
		t.Fatalf("LinkByName: %v", err)
	}
	if err := netlink.LinkDel(l); err != nil {
		t.Fatalf("LinkDel: %v", err)
	}
	v = newKernelVinbero(t, statePath)
	defer func() { _ = v.Close() }()
	if err := v.ReconcileDevices(); err != nil {
		t.Fatalf("ReconcileDevices: %v", err)
	}
	if got := v.ListDevices(); len(got) != 0 {
		t.Errorf("devices = %+v", got)
	}
	if got := v.GetResourceManager().ListDevices(); len(got) != 0 {
		t.Errorf("state devices = %v", got)
	}
}
