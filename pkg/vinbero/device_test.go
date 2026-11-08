package vinbero

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cilium/ebpf/link"
	"github.com/takehaya/vinbero/pkg/config"
	"github.com/takehaya/vinbero/pkg/netresource"
	"go.uber.org/zap"
)

// fakeLink stands in for a bpf_link; the embedded nil interface supplies the
// unexported marker method, and only Close is ever called.
type fakeLink struct {
	link.Link
	ops  *fakeLinkOps
	name string
}

func (l *fakeLink) Close() error {
	l.ops.open[l.name]--
	return nil
}

type fakeLinkOps struct {
	ifindexes map[string]int // the interfaces that exist
	lookupErr error          // a lookup failure that says nothing about existence
	xdpErr    error
	tcErr     error
	open      map[string]int // live links per "xdp:<ifindex>" / "tc:<ifindex>"
	attaches  int
}

func newFakeLinkOps(names ...string) *fakeLinkOps {
	f := &fakeLinkOps{ifindexes: map[string]int{}, open: map[string]int{}}
	for i, n := range names {
		f.ifindexes[n] = 10 + i
	}
	return f
}

func (f *fakeLinkOps) ifindex(name string) (int, error) {
	if f.lookupErr != nil {
		return 0, f.lookupErr
	}
	if i, ok := f.ifindexes[name]; ok {
		return i, nil
	}
	return 0, fmt.Errorf("%w: %s", ErrNoInterface, name)
}

func (f *fakeLinkOps) attachXDP(ifindex int, _ link.XDPAttachFlags) (link.Link, error) {
	if f.xdpErr != nil {
		return nil, f.xdpErr
	}
	f.attaches++
	key := fmt.Sprintf("xdp:%d", ifindex)
	f.open[key]++
	return &fakeLink{ops: f, name: key}, nil
}

func (f *fakeLinkOps) attachTC(ifindex int) (link.Link, error) {
	if f.tcErr != nil {
		return nil, f.tcErr
	}
	key := fmt.Sprintf("tc:%d", ifindex)
	f.open[key]++
	return &fakeLink{ops: f, name: key}, nil
}

// live is the number of links not closed yet.
func (f *fakeLinkOps) live() int {
	n := 0
	for _, c := range f.open {
		n += c
	}
	return n
}

func newTestVinbero(t *testing.T, ops *fakeLinkOps, statePath string, configDevices ...string) *Vinbero {
	t.Helper()
	cfg := &config.Config{}
	cfg.InternalConfig.BpfOptions.DeviceMode = "driver"
	v := &Vinbero{cfg: cfg, devOps: ops, logger: zap.NewNop()}
	for _, n := range configDevices {
		v.devices = append(v.devices, net.Interface{Name: n})
	}
	if statePath != "" {
		rm, err := netresource.NewResourceManager(statePath, zap.NewNop())
		if err != nil {
			t.Fatalf("NewResourceManager: %v", err)
		}
		v.resMgr = rm
	}
	return v
}

func TestAttachDevice(t *testing.T) {
	ops := newFakeLinkOps("eth0", "veth1")
	v := newTestVinbero(t, ops, filepath.Join(t.TempDir(), "state.json"), "eth0")
	if err := v.AttachConfigDevices(); err != nil {
		t.Fatalf("AttachConfigDevices: %v", err)
	}

	d, err := v.AttachDevice("veth1", "")
	if err != nil {
		t.Fatalf("AttachDevice: %v", err)
	}
	if d.Mode != "driver" || d.Ifindex != 11 || d.Config {
		t.Errorf("device = %+v, want the default mode on ifindex 11", d)
	}
	// Same mode (spelled out or defaulted): no second attach.
	if _, err := v.AttachDevice("veth1", "driver"); err != nil {
		t.Errorf("idempotent attach: %v", err)
	}
	if ops.attaches != 2 {
		t.Errorf("attaches = %d, want 2 (eth0 and veth1 once each)", ops.attaches)
	}
	if _, err := v.AttachDevice("veth1", "generic"); !errors.Is(err, ErrModeConflict) {
		t.Errorf("mode change = %v, want ErrModeConflict", err)
	}
	if _, err := v.AttachDevice("veth1", "bogus"); !errors.Is(err, ErrInvalidMode) {
		t.Errorf("bad mode = %v, want ErrInvalidMode", err)
	}
	if _, err := v.AttachDevice("missing0", ""); !errors.Is(err, ErrNoInterface) {
		t.Errorf("missing interface = %v, want ErrNoInterface", err)
	}
	// A config device attaches idempotently but is never persisted.
	if d, err := v.AttachDevice("eth0", ""); err != nil || !d.Config {
		t.Errorf("attach of a config device = %+v, %v", d, err)
	}
	if _, err := v.AttachDevice("eth0", "generic"); !errors.Is(err, ErrModeConflict) {
		t.Errorf("config device in another mode = %v, want ErrModeConflict", err)
	}
	if got := v.resMgr.ListDevices(); !slices.Equal(got, []netresource.ManagedDevice{{Name: "veth1", Mode: "driver"}}) {
		t.Errorf("state devices = %v", got)
	}
	if got := v.ListDevices(); len(got) != 2 || got[0].Name != "eth0" || got[1].Name != "veth1" {
		t.Errorf("ListDevices = %+v", got)
	}
}

// A failing TC attach closes the XDP link again: no half-attached device,
// nothing recorded.
func TestAttachDevice_RollbackOnTCFailure(t *testing.T) {
	ops := newFakeLinkOps("veth1")
	ops.tcErr = errors.New("tcx unsupported")
	v := newTestVinbero(t, ops, filepath.Join(t.TempDir(), "state.json"))
	if _, err := v.AttachDevice("veth1", ""); err == nil {
		t.Fatal("AttachDevice with a failing TC attach: want error")
	}
	if ops.live() != 0 {
		t.Errorf("live links after rollback = %v", ops.open)
	}
	if len(v.ListDevices()) != 0 || len(v.resMgr.ListDevices()) != 0 {
		t.Error("a failed attach left a record")
	}
	ops.tcErr = nil
	if _, err := v.AttachDevice("veth1", ""); err != nil {
		t.Errorf("retry after the failure: %v", err)
	}
}

func TestDetachDevice(t *testing.T) {
	ops := newFakeLinkOps("eth0", "veth1", "veth2")
	v := newTestVinbero(t, ops, filepath.Join(t.TempDir(), "state.json"), "eth0")
	if err := v.AttachConfigDevices(); err != nil {
		t.Fatalf("AttachConfigDevices: %v", err)
	}
	for _, n := range []string{"veth1", "veth2"} {
		if _, err := v.AttachDevice(n, ""); err != nil {
			t.Fatalf("AttachDevice(%s): %v", n, err)
		}
	}

	if err := v.DetachDevice("veth1"); err != nil {
		t.Fatalf("DetachDevice: %v", err)
	}
	if ops.open["xdp:11"] != 0 || ops.open["tc:11"] != 0 {
		t.Errorf("veth1 links still open: %v", ops.open)
	}
	if err := v.DetachDevice("veth1"); !errors.Is(err, ErrNotAttached) {
		t.Errorf("second detach = %v, want ErrNotAttached", err)
	}
	if err := v.DetachDevice("eth0"); !errors.Is(err, ErrConfigDevice) {
		t.Errorf("detach of a config device = %v, want ErrConfigDevice", err)
	}

	// The interface vanished (pod deleted): the detach still succeeds.
	delete(ops.ifindexes, "veth2")
	if err := v.DetachDevice("veth2"); err != nil {
		t.Errorf("detach of a vanished interface: %v", err)
	}
	if got := v.resMgr.ListDevices(); len(got) != 0 {
		t.Errorf("state devices after detach = %v", got)
	}
	if got := v.ListDevices(); len(got) != 1 || got[0].Name != "eth0" {
		t.Errorf("ListDevices = %+v", got)
	}
}

// ListDevices drops an attachment whose interface is gone, and an attach on a
// recreated interface (same name, new ifindex) replaces the stale links.
func TestDevices_StaleAttachments(t *testing.T) {
	ops := newFakeLinkOps("veth1", "veth2")
	v := newTestVinbero(t, ops, filepath.Join(t.TempDir(), "state.json"))
	for _, n := range []string{"veth1", "veth2"} {
		if _, err := v.AttachDevice(n, ""); err != nil {
			t.Fatalf("AttachDevice(%s): %v", n, err)
		}
	}
	// A lookup that fails for another reason keeps both attached.
	ops.lookupErr = errors.New("ENOBUFS")
	if got := v.ListDevices(); len(got) != 2 || ops.live() != 4 {
		t.Errorf("a failed lookup dropped devices: %+v, links %v", got, ops.open)
	}
	ops.lookupErr = nil

	delete(ops.ifindexes, "veth1")
	if got := v.ListDevices(); len(got) != 1 || got[0].Name != "veth2" {
		t.Errorf("ListDevices = %+v, want only veth2", got)
	}
	if got := v.resMgr.ListDevices(); len(got) != 1 || got[0].Name != "veth2" {
		t.Errorf("state devices = %v, want only veth2", got)
	}

	ops.ifindexes["veth2"] = 99 // deleted and recreated under the same name
	d, err := v.AttachDevice("veth2", "")
	if err != nil {
		t.Fatalf("attach on the recreated interface: %v", err)
	}
	if d.Ifindex != 99 {
		t.Errorf("ifindex = %d, want 99", d.Ifindex)
	}
	if ops.live() != 2 || ops.open["xdp:99"] != 1 || ops.open["tc:99"] != 1 {
		t.Errorf("links = %v, want only the pair on ifindex 99", ops.open)
	}
}

// An invalid internal.bpf.device_mode fails the boot even without
// internal.devices: every runtime attach without a mode would fail.
func TestAttachConfigDevices_InvalidMode(t *testing.T) {
	v := newTestVinbero(t, newFakeLinkOps(), "")
	v.cfg.InternalConfig.BpfOptions.DeviceMode = "native"
	if err := v.AttachConfigDevices(); !errors.Is(err, ErrInvalidMode) {
		t.Errorf("AttachConfigDevices = %v, want ErrInvalidMode", err)
	}
}

// After a restart the state devices are attached again. An entry whose
// interface is gone or that internal.devices now declares is dropped; one
// that fails to attach for another reason stays for the next start. None of
// them fails the boot.
func TestReconcileDevices(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	ops := newFakeLinkOps("eth0", "veth1", "veth2", "veth3")
	v := newTestVinbero(t, ops, statePath)
	for _, n := range []string{"eth0", "veth1", "veth2", "veth3"} {
		if _, err := v.AttachDevice(n, "generic"); err != nil {
			t.Fatalf("AttachDevice(%s): %v", n, err)
		}
	}
	if err := v.closeAllDevices(); err != nil {
		t.Fatalf("closeAllDevices: %v", err)
	}
	if ops.live() != 0 {
		t.Fatalf("links after Close = %v", ops.open)
	}

	// Restart: eth0 moved into internal.devices, veth2 is gone, veth3 now
	// refuses XDP (the fake fails every later XDP attach after eth0's).
	delete(ops.ifindexes, "veth2")
	v2 := newTestVinbero(t, ops, statePath, "eth0")
	if err := v2.AttachConfigDevices(); err != nil {
		t.Fatalf("AttachConfigDevices: %v", err)
	}
	failVeth3 := &failingOps{fakeLinkOps: ops, fail: 13}
	v2.devOps = failVeth3
	if err := v2.ReconcileDevices(); err != nil {
		t.Fatalf("ReconcileDevices: %v", err)
	}
	got := v2.ListDevices()
	if len(got) != 2 || got[0].Name != "eth0" || !got[0].Config || got[1].Name != "veth1" || got[1].Mode != "generic" {
		t.Errorf("devices after reconcile = %+v, want config eth0 and generic veth1", got)
	}
	reloaded, err := netresource.NewResourceManager(statePath, zap.NewNop())
	if err != nil {
		t.Fatalf("reload state: %v", err)
	}
	want := []netresource.ManagedDevice{{Name: "veth1", Mode: "generic"}, {Name: "veth3", Mode: "generic"}}
	if got := reloaded.ListDevices(); !slices.Equal(got, want) {
		t.Errorf("state on disk = %v, want %v", got, want)
	}
}

// failingOps fails the XDP attach on one ifindex.
type failingOps struct {
	*fakeLinkOps
	fail int
}

func (f *failingOps) attachXDP(ifindex int, flags link.XDPAttachFlags) (link.Link, error) {
	if ifindex == f.fail {
		return nil, errors.New("EOPNOTSUPP")
	}
	return f.fakeLinkOps.attachXDP(ifindex, flags)
}
