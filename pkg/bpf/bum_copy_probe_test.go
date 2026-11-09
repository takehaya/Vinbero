package bpf

import (
	"errors"
	"testing"
	"time"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// TestBpfLoadGenericCopyProbe runs the startup probe for real (the
// multi-kernel CI runs every TestBpfLoad* test). Either verdict is a pass:
// which one a kernel gives depends on whether it has the private-skb fix.
func TestBpfLoadGenericCopyProbe(t *testing.T) {
	before, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = before.Close() }()

	start := time.Now()
	private, err := ProbeGenericBroadcastCopies(time.Second)
	if errors.Is(err, unix.EOPNOTSUPP) {
		// Kernels built without veth (vinberod then runs xdp-mode BDs in tc).
		t.Skipf("probe cannot run on this kernel: %v", err)
	}
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	t.Logf("generic XDP broadcast copies private=%v (%v)", private, time.Since(start))

	after, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = after.Close() }()
	if !before.Equal(after) {
		t.Fatal("the probe left the test goroutine in another network namespace")
	}
}

func TestProbeVerdict(t *testing.T) {
	for _, tc := range []struct {
		name        string
		stamps      map[byte][]byte
		wantPrivate bool
		wantErr     bool
	}{
		{"private", map[byte][]byte{0: {0xa0, 0xa1}, 1: {0xa1, 0xa0}, 2: {0xa0, 0xa1}}, true, false},
		{"shared", map[byte][]byte{0: {0xa1, 0xa1}, 1: {0xa0, 0xa0}}, false, false},
		{"one frame shared is enough", map[byte][]byte{0: {0xa0, 0xa1}, 1: {0xa1, 0xa1}}, false, false},
		{"lost copies are not counted", map[byte][]byte{0: {0xa0}, 1: {0xa0, 0xa1}}, true, false},
		{"nothing to compare", map[byte][]byte{0: {0xa0}}, false, true},
		{"nothing came back", map[byte][]byte{}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := probeVerdict(tc.stamps)
			if (err != nil) != tc.wantErr || got != tc.wantPrivate {
				t.Errorf("probeVerdict = %v, %v; want private=%v err=%v", got, err, tc.wantPrivate, tc.wantErr)
			}
		})
	}
}
