package vinbero

import (
	"path/filepath"
	"testing"
)

// The sweep's interface dump is older than the attachments it checks: one
// missing from the dump stays when the interface exists, and goes when it
// does not.
func TestPruneDevicesConfirmsUnderLock(t *testing.T) {
	ops := newFakeLinkOps("veth1", "veth2")
	v := newTestVinbero(t, ops, filepath.Join(t.TempDir(), "state.json"))
	if _, err := v.AttachDevice("veth1", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := v.AttachDevice("veth2", ""); err != nil {
		t.Fatal(err)
	}

	v.pruneDevices(map[string]int{}) // a dump from before both attachments
	if len(v.attached) != 2 {
		t.Fatalf("attachments made after the dump were dropped: %v", v.attached)
	}

	delete(ops.ifindexes, "veth2")
	v.pruneDevices(map[string]int{})
	if _, ok := v.attached["veth2"]; ok || len(v.attached) != 1 {
		t.Errorf("attachments = %v, want only veth1", v.attached)
	}
}
