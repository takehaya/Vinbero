package bpf

import (
	"net"
	"testing"
)

// keep leaves only the locally learned entries it selects; a remote entry
// ages even when its MAC is kept.
func TestAgeFdbEntriesKeep(t *testing.T) {
	h := newXDPTestHelper(t)
	const bd = uint16(100)
	stale := net.HardwareAddr{0, 0, 0, 0, 0, 1}
	held := net.HardwareAddr{0, 0, 0, 0, 0, 2}
	remote := net.HardwareAddr{0, 0, 0, 0, 0, 3}
	if err := h.mapOps.CreateFdb(bd, stale, &FdbEntry{Oif: 1, LastSeen: 1}); err != nil {
		t.Fatal(err)
	}
	if err := h.mapOps.CreateFdb(bd, held, &FdbEntry{Oif: 1, LastSeen: 1}); err != nil {
		t.Fatal(err)
	}
	if err := h.mapOps.CreateFdb(bd, remote, &FdbEntry{IsRemote: 1, LastSeen: 1}); err != nil {
		t.Fatal(err)
	}

	aged, err := h.mapOps.AgeFdbEntries(1e9, func(k FdbKey) bool {
		m := net.HardwareAddr(k.Mac[:]).String()
		return m == held.String() || m == remote.String()
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, a := range aged {
		got[a.MAC.String()] = true
	}
	if !got[stale.String()] || !got[remote.String()] || got[held.String()] || len(aged) != 2 {
		t.Errorf("aged = %+v, want %s and %s", aged, stale, remote)
	}
	if _, err := h.mapOps.GetFdb(bd, held); err != nil {
		t.Errorf("the kept entry was aged: %v", err)
	}
}
