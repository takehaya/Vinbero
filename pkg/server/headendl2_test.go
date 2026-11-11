package server

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"github.com/cilium/ebpf"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/vinbero"
)

// fakeBook is an l2CircuitBook that records what the server asks of it.
type fakeBook struct {
	create   func(vinbero.L2Circuit) error
	del      func(ifindex uint32, vlan uint16) error
	vanished func(name string, vlan uint16) (bool, error)
}

func (f *fakeBook) Create(c vinbero.L2Circuit) error {
	if f.create == nil {
		return nil
	}
	return f.create(c)
}
func (f *fakeBook) Delete(ifindex uint32, vlan uint16) error { return f.del(ifindex, vlan) }
func (f *fakeBook) DeleteVanished(name string, vlan uint16) (bool, error) {
	if f.vanished == nil {
		return false, nil
	}
	return f.vanished(name, vlan)
}
func (f *fakeBook) Flush() (uint32, error) { return 0, nil }

// lookupLo resolves "lo" only.
func lookupLo(name string) (vinbero.LinkID, error) {
	if name == "lo" {
		return vinbero.LinkID{Name: "lo", Ifindex: 1}, nil
	}
	return vinbero.LinkID{}, errLinkNotFound
}

func deleteTargets(t *testing.T, s *HeadendL2Server, names ...string) *v1.HeadendL2DeleteResponse {
	t.Helper()
	req := &v1.HeadendL2DeleteRequest{}
	for _, n := range names {
		req.Targets = append(req.Targets, &v1.HeadendL2DeleteTarget{InterfaceName: n})
	}
	resp, err := s.HeadendL2Delete(context.Background(), connect.NewRequest(req))
	if err != nil {
		t.Fatal(err)
	}
	return resp.Msg
}

func isNotFound(e *v1.OperationError) bool {
	return strings.HasPrefix(e.Reason, v1.ReasonNotFound)
}

// A name that resolves to nothing is reported as not found, so a typo or a
// renamed interface is visible and a teardown can treat it as already gone.
func TestHeadendL2DeleteUnresolvableName(t *testing.T) {
	s := NewHeadendL2Server(nil)
	s.SetCircuits(&fakeBook{})
	got := deleteTargets(t, s, "vbtypo0test")
	if len(got.Deleted) != 0 || len(got.Errors) != 1 || !isNotFound(got.Errors[0]) {
		t.Errorf("got %+v, want one not-found error", got)
	}

	got = deleteTargets(t, s, "bad/name")
	if len(got.Errors) != 1 || isNotFound(got.Errors[0]) {
		t.Errorf("a malformed name is an error, not not-found: %+v", got)
	}
}

// A live interface without the entry is not found too, and a real failure
// stays an error.
func TestHeadendL2DeleteOutcomes(t *testing.T) {
	s := NewHeadendL2Server(nil)
	s.lookupLink = lookupLo
	book := &fakeBook{}
	s.SetCircuits(book)
	book.del = func(uint32, uint16) error { return ebpf.ErrKeyNotExist }
	if got := deleteTargets(t, s, "lo"); len(got.Errors) != 1 || !isNotFound(got.Errors[0]) {
		t.Errorf("missing entry: %+v", got)
	}

	book.del = func(uint32, uint16) error { return errors.New("boom") }
	if got := deleteTargets(t, s, "lo"); len(got.Errors) != 1 || isNotFound(got.Errors[0]) {
		t.Errorf("a real failure must not look like not-found: %+v", got)
	}

	book.del = func(uint32, uint16) error { return nil }
	if got := deleteTargets(t, s, "lo"); len(got.Deleted) != 1 || len(got.Errors) != 0 {
		t.Errorf("success: %+v", got)
	}
}

// A saved circuit whose interface is gone is deleted by its old name; a name
// with no such circuit stays not found.
func TestHeadendL2DeleteVanishedName(t *testing.T) {
	s := NewHeadendL2Server(nil)
	s.lookupLink = lookupLo
	s.SetCircuits(&fakeBook{vanished: func(name string, vlan uint16) (bool, error) {
		return name == "vbgone0" && vlan == 0, nil
	}})
	if got := deleteTargets(t, s, "vbgone0"); len(got.Deleted) != 1 || len(got.Errors) != 0 {
		t.Errorf("saved circuit of a vanished interface: %+v", got)
	}
	if got := deleteTargets(t, s, "vbgone1"); len(got.Errors) != 1 || !isNotFound(got.Errors[0]) {
		t.Errorf("no saved circuit: %+v", got)
	}
}

// An L2 circuit on a port enslaved to a VRF device is refused before any map
// write: its encapsulations and BUM copies would be looked up in the VRF
// table. (mapOps is nil, so reaching the write would panic.)
func TestHeadendL2CreateRefusesVrfPort(t *testing.T) {
	s := NewHeadendL2Server(nil)
	s.SetClosedVRFCheck(func(uint32) (string, bool, error) { return "vrf-cust", true, nil }, nil)
	resp, err := s.HeadendL2Create(context.Background(), connect.NewRequest(&v1.HeadendL2CreateRequest{
		HeadendL2S: []*v1.HeadendL2{{InterfaceName: "lo", SrcAddr: "fc00::1", Segments: []string{"fc00::2"}, BdId: 100}},
	}))
	if err != nil {
		t.Fatalf("HeadendL2Create: %v", err)
	}
	if len(resp.Msg.Created) != 0 || len(resp.Msg.Errors) != 1 ||
		!strings.Contains(resp.Msg.Errors[0].Reason, `port of VRF "vrf-cust"`) {
		t.Errorf("got %+v, want one VRF-port error", resp.Msg)
	}
}

// The closed-VRF check and the map write both run under the VRF mutation
// lock, so a VrfCreate cannot close the port's table between them.
func TestHeadendL2CreateHoldsVRFLock(t *testing.T) {
	s := NewHeadendL2Server(nil)
	vrfMu := &sync.Mutex{}
	held := func(what string) {
		if vrfMu.TryLock() {
			vrfMu.Unlock()
			t.Errorf("%s runs without the VRF mutation lock", what)
		}
	}
	s.SetClosedVRFCheck(func(uint32) (string, bool, error) {
		held("the closed-VRF check")
		return "", false, nil
	}, vrfMu)
	written := 0
	s.SetCircuits(&fakeBook{create: func(vinbero.L2Circuit) error {
		held("the map write")
		written++
		return nil
	}})
	s.lookupLink = lookupLo
	resp, err := s.HeadendL2Create(context.Background(), connect.NewRequest(&v1.HeadendL2CreateRequest{
		HeadendL2S: []*v1.HeadendL2{{InterfaceName: "lo", SrcAddr: "fc00::1", Segments: []string{"fc00::2"}, BdId: 100}},
	}))
	if err != nil || written != 1 {
		t.Fatalf("HeadendL2Create: %v, written %d, %+v", err, written, resp.Msg)
	}
	if !vrfMu.TryLock() {
		t.Fatal("the lock is still held after the create")
	}
}
