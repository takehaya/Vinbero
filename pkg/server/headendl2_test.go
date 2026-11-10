package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/cilium/ebpf"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

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
	s.deleteEntry = func(uint32, uint16) error { return ebpf.ErrKeyNotExist }
	if got := deleteTargets(t, s, "lo"); len(got.Errors) != 1 || !isNotFound(got.Errors[0]) {
		t.Errorf("missing entry: %+v", got)
	}

	s.deleteEntry = func(uint32, uint16) error { return errors.New("boom") }
	if got := deleteTargets(t, s, "lo"); len(got.Errors) != 1 || isNotFound(got.Errors[0]) {
		t.Errorf("a real failure must not look like not-found: %+v", got)
	}

	s.deleteEntry = func(uint32, uint16) error { return nil }
	if got := deleteTargets(t, s, "lo"); len(got.Deleted) != 1 || len(got.Errors) != 0 {
		t.Errorf("success: %+v", got)
	}
}

// An L2 circuit on a port enslaved to a VRF device is refused before any map
// write: its encapsulations and BUM copies would be looked up in the VRF
// table. (mapOps is nil, so reaching the write would panic.)
func TestHeadendL2CreateRefusesVrfPort(t *testing.T) {
	s := NewHeadendL2Server(nil)
	s.vrfMaster = func(uint32) (string, error) { return "vrf-cust", nil }
	resp, err := s.HeadendL2Create(context.Background(), connect.NewRequest(&v1.HeadendL2CreateRequest{
		HeadendL2S: []*v1.HeadendL2{{InterfaceName: "lo", SrcAddr: "fc00::1", Segments: []string{"fc00::2"}, BdId: 100}},
	}))
	if err != nil {
		t.Fatalf("HeadendL2Create: %v", err)
	}
	if len(resp.Msg.Created) != 0 || len(resp.Msg.Errors) != 1 ||
		!strings.Contains(resp.Msg.Errors[0].Reason, `enslaved to VRF device "vrf-cust"`) {
		t.Errorf("got %+v, want one VRF-port error", resp.Msg)
	}
}
