package server

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// An out-of-range bd_id (> uint16) is rejected as a per-item error rather than
// silently truncated into a different bridge domain.
func TestVrfBgpBind_BdIdOutOfRange(t *testing.T) {
	s := NewVrfBgpServer(vrfbgp.NewManager())
	resp, err := s.VrfBgpBind(context.Background(), connect.NewRequest(&v1.VrfBgpBindRequest{
		Bindings: []*v1.VrfBgpBinding{
			{VrfName: "evi-ok", ImportRts: []string{"65000:100"}, BdId: 100},
			{VrfName: "evi-bad", ImportRts: []string{"65000:101"}, BdId: 70000},
		},
	}))
	if err != nil {
		t.Fatalf("VrfBgpBind: %v", err)
	}
	if len(resp.Msg.Bound) != 1 || resp.Msg.Bound[0].GetVrfName() != "evi-ok" {
		t.Errorf("only the in-range binding should be bound; bound=%v", resp.Msg.Bound)
	}
	if len(resp.Msg.Errors) != 1 {
		t.Fatalf("out-of-range bd_id must be a per-item error; errors=%v", resp.Msg.Errors)
	}
	if got := s.mgr.List(); len(got) != 1 || got[0].BDID != 100 {
		t.Errorf("only the in-range BD must be stored; got %+v", got)
	}
}
