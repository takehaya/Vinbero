package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/api/vinbero/v1/vinberov1connect"
)

type stubHeadendL2 struct {
	vinberov1connect.UnimplementedHeadendL2ServiceHandler
	resp *v1.HeadendL2DeleteResponse
}

func (s *stubHeadendL2) HeadendL2Delete(context.Context, *connect.Request[v1.HeadendL2DeleteRequest]) (*connect.Response[v1.HeadendL2DeleteResponse], error) {
	return connect.NewResponse(s.resp), nil
}

// A per-target error fails the command instead of exiting 0 with no output.
func TestHeadendL2DeleteReportsErrors(t *testing.T) {
	stub := &stubHeadendL2{}
	mux := http.NewServeMux()
	mux.Handle(vinberov1connect.NewHeadendL2ServiceHandler(stub))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	args := []string{"vinbero", "-s", srv.URL, "headend-l2", "delete", "--interface", "eth9", "--vlan-id", "0"}

	stub.resp = &v1.HeadendL2DeleteResponse{
		Errors: []*v1.OperationError{{TriggerPrefix: "eth9:vlan_0", Reason: "boom"}},
	}
	if err := NewApp().Run(args); err == nil {
		t.Error("delete reported success for a per-target error")
	}

	stub.resp = &v1.HeadendL2DeleteResponse{
		Deleted: []*v1.HeadendL2DeleteTarget{{InterfaceName: "eth9"}},
	}
	if err := NewApp().Run(args); err != nil {
		t.Errorf("delete failed without an error: %v", err)
	}
}
