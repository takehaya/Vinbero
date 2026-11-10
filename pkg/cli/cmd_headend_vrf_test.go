package cli

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/api/vinbero/v1/vinberov1connect"
)

type stubHeadendV4 struct {
	vinberov1connect.UnimplementedHeadendv4ServiceHandler
	created []*v1.Headendv4
	deleted *v1.Headendv4DeleteRequest
	listed  *v1.Headendv4ListRequest
	flushed *v1.Headendv4FlushRequest
}

func (s *stubHeadendV4) Headendv4Create(_ context.Context, r *connect.Request[v1.Headendv4CreateRequest]) (*connect.Response[v1.Headendv4CreateResponse], error) {
	s.created = append(s.created, r.Msg.Headendv4S...)
	return connect.NewResponse(&v1.Headendv4CreateResponse{Created: r.Msg.Headendv4S}), nil
}

func (s *stubHeadendV4) Headendv4Delete(_ context.Context, r *connect.Request[v1.Headendv4DeleteRequest]) (*connect.Response[v1.Headendv4DeleteResponse], error) {
	s.deleted = r.Msg
	return connect.NewResponse(&v1.Headendv4DeleteResponse{DeletedTriggerPrefixes: r.Msg.TriggerPrefixes}), nil
}

func (s *stubHeadendV4) Headendv4Flush(_ context.Context, r *connect.Request[v1.Headendv4FlushRequest]) (*connect.Response[v1.Headendv4FlushResponse], error) {
	s.flushed = r.Msg
	return connect.NewResponse(&v1.Headendv4FlushResponse{}), nil
}

func (s *stubHeadendV4) Headendv4List(_ context.Context, r *connect.Request[v1.Headendv4ListRequest]) (*connect.Response[v1.Headendv4ListResponse], error) {
	s.listed = r.Msg
	return connect.NewResponse(&v1.Headendv4ListResponse{Headendv4S: []*v1.Headendv4{
		{TriggerPrefix: "10.0.0.0/24", SrcAddr: "fc00::1", Segments: []string{"fc00::a"}},
		{TriggerPrefix: "10.0.0.0/24", SrcAddr: "fc00::1", Segments: []string{"fc00::b"}, VrfName: "tenant-a", VrfId: 3},
		{TriggerPrefix: "10.0.0.0/24", SrcAddr: "fc00::1", Segments: []string{"fc00::c"}, VrfId: 9},
	}}), nil
}

func captureStdout(t *testing.T, run func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	runErr := run()
	os.Stdout = saved
	_ = w.Close()
	out, _ := io.ReadAll(r)
	return string(out), runErr
}

// --vrf reaches every headend-v4 request, and the list shows each entry's
// VRF in the second column, so the prefix stays the first field and the
// segment list the last.
func TestHeadendV4VRFFlag(t *testing.T) {
	stub := &stubHeadendV4{}
	mux := http.NewServeMux()
	mux.Handle(vinberov1connect.NewHeadendv4ServiceHandler(stub))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	run := func(args ...string) (string, error) {
		return captureStdout(t, func() error {
			return NewApp().Run(append([]string{"vinbero", "-s", srv.URL, "headend-v4"}, args...))
		})
	}

	if _, err := run("create", "--trigger-prefix", "10.0.0.0/24", "--src-addr", "fc00::1", "--segments", "fc00::b", "--vrf", "tenant-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := run("create", "--trigger-prefix", "10.0.0.0/24", "--src-addr", "fc00::1", "--segments", "fc00::a"); err != nil {
		t.Fatal(err)
	}
	if len(stub.created) != 2 || stub.created[0].VrfName != "tenant-a" || stub.created[1].VrfName != "" {
		t.Errorf("created = %v", stub.created)
	}
	if _, err := run("delete", "--trigger-prefix", "10.0.0.0/24", "--vrf", "tenant-a"); err != nil || stub.deleted.VrfName != "tenant-a" {
		t.Errorf("delete = %v %v", stub.deleted, err)
	}
	if _, err := run("flush", "--yes", "--vrf", "tenant-a"); err != nil || stub.flushed.VrfName != "tenant-a" || stub.flushed.AllVrfs {
		t.Errorf("flush = %v %v", stub.flushed, err)
	}
	if _, err := run("flush", "--yes"); err != nil || stub.flushed.VrfName != "" || stub.flushed.AllVrfs {
		t.Errorf("flush without a VRF = %v %v, want the global VRF", stub.flushed, err)
	}
	if _, err := run("flush", "--yes", "--all-vrfs"); err != nil || !stub.flushed.AllVrfs {
		t.Errorf("flush --all-vrfs = %v %v", stub.flushed, err)
	}
	if _, err := run("list"); err != nil || stub.listed.VrfName != "" || stub.listed.AllVrfs {
		t.Errorf("list without a VRF = %v %v, want the global VRF", stub.listed, err)
	}
	out, err := run("list", "--all-vrfs")
	if err != nil {
		t.Fatal(err)
	}
	if !stub.listed.AllVrfs {
		t.Error("list --all-vrfs did not ask for every VRF")
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 || strings.Fields(lines[0])[2] != "VRF" {
		t.Fatalf("list output:\n%s", out)
	}
	for i, want := range []string{"global", "tenant-a", "vrf_id=9"} {
		f := strings.Fields(lines[i+1])
		if f[0] != "10.0.0.0/24" || f[1] != want || f[len(f)-1] != "fc00::"+string(rune('a'+i)) {
			t.Errorf("row %d = %v, want VRF %s", i, f, want)
		}
	}
	if _, err := run("list", "--vrf", "global"); err != nil || stub.listed.VrfName != "global" {
		t.Errorf("list --vrf global = %v %v", stub.listed, err)
	}
}
