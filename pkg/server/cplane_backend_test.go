package server

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/cplane"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	"go.uber.org/zap"
)

type backendCapture struct {
	fakeCplane
	reg cplane.Registration
}

func (f *backendCapture) Register(_ context.Context, r cplane.Registration) error {
	f.reg = r
	return nil
}
func TestCplaneNativeRegistrationTransport(t *testing.T) {
	f := &backendCapture{}
	s := &PluginServer{cplane: f, logger: zap.NewNop()}
	_, err := s.CplanePluginRegister(context.Background(), connect.NewRequest(&v1.CplanePluginRegisterRequest{Name: "composition", Backend: "native", NativeId: "mup-composition", NativeVersion: "1"}))
	if err != nil {
		t.Fatal(err)
	}
	if f.reg.Backend != "native" || f.reg.NativeID != "mup-composition" || f.reg.NativeVersion != "1" || len(f.reg.Module) != 0 {
		t.Fatalf("native request lost: %+v", f.reg)
	}
	if code := connect.CodeOf(cplaneRPCError(cplane.ErrNativeDisabled)); code != connect.CodePermissionDenied {
		t.Fatal(code)
	}
	if code := connect.CodeOf(cplaneRPCError(wasm.ErrAdmission)); code != connect.CodeInvalidArgument {
		t.Fatal(code)
	}
}
