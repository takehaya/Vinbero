package cni

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/api/vinbero/v1/vinberov1connect"
)

type fakeVrfClient struct {
	vinberov1connect.VrfServiceClient
	removeErr error // the context error VrfAcRemove saw
}

func (f *fakeVrfClient) VrfAcRemove(ctx context.Context, _ *connect.Request[v1.VrfAcRemoveRequest]) (*connect.Response[v1.VrfAcRemoveResponse], error) {
	f.removeErr = ctx.Err()
	return connect.NewResponse(&v1.VrfAcRemoveResponse{}), nil
}

type hungDeviceClient struct {
	vinberov1connect.DeviceServiceClient
}

func (hungDeviceClient) DeviceDetach(ctx context.Context, _ *connect.Request[v1.DeviceDetachRequest]) (*connect.Response[v1.DeviceDetachResponse], error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// A hung RPC fails alone: the next one gets its own time budget.
func TestRPCTimeoutIsPerCall(t *testing.T) {
	vrf := &fakeVrfClient{}
	d := &rpcDaemon{vrf: vrf, device: hungDeviceClient{}, timeout: 20 * time.Millisecond}
	ctx := context.Background()
	if err := d.DetachDevice(ctx, "vb0"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DetachDevice = %v, want DeadlineExceeded", err)
	}
	if err := d.RemoveAC(ctx, "tenant-a", "vb0"); err != nil {
		t.Fatalf("RemoveAC: %v", err)
	}
	if vrf.removeErr != nil {
		t.Errorf("RemoveAC ran with a spent context: %v", vrf.removeErr)
	}
}
