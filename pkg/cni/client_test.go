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
	vrfs      []*v1.Vrf
	creates   int
}

func (f *fakeVrfClient) VrfShow(context.Context, *connect.Request[v1.VrfShowRequest]) (*connect.Response[v1.VrfShowResponse], error) {
	return connect.NewResponse(&v1.VrfShowResponse{Vrfs: f.vrfs}), nil
}

func (f *fakeVrfClient) VrfCreate(context.Context, *connect.Request[v1.VrfCreateRequest]) (*connect.Response[v1.VrfCreateResponse], error) {
	f.creates++
	return connect.NewResponse(&v1.VrfCreateResponse{}), nil
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

// An existing VRF is left alone (VrfCreate would replace its device facet);
// another table is refused; a missing or deviceless VRF is created.
func TestEnsureVRF(t *testing.T) {
	for _, tc := range []struct {
		name    string
		vrfs    []*v1.Vrf
		creates int
		wantErr bool
	}{
		{"missing", nil, 1, false},
		{"deviceless", []*v1.Vrf{{Name: "tenant-a"}}, 1, false},
		{"same table", []*v1.Vrf{{Name: "tenant-a", TableId: 100, Ifindex: 7}}, 0, false},
		{"other table", []*v1.Vrf{{Name: "tenant-a", TableId: 200, Ifindex: 7}}, 0, true},
		{"other vrf", []*v1.Vrf{{Name: "tenant-b", TableId: 200, Ifindex: 7}}, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vrf := &fakeVrfClient{vrfs: tc.vrfs}
			d := &rpcDaemon{vrf: vrf, timeout: time.Second}
			err := d.EnsureVRF(context.Background(), "tenant-a", 100)
			if (err != nil) != tc.wantErr || vrf.creates != tc.creates {
				t.Errorf("err = %v, creates = %d, want creates %d", err, vrf.creates, tc.creates)
			}
		})
	}
}
