package server

import (
	"context"
	"fmt"
	"testing"

	"connectrpc.com/connect"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/vinbero"
)

type fakeAttacher struct {
	attachErr error
	detachErr error
	calls     []string
	devices   []vinbero.Device
}

func (f *fakeAttacher) AttachDevice(name, mode string) (vinbero.Device, error) {
	f.calls = append(f.calls, "attach:"+name+":"+mode)
	if f.attachErr != nil {
		return vinbero.Device{}, f.attachErr
	}
	if mode == "" {
		mode = "driver"
	}
	return vinbero.Device{Name: name, Ifindex: 7, Mode: mode}, nil
}

func (f *fakeAttacher) DetachDevice(name string) error {
	f.calls = append(f.calls, "detach:"+name)
	return f.detachErr
}

func (f *fakeAttacher) ListDevices() []vinbero.Device { return f.devices }

func TestDeviceServer_Attach(t *testing.T) {
	a := &fakeAttacher{}
	s := NewDeviceServer(a)
	resp, err := s.DeviceAttach(context.Background(), connect.NewRequest(&v1.DeviceAttachRequest{Name: "veth1", Mode: "generic"}))
	if err != nil {
		t.Fatalf("DeviceAttach: %v", err)
	}
	if d := resp.Msg.GetDevice(); d.GetName() != "veth1" || d.GetIfindex() != 7 || d.GetMode() != "generic" || d.GetConfig() {
		t.Errorf("device = %+v", d)
	}

	for _, name := range []string{"", "a-name-past-15-bytes", "a/b", "a b", "..", "a:1"} {
		_, err := s.DeviceAttach(context.Background(), connect.NewRequest(&v1.DeviceAttachRequest{Name: name}))
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("DeviceAttach(%q) = %v, want InvalidArgument", name, err)
		}
		_, err = s.DeviceDetach(context.Background(), connect.NewRequest(&v1.DeviceDetachRequest{Name: name}))
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("DeviceDetach(%q) = %v, want InvalidArgument", name, err)
		}
	}
	if len(a.calls) != 1 {
		t.Errorf("invalid names reached the attacher: %v", a.calls)
	}
}

// The attacher's sentinel errors map to status codes a client can act on.
func TestDeviceServer_ErrorCodes(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code connect.Code
	}{
		{fmt.Errorf("wrap: %w", vinbero.ErrInvalidMode), connect.CodeInvalidArgument},
		{fmt.Errorf("wrap: %w", vinbero.ErrNoInterface), connect.CodeNotFound},
		{fmt.Errorf("wrap: %w", vinbero.ErrNotAttached), connect.CodeNotFound},
		{fmt.Errorf("wrap: %w", vinbero.ErrModeConflict), connect.CodeFailedPrecondition},
		{fmt.Errorf("wrap: %w", vinbero.ErrConfigDevice), connect.CodeFailedPrecondition},
		{fmt.Errorf("EBUSY"), connect.CodeInternal},
	} {
		s := NewDeviceServer(&fakeAttacher{attachErr: tc.err, detachErr: tc.err})
		_, err := s.DeviceAttach(context.Background(), connect.NewRequest(&v1.DeviceAttachRequest{Name: "veth1"}))
		if connect.CodeOf(err) != tc.code {
			t.Errorf("attach %v: code %v, want %v", tc.err, connect.CodeOf(err), tc.code)
		}
		_, err = s.DeviceDetach(context.Background(), connect.NewRequest(&v1.DeviceDetachRequest{Name: "veth1"}))
		if connect.CodeOf(err) != tc.code {
			t.Errorf("detach %v: code %v, want %v", tc.err, connect.CodeOf(err), tc.code)
		}
	}
}

func TestDeviceServer_List(t *testing.T) {
	s := NewDeviceServer(&fakeAttacher{devices: []vinbero.Device{
		{Name: "eth0", Ifindex: 2, Mode: "driver", Config: true},
		{Name: "veth1", Ifindex: 9, Mode: "generic"},
	}})
	resp, err := s.DeviceList(context.Background(), connect.NewRequest(&v1.DeviceListRequest{}))
	if err != nil {
		t.Fatalf("DeviceList: %v", err)
	}
	got := resp.Msg.GetDevices()
	if len(got) != 2 || !got[0].GetConfig() || got[1].GetName() != "veth1" || got[1].GetIfindex() != 9 {
		t.Errorf("devices = %v", got)
	}
}

func TestDeviceServer_NoAttacher(t *testing.T) {
	s := NewDeviceServer(nil)
	if _, err := s.DeviceAttach(context.Background(), connect.NewRequest(&v1.DeviceAttachRequest{Name: "veth1"})); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Errorf("attach without attacher = %v", err)
	}
	if _, err := s.DeviceList(context.Background(), connect.NewRequest(&v1.DeviceListRequest{})); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Errorf("list without attacher = %v", err)
	}
}
