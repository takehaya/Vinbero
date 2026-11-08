package server

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/vinbero"
)

// DeviceAttacher is the data-plane surface DeviceService drives.
// *vinbero.Vinbero satisfies it; tests use a fake.
type DeviceAttacher interface {
	AttachDevice(name, mode string) (vinbero.Device, error)
	DetachDevice(name string) error
	ListDevices() []vinbero.Device
}

// DeviceServer is the Connect RPC handler for DeviceService. The attacher
// serializes attach / detach itself, so the handler holds no lock.
type DeviceServer struct {
	attacher DeviceAttacher
}

// NewDeviceServer wires the handler. A nil attacher makes every RPC return
// Unimplemented.
func NewDeviceServer(attacher DeviceAttacher) *DeviceServer {
	return &DeviceServer{attacher: attacher}
}

// maxIfnameLen is IFNAMSIZ minus the terminating NUL.
const maxIfnameLen = 15

// validateIfname rejects names the kernel can never accept, so a typo comes
// back as InvalidArgument instead of NotFound.
func validateIfname(name string) error {
	switch {
	case name == "":
		return errors.New("name is required")
	case len(name) > maxIfnameLen:
		return fmt.Errorf("interface name %q is longer than %d bytes", name, maxIfnameLen)
	case name == "." || name == "..", strings.ContainsAny(name, "/: \t\n"):
		return fmt.Errorf("invalid interface name %q", name)
	}
	return nil
}

func (s *DeviceServer) unavailable() error {
	if s.attacher == nil {
		return connect.NewError(connect.CodeUnimplemented, errors.New("device attach is not available"))
	}
	return nil
}

func (s *DeviceServer) DeviceAttach(
	_ context.Context,
	req *connect.Request[v1.DeviceAttachRequest],
) (*connect.Response[v1.DeviceAttachResponse], error) {
	if err := s.unavailable(); err != nil {
		return nil, err
	}
	if err := validateIfname(req.Msg.GetName()); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	d, err := s.attacher.AttachDevice(req.Msg.GetName(), req.Msg.GetMode())
	if err != nil {
		return nil, deviceError(err)
	}
	return connect.NewResponse(&v1.DeviceAttachResponse{Device: deviceToProto(d)}), nil
}

func (s *DeviceServer) DeviceDetach(
	_ context.Context,
	req *connect.Request[v1.DeviceDetachRequest],
) (*connect.Response[v1.DeviceDetachResponse], error) {
	if err := s.unavailable(); err != nil {
		return nil, err
	}
	if err := validateIfname(req.Msg.GetName()); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := s.attacher.DetachDevice(req.Msg.GetName()); err != nil {
		return nil, deviceError(err)
	}
	return connect.NewResponse(&v1.DeviceDetachResponse{}), nil
}

func (s *DeviceServer) DeviceList(
	_ context.Context,
	_ *connect.Request[v1.DeviceListRequest],
) (*connect.Response[v1.DeviceListResponse], error) {
	if err := s.unavailable(); err != nil {
		return nil, err
	}
	devs := s.attacher.ListDevices()
	out := make([]*v1.Device, 0, len(devs))
	for _, d := range devs {
		out = append(out, deviceToProto(d))
	}
	return connect.NewResponse(&v1.DeviceListResponse{Devices: out}), nil
}

// deviceError maps the attacher's errors to status codes; anything else is
// a kernel or state-file failure.
func deviceError(err error) error {
	code := connect.CodeInternal
	switch {
	case errors.Is(err, vinbero.ErrInvalidMode):
		code = connect.CodeInvalidArgument
	case errors.Is(err, vinbero.ErrNoInterface), errors.Is(err, vinbero.ErrNotAttached):
		code = connect.CodeNotFound
	case errors.Is(err, vinbero.ErrModeConflict), errors.Is(err, vinbero.ErrConfigDevice):
		code = connect.CodeFailedPrecondition
	}
	return connect.NewError(code, err)
}

func deviceToProto(d vinbero.Device) *v1.Device {
	return &v1.Device{Name: d.Name, Ifindex: uint32(d.Ifindex), Mode: d.Mode, Config: d.Config}
}
