package cni

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"connectrpc.com/connect"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/api/vinbero/v1/vinberov1connect"
)

// Binding is the BGP binding the plugin creates for a VRF that has none.
type Binding struct {
	VRF         string
	RD          string
	RTs         []RouteTarget
	Locator     string
	MaxPrefixes uint32
}

// Daemon is the part of the vinberod API the plugin drives. Every call is
// idempotent, so a retried ADD or DEL converges.
type Daemon interface {
	// EnsureVRF creates the kernel VRF, or adopts it when it already
	// exists on the same table.
	EnsureVRF(ctx context.Context, name string, tableID uint32) error
	// EnsureBinding binds the VRF when it has no binding yet. An existing
	// binding is kept; it must use the same RD and redistribute static
	// routes.
	EnsureBinding(ctx context.Context, b Binding) error
	AddAC(ctx context.Context, vrf, ifname string) error
	RemoveAC(ctx context.Context, vrf, ifname string) error
	AttachDevice(ctx context.Context, ifname, mode string) error
	// DetachDevice succeeds when the device is not attached.
	DetachDevice(ctx context.Context, ifname string) error
	DeviceAttached(ctx context.Context, ifname string) (bool, error)
}

// rpcDaemon talks to vinberod over Connect RPC, like vbctl.
type rpcDaemon struct {
	vrf    vinberov1connect.VrfServiceClient
	vrfBgp vinberov1connect.VrfBgpServiceClient
	device vinberov1connect.DeviceServiceClient
}

// NewDaemon returns a Daemon for the vinberod at serverURL.
func NewDaemon(serverURL string) Daemon {
	c := http.DefaultClient
	return &rpcDaemon{
		vrf:    vinberov1connect.NewVrfServiceClient(c, serverURL),
		vrfBgp: vinberov1connect.NewVrfBgpServiceClient(c, serverURL),
		device: vinberov1connect.NewDeviceServiceClient(c, serverURL),
	}
}

func opErrors(errs []*v1.OperationError) error {
	if len(errs) == 0 {
		return nil
	}
	reasons := make([]string, 0, len(errs))
	for _, e := range errs {
		reasons = append(reasons, e.GetReason())
	}
	return fmt.Errorf("%s", strings.Join(reasons, "; "))
}

func (d *rpcDaemon) EnsureVRF(ctx context.Context, name string, tableID uint32) error {
	resp, err := d.vrf.VrfCreate(ctx, connect.NewRequest(&v1.VrfCreateRequest{
		Vrfs: []*v1.Vrf{{Name: name, TableId: tableID}},
	}))
	if err != nil {
		return fmt.Errorf("VrfCreate %s: %w", name, err)
	}
	if err := opErrors(resp.Msg.GetErrors()); err != nil {
		return fmt.Errorf("VrfCreate %s (table %d): %w", name, tableID, err)
	}
	return nil
}

func (d *rpcDaemon) EnsureBinding(ctx context.Context, b Binding) error {
	list, err := d.vrfBgp.VrfBgpList(ctx, connect.NewRequest(&v1.VrfBgpListRequest{}))
	if err != nil {
		return fmt.Errorf("VrfBgpList: %w", err)
	}
	for _, cur := range list.Msg.GetBindings() {
		if cur.GetVrfName() == b.VRF {
			return checkBinding(cur, b)
		}
	}
	families := make(map[string]*v1.VrfBgpFamily)
	for _, rt := range b.RTs {
		f := families[rt.Family]
		if f == nil {
			f = &v1.VrfBgpFamily{}
			families[rt.Family] = f
		}
		f.RouteTargets = append(f.RouteTargets, &v1.VrfBgpRouteTarget{Rt: rt.RT, Direction: rt.Direction})
	}
	resp, err := d.vrfBgp.VrfBgpBind(ctx, connect.NewRequest(&v1.VrfBgpBindRequest{
		Bindings: []*v1.VrfBgpBinding{{
			VrfName:        b.VRF,
			Rd:             b.RD,
			DefaultLocator: b.Locator,
			Redistribute:   []string{"static"},
			MaxPrefixes:    b.MaxPrefixes,
			Families:       families,
		}},
	}))
	if err != nil {
		return fmt.Errorf("VrfBgpBind %s: %w", b.VRF, err)
	}
	if err := opErrors(resp.Msg.GetErrors()); err != nil {
		return fmt.Errorf("VrfBgpBind %s: %w", b.VRF, err)
	}
	return nil
}

// checkBinding refuses an existing binding the pod routes would not be
// advertised through as configured. The plugin never rewrites a binding: it
// may come from the vinberod config or another network.
func checkBinding(cur *v1.VrfBgpBinding, want Binding) error {
	if cur.GetRd() != want.RD {
		return fmt.Errorf("vrf %s is already bound with rd %q, the network configuration says %q", want.VRF, cur.GetRd(), want.RD)
	}
	if cur.GetDefaultLocator() != want.Locator {
		return fmt.Errorf("vrf %s is already bound with locator %q, the network configuration says %q", want.VRF, cur.GetDefaultLocator(), want.Locator)
	}
	if !slices.Contains(cur.GetRedistribute(), "static") {
		return fmt.Errorf("vrf %s is bound without redistribute static, so pod routes would not be advertised", want.VRF)
	}
	return nil
}

func (d *rpcDaemon) AddAC(ctx context.Context, vrf, ifname string) error {
	_, err := d.vrf.VrfAcAdd(ctx, connect.NewRequest(&v1.VrfAcAddRequest{
		Name: vrf, Ac: &v1.VrfAc{InterfaceName: ifname},
	}))
	if err != nil {
		return fmt.Errorf("VrfAcAdd %s/%s: %w", vrf, ifname, err)
	}
	return nil
}

func (d *rpcDaemon) RemoveAC(ctx context.Context, vrf, ifname string) error {
	_, err := d.vrf.VrfAcRemove(ctx, connect.NewRequest(&v1.VrfAcRemoveRequest{
		Name: vrf, Ac: &v1.VrfAc{InterfaceName: ifname},
	}))
	if err != nil {
		return fmt.Errorf("VrfAcRemove %s/%s: %w", vrf, ifname, err)
	}
	return nil
}

func (d *rpcDaemon) AttachDevice(ctx context.Context, ifname, mode string) error {
	_, err := d.device.DeviceAttach(ctx, connect.NewRequest(&v1.DeviceAttachRequest{Name: ifname, Mode: mode}))
	if err != nil {
		return fmt.Errorf("DeviceAttach %s: %w", ifname, err)
	}
	return nil
}

func (d *rpcDaemon) DetachDevice(ctx context.Context, ifname string) error {
	_, err := d.device.DeviceDetach(ctx, connect.NewRequest(&v1.DeviceDetachRequest{Name: ifname}))
	if err != nil && connect.CodeOf(err) != connect.CodeNotFound {
		return fmt.Errorf("DeviceDetach %s: %w", ifname, err)
	}
	return nil
}

func (d *rpcDaemon) DeviceAttached(ctx context.Context, ifname string) (bool, error) {
	resp, err := d.device.DeviceList(ctx, connect.NewRequest(&v1.DeviceListRequest{}))
	if err != nil {
		return false, fmt.Errorf("DeviceList: %w", err)
	}
	return slices.ContainsFunc(resp.Msg.GetDevices(), func(dev *v1.Device) bool {
		return dev.GetName() == ifname
	}), nil
}
