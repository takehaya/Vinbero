package cni

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

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
	// Redistribute is the redistribution list the binding must carry. L3
	// mode sets ["static"] (the pod /32s are redistributed as VPNv4); L2
	// mode leaves it nil (EVPN RT2 comes from MAC learning, not a route
	// table).
	Redistribute []string
}

// Daemon is the part of the vinberod API the plugin drives. Every call is
// idempotent, so a retried ADD or DEL converges.
type Daemon interface {
	// EnsureVRF creates the kernel VRF unless vinberod already has it on
	// the same table; another table is an error.
	EnsureVRF(ctx context.Context, name string, tableID uint32) error
	// EnsureBinding binds the VRF when it has no binding yet. An existing
	// binding is kept; it must use the same RD and the binding's
	// redistribution list.
	EnsureBinding(ctx context.Context, b Binding) error
	AddAC(ctx context.Context, vrf, ifname string) error
	RemoveAC(ctx context.Context, vrf, ifname string) error
	AttachDevice(ctx context.Context, ifname, mode string) error
	// DetachDevice succeeds when the device is not attached.
	DetachDevice(ctx context.Context, ifname string) error
	DeviceAttached(ctx context.Context, ifname string) (bool, error)

	// --- L2 mode ---
	// EnsureBridgeDomain verifies that the VRF carries the pre-declared
	// bridge facet with the given bd_id. The plugin never creates or
	// destroys a bridge domain, so a missing or mismatched facet is an
	// error the operator fixes in the node's vinberod config.
	EnsureBridgeDomain(ctx context.Context, vrf, bridge string, bdID uint32) error
	AddBridgeMember(ctx context.Context, vrf, ifname string) error
	// RemoveBridgeMember succeeds when the port is not a member.
	RemoveBridgeMember(ctx context.Context, vrf, ifname string) error
	// CreateL2Circuit registers the port as a BD circuit (headend_l2 with
	// bd_id; source and segments come from the peer, so they are omitted).
	CreateL2Circuit(ctx context.Context, ifname string, bdID uint32) error
	// DeleteL2Circuit succeeds when the circuit is already gone.
	DeleteL2Circuit(ctx context.Context, ifname string) error
	// L2CircuitPresent reports whether the port has a BD circuit for bd_id.
	L2CircuitPresent(ctx context.Context, ifname string, bdID uint32) (bool, error)
}

// rpcDaemon talks to vinberod over Connect RPC, like vbctl. Each RPC gets its
// own timeout, so a hung one fails alone instead of using up the time of
// the calls after it, and a hung daemon fails the CNI command instead of
// blocking the runtime.
type rpcDaemon struct {
	vrf     vinberov1connect.VrfServiceClient
	vrfBgp  vinberov1connect.VrfBgpServiceClient
	device  vinberov1connect.DeviceServiceClient
	hl2     vinberov1connect.HeadendL2ServiceClient
	timeout time.Duration
}

func (d *rpcDaemon) bound(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, d.timeout)
}

// NewDaemon returns a Daemon for the vinberod at serverURL.
func NewDaemon(serverURL string) Daemon {
	c := http.DefaultClient
	return &rpcDaemon{
		vrf:     vinberov1connect.NewVrfServiceClient(c, serverURL),
		vrfBgp:  vinberov1connect.NewVrfBgpServiceClient(c, serverURL),
		device:  vinberov1connect.NewDeviceServiceClient(c, serverURL),
		hl2:     vinberov1connect.NewHeadendL2ServiceClient(c, serverURL),
		timeout: rpcTimeout,
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
	showCtx, cancelShow := d.bound(ctx)
	defer cancelShow()
	show, err := d.vrf.VrfShow(showCtx, connect.NewRequest(&v1.VrfShowRequest{}))
	if err != nil {
		return fmt.Errorf("VrfShow: %w", err)
	}
	// VrfCreate on an existing VRF replaces its device facet with the
	// request's and writes the state file, so it only runs when needed.
	for _, v := range show.Msg.GetVrfs() {
		if v.GetName() != name || v.GetIfindex() == 0 {
			continue
		}
		if v.GetTableId() != tableID {
			return fmt.Errorf("vrf %s exists with table %d, the network configuration says %d", name, v.GetTableId(), tableID)
		}
		return nil
	}
	ctx, cancel := d.bound(ctx)
	defer cancel()
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
	listCtx, cancel := d.bound(ctx)
	defer cancel()
	list, err := d.vrfBgp.VrfBgpList(listCtx, connect.NewRequest(&v1.VrfBgpListRequest{}))
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
	bindCtx, cancelBind := d.bound(ctx)
	defer cancelBind()
	resp, err := d.vrfBgp.VrfBgpBind(bindCtx, connect.NewRequest(&v1.VrfBgpBindRequest{
		Bindings: []*v1.VrfBgpBinding{{
			VrfName:        b.VRF,
			Rd:             b.RD,
			DefaultLocator: b.Locator,
			Redistribute:   b.Redistribute,
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
// advertised through as configured: another RD, locator, route targets or
// prefix limit, or no redistribution of static routes. The plugin never rewrites a binding: it
// may come from the vinberod config or another network.
func checkBinding(cur *v1.VrfBgpBinding, want Binding) error {
	if cur.GetRd() != want.RD {
		return fmt.Errorf("vrf %s is already bound with rd %q, the network configuration says %q", want.VRF, cur.GetRd(), want.RD)
	}
	if cur.GetDefaultLocator() != want.Locator {
		return fmt.Errorf("vrf %s is already bound with locator %q, the network configuration says %q", want.VRF, cur.GetDefaultLocator(), want.Locator)
	}
	for _, r := range want.Redistribute {
		if !slices.Contains(cur.GetRedistribute(), r) {
			return fmt.Errorf("vrf %s is bound without redistribute %s, so pod routes would not be advertised", want.VRF, r)
		}
	}
	if want.MaxPrefixes != 0 && cur.GetMaxPrefixes() != want.MaxPrefixes {
		return fmt.Errorf("vrf %s is already bound with maxPrefixes %d, the network configuration says %d", want.VRF, cur.GetMaxPrefixes(), want.MaxPrefixes)
	}
	return checkRouteTargets(cur, want)
}

const (
	rtImport = 1 << iota
	rtExport
)

// rtDirection maps a direction to its bits; empty means both.
func rtDirection(direction string) int {
	switch direction {
	case "import":
		return rtImport
	case "export":
		return rtExport
	default:
		return rtImport | rtExport
	}
}

// checkRouteTargets compares the route targets of every family the network
// configuration names. Families it does not name are left to the binding.
func checkRouteTargets(cur *v1.VrfBgpBinding, want Binding) error {
	wanted := make(map[string]map[string]int)
	for _, rt := range want.RTs {
		if wanted[rt.Family] == nil {
			wanted[rt.Family] = make(map[string]int)
		}
		wanted[rt.Family][rt.RT] |= rtDirection(rt.Direction)
	}
	for family, rts := range wanted {
		have := make(map[string]int)
		for _, rt := range cur.GetFamilies()[family].GetRouteTargets() {
			have[rt.GetRt()] |= rtDirection(rt.GetDirection())
		}
		if !maps.Equal(have, rts) {
			return fmt.Errorf("vrf %s is already bound with other %s route targets than the network configuration says", want.VRF, family)
		}
	}
	return nil
}

func (d *rpcDaemon) AddAC(ctx context.Context, vrf, ifname string) error {
	ctx, cancel := d.bound(ctx)
	defer cancel()
	_, err := d.vrf.VrfAcAdd(ctx, connect.NewRequest(&v1.VrfAcAddRequest{
		Name: vrf, Ac: &v1.VrfAc{InterfaceName: ifname},
	}))
	if err != nil {
		return fmt.Errorf("VrfAcAdd %s/%s: %w", vrf, ifname, err)
	}
	return nil
}

func (d *rpcDaemon) RemoveAC(ctx context.Context, vrf, ifname string) error {
	ctx, cancel := d.bound(ctx)
	defer cancel()
	_, err := d.vrf.VrfAcRemove(ctx, connect.NewRequest(&v1.VrfAcRemoveRequest{
		Name: vrf, Ac: &v1.VrfAc{InterfaceName: ifname},
	}))
	if err != nil {
		return fmt.Errorf("VrfAcRemove %s/%s: %w", vrf, ifname, err)
	}
	return nil
}

func (d *rpcDaemon) AttachDevice(ctx context.Context, ifname, mode string) error {
	ctx, cancel := d.bound(ctx)
	defer cancel()
	_, err := d.device.DeviceAttach(ctx, connect.NewRequest(&v1.DeviceAttachRequest{Name: ifname, Mode: mode}))
	if err != nil {
		return fmt.Errorf("DeviceAttach %s: %w", ifname, err)
	}
	return nil
}

func (d *rpcDaemon) DetachDevice(ctx context.Context, ifname string) error {
	ctx, cancel := d.bound(ctx)
	defer cancel()
	_, err := d.device.DeviceDetach(ctx, connect.NewRequest(&v1.DeviceDetachRequest{Name: ifname}))
	if err != nil && connect.CodeOf(err) != connect.CodeNotFound {
		return fmt.Errorf("DeviceDetach %s: %w", ifname, err)
	}
	return nil
}

func (d *rpcDaemon) DeviceAttached(ctx context.Context, ifname string) (bool, error) {
	ctx, cancel := d.bound(ctx)
	defer cancel()
	resp, err := d.device.DeviceList(ctx, connect.NewRequest(&v1.DeviceListRequest{}))
	if err != nil {
		return false, fmt.Errorf("DeviceList: %w", err)
	}
	return slices.ContainsFunc(resp.Msg.GetDevices(), func(dev *v1.Device) bool {
		return dev.GetName() == ifname
	}), nil
}

// EnsureBridgeDomain verifies the pre-declared bridge facet is on the VRF
// with the configured bd_id. The plugin does not create bridge domains, so a
// missing or mismatched facet is a node-configuration error.
func (d *rpcDaemon) EnsureBridgeDomain(ctx context.Context, vrf, bridge string, bdID uint32) error {
	ctx, cancel := d.bound(ctx)
	defer cancel()
	show, err := d.vrf.VrfShow(ctx, connect.NewRequest(&v1.VrfShowRequest{}))
	if err != nil {
		return fmt.Errorf("VrfShow: %w", err)
	}
	for _, v := range show.Msg.GetVrfs() {
		if v.GetName() != vrf {
			continue
		}
		br := v.GetBridge()
		if br == nil {
			return fmt.Errorf("vrf %s has no bridge domain; declare it in the vinberod config (vrfs.entries[].bridge)", vrf)
		}
		if br.GetName() != bridge {
			return fmt.Errorf("vrf %s has bridge %q, the network configuration says %q", vrf, br.GetName(), bridge)
		}
		if br.GetBdId() != bdID {
			return fmt.Errorf("vrf %s bridge %s has bd_id %d, the network configuration says %d", vrf, bridge, br.GetBdId(), bdID)
		}
		return nil
	}
	return fmt.Errorf("vrf %s does not exist; declare it and its bridge domain in the vinberod config", vrf)
}

func (d *rpcDaemon) AddBridgeMember(ctx context.Context, vrf, ifname string) error {
	ctx, cancel := d.bound(ctx)
	defer cancel()
	_, err := d.vrf.VrfBridgeMemberAdd(ctx, connect.NewRequest(&v1.VrfBridgeMemberAddRequest{
		VrfName: vrf, InterfaceName: ifname,
	}))
	if err != nil {
		return fmt.Errorf("VrfBridgeMemberAdd %s/%s: %w", vrf, ifname, err)
	}
	return nil
}

func (d *rpcDaemon) RemoveBridgeMember(ctx context.Context, vrf, ifname string) error {
	ctx, cancel := d.bound(ctx)
	defer cancel()
	_, err := d.vrf.VrfBridgeMemberRemove(ctx, connect.NewRequest(&v1.VrfBridgeMemberRemoveRequest{
		VrfName: vrf, InterfaceName: ifname,
	}))
	// A port that is gone, or not a member, succeeds (see the RPC contract).
	if err != nil && connect.CodeOf(err) != connect.CodeNotFound {
		return fmt.Errorf("VrfBridgeMemberRemove %s/%s: %w", vrf, ifname, err)
	}
	return nil
}

func (d *rpcDaemon) CreateL2Circuit(ctx context.Context, ifname string, bdID uint32) error {
	ctx, cancel := d.bound(ctx)
	defer cancel()
	resp, err := d.hl2.HeadendL2Create(ctx, connect.NewRequest(&v1.HeadendL2CreateRequest{
		HeadendL2S: []*v1.HeadendL2{{InterfaceName: ifname, VlanId: 0, BdId: bdID}},
	}))
	if err != nil {
		return fmt.Errorf("HeadendL2Create %s bd %d: %w", ifname, bdID, err)
	}
	if err := opErrors(resp.Msg.GetErrors()); err != nil {
		return fmt.Errorf("HeadendL2Create %s bd %d: %w", ifname, bdID, err)
	}
	return nil
}

func (d *rpcDaemon) DeleteL2Circuit(ctx context.Context, ifname string) error {
	ctx, cancel := d.bound(ctx)
	defer cancel()
	resp, err := d.hl2.HeadendL2Delete(ctx, connect.NewRequest(&v1.HeadendL2DeleteRequest{
		Targets: []*v1.HeadendL2DeleteTarget{{InterfaceName: ifname, VlanId: 0}},
	}))
	if err != nil {
		return fmt.Errorf("HeadendL2Delete %s: %w", ifname, err)
	}
	// A circuit the link watcher already swept, or one on a vanished
	// interface, comes back as ReasonNotFound: that is the teardown's goal.
	for _, e := range resp.Msg.GetErrors() {
		if !strings.Contains(e.GetReason(), v1.ReasonNotFound) {
			return fmt.Errorf("HeadendL2Delete %s: %s", ifname, e.GetReason())
		}
	}
	return nil
}

func (d *rpcDaemon) L2CircuitPresent(ctx context.Context, ifname string, bdID uint32) (bool, error) {
	ctx, cancel := d.bound(ctx)
	defer cancel()
	resp, err := d.hl2.HeadendL2List(ctx, connect.NewRequest(&v1.HeadendL2ListRequest{}))
	if err != nil {
		return false, fmt.Errorf("HeadendL2List: %w", err)
	}
	return slices.ContainsFunc(resp.Msg.GetHeadendL2S(), func(h *v1.HeadendL2) bool {
		return h.GetInterfaceName() == ifname && h.GetVlanId() == 0 && h.GetBdId() == bdID
	}), nil
}
