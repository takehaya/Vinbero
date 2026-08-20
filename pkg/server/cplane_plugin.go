package server

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"connectrpc.com/connect"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bgp/demux"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/cplane"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
)

// CplaneManager is the control-plane plugin manager the RPC handlers drive.
// It is an interface so the server can be built without one -- a daemon
// with control-plane plugins disabled answers these calls with
// Unimplemented rather than carrying a runtime it never uses.
type CplaneManager interface {
	Register(ctx context.Context, reg cplane.Registration) error
	Unregister(ctx context.Context, name string) error
	List() []string
	Stats() []cplane.PluginStats
	StatsFor(name string) (cplane.PluginStats, bool)
	// Unrestored and Forget cover the plugins the store held that would
	// not start: they are not running, so nothing else here reports them,
	// yet the daemon still holds their state and their claims.
	Unrestored() []cplane.UnrestoredPlugin
	Forget(name string) error
	// ReconcileAdvertised re-derives what every plugin originates. A
	// plugin names a VRF and the host fills in the route distinguisher,
	// the route targets and the cap from that VRF's binding, so an
	// operator editing a binding has to reach the plugins that took
	// values from it.
	ReconcileAdvertised(ctx context.Context)
}

// SetCplaneManager installs the manager. Call before Setup, like the other
// optional dependencies.
func (s *PluginServer) SetCplaneManager(m CplaneManager) {
	s.cplane = m
}

// CplanePluginRegister starts or upgrades a control-plane plugin.
func (s *PluginServer) CplanePluginRegister(
	ctx context.Context,
	req *connect.Request[v1.CplanePluginRegisterRequest],
) (*connect.Response[v1.CplanePluginRegisterResponse], error) {
	if s.cplane == nil {
		return nil, connect.NewError(connect.CodeUnimplemented,
			errors.New("control-plane plugins are not enabled on this daemon"))
	}
	msg := req.Msg

	// Whether this is an upgrade is decided before the register, so the
	// answer describes what the operator's call did rather than the state
	// it happened to observe afterwards.
	replaced := false
	for _, name := range s.cplane.List() {
		if name == msg.GetName() {
			replaced = true
			break
		}
	}

	families, err := parseFamilies(msg.GetFamilies())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	behaviors, err := parseBehaviors(msg.GetEndpointBehaviors())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	caps, err := wasm.ParseCapabilities(msg.GetCapabilities())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	// The wire form is parsed into the canonical Scope here, at the
	// transport boundary; whether the scope covers the capabilities is a
	// domain rule checked inside Manager.Register, so it holds on the
	// restore path too and not only for an operator's RPC.
	scope, err := cplane.ParseScope(cplane.ScopeSpec{
		Locators:        msg.GetScope().GetLocators(),
		VRFs:            msg.GetScope().GetVrfs(),
		HeadendPrefixes: msg.GetScope().GetHeadendPrefixes(),
		HeadendV4Slots:  msg.GetScope().GetHeadendV4Slots(),
		HeadendV6Slots:  msg.GetScope().GetHeadendV6Slots(),
		EndpointSlots:   msg.GetScope().GetEndpointSlots(),
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	reg := cplane.Registration{
		Name:         msg.GetName(),
		Module:       msg.GetWasm(),
		Config:       msg.GetConfig(),
		Families:     families,
		Behaviors:    behaviors,
		Capabilities: caps,
		Scope:        scope,
		TickInterval: time.Duration(msg.GetTickIntervalMs()) * time.Millisecond,
	}
	if err := s.cplane.Register(ctx, reg); err != nil {
		return nil, cplaneRPCError(err)
	}
	s.logger.Info("registered control-plane plugin",
		zap.String("plugin", msg.GetName()),
		zap.Bool("replaced", replaced))
	return connect.NewResponse(&v1.CplanePluginRegisterResponse{Replaced: replaced}), nil
}

// CplanePluginUnregister stops a plugin and removes the state it owns.
func (s *PluginServer) CplanePluginUnregister(
	ctx context.Context,
	req *connect.Request[v1.CplanePluginUnregisterRequest],
) (*connect.Response[v1.CplanePluginUnregisterResponse], error) {
	if s.cplane == nil {
		return nil, connect.NewError(connect.CodeUnimplemented,
			errors.New("control-plane plugins are not enabled on this daemon"))
	}
	if err := s.cplane.Unregister(ctx, req.Msg.GetName()); err != nil {
		return nil, cplaneRPCError(err)
	}
	s.logger.Info("unregistered control-plane plugin", zap.String("plugin", req.Msg.GetName()))
	return connect.NewResponse(&v1.CplanePluginUnregisterResponse{}), nil
}

// CplanePluginList enumerates the running plugins, sorted by name so a
// caller can diff two snapshots.
func (s *PluginServer) CplanePluginList(
	_ context.Context,
	_ *connect.Request[v1.CplanePluginListRequest],
) (*connect.Response[v1.CplanePluginListResponse], error) {
	if s.cplane == nil {
		return nil, connect.NewError(connect.CodeUnimplemented,
			errors.New("control-plane plugins are not enabled on this daemon"))
	}
	names := s.cplane.List()
	sort.Strings(names)
	out := make([]*v1.CplanePluginInfo, 0, len(names))
	for _, name := range names {
		out = append(out, &v1.CplanePluginInfo{Name: name})
	}
	return connect.NewResponse(&v1.CplanePluginListResponse{Plugins: out}), nil
}

// CplanePluginStats reports what each running plugin is doing and
// holding.
func (s *PluginServer) CplanePluginStats(
	_ context.Context,
	req *connect.Request[v1.CplanePluginStatsRequest],
) (*connect.Response[v1.CplanePluginStatsResponse], error) {
	if s.cplane == nil {
		return nil, connect.NewError(connect.CodeUnimplemented,
			errors.New("control-plane plugins are not enabled on this daemon"))
	}
	var stats []cplane.PluginStats
	if name := req.Msg.GetName(); name != "" {
		one, ok := s.cplane.StatsFor(name)
		if !ok {
			return nil, connect.NewError(connect.CodeNotFound,
				fmt.Errorf("plugin %q is not registered", name))
		}
		stats = []cplane.PluginStats{one}
	} else {
		stats = s.cplane.Stats()
	}

	out := make([]*v1.CplanePluginStat, 0, len(stats))
	for _, st := range stats {
		behaviors := make([]uint32, 0, len(st.Behaviors))
		for _, b := range st.Behaviors {
			behaviors = append(behaviors, uint32(b))
		}
		out = append(out, &v1.CplanePluginStat{
			Name:                st.Name,
			Capabilities:        st.Capabilities,
			EndpointBehaviors:   behaviors,
			DroppedEvents:       st.DroppedEvents,
			Restarts:            uint32(st.Restarts),
			QuarantinedEvents:   st.Quarantined,
			Snapshots:           st.Snapshots,
			Dead:                st.Dead,
			HeadendEntries:      uint32(st.HeadendEntries),
			AdvertisedRoutes:    uint32(st.AdvertisedRoutes),
			LocalSids:           uint32(st.LocalSIDs),
			MaxHeadendEntries:   uint32(st.Quotas.MaxHeadendEntries),
			MaxAdvertisedRoutes: uint32(st.Quotas.MaxAdvertisedRoutes),
			MaxLocalSids:        uint32(st.Quotas.MaxLocalSIDs),
			Since:               timestamppb.New(st.Since),
			PendingDeclarations: uint32(st.PendingDeclarations),
			Scope: &v1.CplanePluginScope{
				Locators:        st.Scope.Locators,
				Vrfs:            st.Scope.VRFs,
				HeadendPrefixes: st.Scope.HeadendPrefixStrings(),
				HeadendV4Slots:  st.Scope.HeadendV4Slots,
				HeadendV6Slots:  st.Scope.HeadendV6Slots,
				EndpointSlots:   st.Scope.EndpointSlots,
			},
		})
	}

	// The plugins that would not start go out alongside the running ones.
	// The daemon is still holding their state and their claims, and a
	// response that showed only what is running would let an operator
	// conclude they are simply gone.
	var unrestored []*v1.UnrestoredCplanePlugin
	if req.Msg.GetName() == "" {
		for _, u := range s.cplane.Unrestored() {
			behaviors := make([]uint32, 0, len(u.Behaviors))
			for _, b := range u.Behaviors {
				behaviors = append(behaviors, uint32(b))
			}
			unrestored = append(unrestored, &v1.UnrestoredCplanePlugin{
				Name:              u.Name,
				EndpointBehaviors: behaviors,
				Reason:            u.Reason,
				Since:             timestamppb.New(u.Since),
			})
		}
	}
	return connect.NewResponse(&v1.CplanePluginStatsResponse{
		Plugins:    out,
		Unrestored: unrestored,
	}), nil
}

// CplanePluginForget drops a plugin the store held that would not start.
func (s *PluginServer) CplanePluginForget(
	_ context.Context,
	req *connect.Request[v1.CplanePluginForgetRequest],
) (*connect.Response[v1.CplanePluginForgetResponse], error) {
	if s.cplane == nil {
		return nil, connect.NewError(connect.CodeUnimplemented,
			errors.New("control-plane plugins are not enabled on this daemon"))
	}
	if err := s.cplane.Forget(req.Msg.GetName()); err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}
	return connect.NewResponse(&v1.CplanePluginForgetResponse{}), nil
}

// parseFamilies validates the operator-facing family names.
func parseFamilies(names []string) ([]bgp.Family, error) {
	if len(names) == 0 {
		return nil, nil
	}
	out := make([]bgp.Family, 0, len(names))
	for _, n := range names {
		f, err := bgp.ParseFamily(n)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// parseBehaviors narrows the request's uint32 codepoints to the 16 bits an
// endpoint behavior actually occupies, so an out-of-range value is refused
// here rather than silently truncated into someone else's codepoint.
func parseBehaviors(codepoints []uint32) ([]uint16, error) {
	if len(codepoints) == 0 {
		return nil, nil
	}
	out := make([]uint16, 0, len(codepoints))
	for _, cp := range codepoints {
		if cp > 0xFFFF {
			return nil, fmt.Errorf("endpoint behavior %d does not fit 16 bits", cp)
		}
		out = append(out, uint16(cp))
	}
	return out, nil
}

// cplaneRPCError maps a manager failure onto a Connect code an operator can
// act on: a module or a name the daemon refused is the caller's to fix,
// everything else is the daemon's.
func cplaneRPCError(err error) error {
	switch {
	case errors.Is(err, wasm.ErrAdmission),
		errors.Is(err, demux.ErrUnclaimable),
		errors.Is(err, cplane.ErrScopeDoesNotCoverCapabilities),
		errors.Is(err, bpf.ErrBundleNameInvalid),
		errors.Is(err, bpf.ErrBundleNameTooLong):
		// The module, the codepoint, the name or the scope/capability
		// combination is wrong, and the caller is holding all of them.
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, cplane.ErrLeaseHeld),
		errors.Is(err, cplane.ErrSlotHeld),
		errors.Is(err, demux.ErrBehaviorHeld):
		// Nothing is wrong with the request; something else holds what it
		// asked for, and the caller decides what gives.
		return connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, cplane.ErrPluginNotRegistered):
		return connect.NewError(connect.CodeNotFound, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}
