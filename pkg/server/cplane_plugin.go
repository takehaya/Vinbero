package server

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"connectrpc.com/connect"
	"go.uber.org/zap"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
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

	reg := cplane.Registration{
		Name:         msg.GetName(),
		Module:       msg.GetWasm(),
		Config:       msg.GetConfig(),
		Families:     families,
		Behaviors:    behaviors,
		Capabilities: caps,
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
	case errors.Is(err, wasm.ErrAdmission):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, cplane.ErrLeaseHeld):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}
