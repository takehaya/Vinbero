package evpn

import "errors"

// ErrNotImplemented is returned by NewStubHandler so callers can distinguish
// "handler dormant" from real runtime errors via errors.Is.
var ErrNotImplemented = errors.New("evpn handler not implemented yet")

// NewStubHandler returns a Handler whose every method returns ErrNotImplemented.
// It lets vinberod wire a non-nil Handler field unconditionally.
func NewStubHandler() Handler { return stubHandler{} }

type stubHandler struct{}

func (stubHandler) ApplyRoute(Route) error    { return ErrNotImplemented }
func (stubHandler) WithdrawRoute(Route) error { return ErrNotImplemented }
