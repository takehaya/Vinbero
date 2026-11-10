package server

import (
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/takehaya/vinbero/pkg/vrf"
)

// resolveHeadendVRF returns the vrf_id of the VRF a headend request names.
// The empty name and the reserved global name are vrf 0; any other name
// must be an existing VRF, and the error for one that is not wraps
// vrf.ErrUnknownVRF. No VRF is created. vrfs may be nil, which resolves
// the global VRF only.
//
// With hold set, the VRF cannot start its deletion until release is
// called; the caller writes the entry before it does and nothing else. A
// global-VRF request takes no hold.
func resolveHeadendVRF(vrfs vrf.Directory, name string, hold bool) (id uint32, release func(), err error) {
	if vrf.IsGlobalName(name) {
		return vrf.GlobalVRFID, func() {}, nil
	}
	if vrfs == nil {
		return 0, nil, fmt.Errorf("%w %q", vrf.ErrUnknownVRF, name)
	}
	release = func() {}
	if hold {
		release = vrfs.HoldIDs()
	}
	id, err = vrfs.LookupID(name)
	if err != nil {
		release()
		return 0, nil, err
	}
	return id, release, nil
}

// headendVRFName is the vrf_name a response carries for id: empty for the
// global VRF, and for an id no VRF holds (vrf_id still tells).
func headendVRFName(vrfs vrf.Directory, id uint32) string {
	if id == vrf.GlobalVRFID || vrfs == nil {
		return ""
	}
	name, _ := vrfs.NameOf(id)
	return name
}

// headendVRFError maps a failed resolve to the RPC error: NotFound for an
// unknown VRF, as the VRF RPCs answer.
func headendVRFError(err error) error {
	if errors.Is(err, vrf.ErrUnknownVRF) {
		return connect.NewError(connect.CodeNotFound, err)
	}
	return connect.NewError(connect.CodeInternal, err)
}

// headendVRFScope is the VRF a List or Flush covers: one VRF (only set)
// or every VRF. vrf_name and all_vrfs together are refused.
func headendVRFScope(vrfs vrf.Directory, name string, all bool) (only *uint32, err error) {
	if all {
		if name != "" {
			return nil, connect.NewError(connect.CodeInvalidArgument,
				fmt.Errorf("vrf_name %q and all_vrfs are exclusive", name))
		}
		return nil, nil
	}
	id, _, err := resolveHeadendVRF(vrfs, name, false)
	if err != nil {
		return nil, headendVRFError(err)
	}
	return &id, nil
}

// checkRequestVRFID accepts a request vrf_id of 0 or the id vrf_name
// resolved to, so an entry a List returned can be sent back as it is.
func checkRequestVRFID(requested, resolved uint32, name string) error {
	if requested == 0 || requested == resolved {
		return nil
	}
	return fmt.Errorf("vrf_id %d does not match vrf_name %q (vrf_id %d); vrf_id is server-assigned", requested, name, resolved)
}
