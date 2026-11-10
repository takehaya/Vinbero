package server

import (
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/takehaya/vinbero/pkg/vrf"
)

// HeadendVRFs resolves the VRF a headend request names. *vrf.Manager
// satisfies it.
type HeadendVRFs interface {
	LookupID(name string) (uint32, error)
	NameOf(id uint32) (string, bool)
	HoldIDs() (release func())
}

// resolveHeadendVRF returns the vrf_id of the VRF a headend request names.
// The empty name and the reserved global name are vrf 0; any other name
// must be an existing VRF, and the error for one that is not wraps
// vrf.ErrUnknownVRF. No VRF is created.
//
// With hold set, the VRF cannot be deleted until release is called, so a
// write made before then is seen by the delete's reference check. A
// global-VRF request takes no hold.
func resolveHeadendVRF(vrfs HeadendVRFs, name string, hold bool) (id uint32, release func(), err error) {
	if name == "" || name == vrf.GlobalVRFName {
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
// global VRF, and for an id no VRF holds any more (vrf_id still tells).
func headendVRFName(vrfs HeadendVRFs, id uint32) string {
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

// errVRFIDServerAssigned refuses a request that sets vrf_id; it names the
// VRF with vrf_name.
var errVRFIDServerAssigned = errors.New("vrf_id is server-assigned and must be unset; name the VRF with vrf_name")
