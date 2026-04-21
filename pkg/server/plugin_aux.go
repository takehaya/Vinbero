package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// validatePluginSlot rejects (map_type, slot) pairs that fall outside a plugin
// PROG_ARRAY range — all PluginAux ownership is scoped by this tuple, so a
// non-plugin slot would produce owner tags nothing else can match.
func validatePluginSlot(mapType string, slot uint32) error {
	switch mapType {
	case bpf.MapTypeEndpoint:
		if slot < bpf.EndpointPluginBase || slot >= bpf.EndpointProgMax {
			return fmt.Errorf("endpoint plugin slot must be in [%d, %d), got %d",
				bpf.EndpointPluginBase, bpf.EndpointProgMax, slot)
		}
	case bpf.MapTypeHeadendV4, bpf.MapTypeHeadendV6:
		if slot < bpf.HeadendPluginBase || slot >= bpf.HeadendProgMax {
			return fmt.Errorf("headend plugin slot must be in [%d, %d), got %d",
				bpf.HeadendPluginBase, bpf.HeadendProgMax, slot)
		}
	default:
		return fmt.Errorf("unknown map_type %q (expected endpoint / headend_v4 / headend_v6)", mapType)
	}
	return nil
}

// encodePluginAuxPayload normalizes a PluginAux payload to its on-wire byte
// form. Exactly one of rawIn / jsonIn must be non-empty; json is encoded via
// the plugin's BTF-declared <program>_aux struct.
func (s *PluginServer) encodePluginAuxPayload(mapType string, slot uint32, rawIn []byte, jsonIn string) ([]byte, error) {
	if len(rawIn) > 0 && jsonIn != "" {
		return nil, fmt.Errorf("raw and json payloads are mutually exclusive")
	}
	if len(rawIn) == 0 && jsonIn == "" {
		return nil, fmt.Errorf("either raw or json payload must be provided")
	}
	if len(rawIn) > 0 {
		if len(rawIn) > bpf.SidAuxPluginRawMax {
			return nil, fmt.Errorf("raw length %d exceeds SidAuxPluginRawMax (%d)",
				len(rawIn), bpf.SidAuxPluginRawMax)
		}
		return rawIn, nil
	}
	auxType := s.AuxType(mapType, slot)
	if auxType == nil {
		return nil, fmt.Errorf("plugin at %s/%d has no <program>_aux BTF type; use raw payload",
			mapType, slot)
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(jsonIn)))
	dec.UseNumber()
	var payload map[string]any
	if err := dec.Decode(&payload); err != nil {
		return nil, fmt.Errorf("payload is not a valid JSON object: %w", err)
	}
	return EncodePluginAux(auxType, payload)
}

// ownerMismatchToConnectErr converts an ErrOwnerMismatch into a
// PermissionDenied connect error so clients can distinguish it from
// transport / verification failures.
func ownerMismatchToConnectErr(err error) error {
	if errors.Is(err, bpf.ErrOwnerMismatch) {
		return connect.NewError(connect.CodePermissionDenied, err)
	}
	return connect.NewError(connect.CodeInternal, err)
}

func (s *PluginServer) PluginAuxAlloc(
	ctx context.Context,
	req *connect.Request[v1.PluginAuxAllocRequest],
) (*connect.Response[v1.PluginAuxAllocResponse], error) {
	msg := req.Msg
	if err := validatePluginSlot(msg.MapType, msg.Slot); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	raw, err := s.encodePluginAuxPayload(msg.MapType, msg.Slot, msg.GetRaw(), msg.GetJson())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	owner := bpf.AuxOwnerPluginTag(msg.MapType, msg.Slot)
	idx, err := s.mapOps.AllocPluginAux(owner)
	if err != nil {
		return nil, connect.NewError(connect.CodeResourceExhausted, err)
	}
	if err := s.mapOps.PutPluginAux(idx, raw, owner); err != nil {
		// roll back the allocator so the index can be reused
		_ = s.mapOps.FreePluginAux(idx, owner)
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&v1.PluginAuxAllocResponse{Index: idx}), nil
}

func (s *PluginServer) PluginAuxUpdate(
	ctx context.Context,
	req *connect.Request[v1.PluginAuxUpdateRequest],
) (*connect.Response[v1.PluginAuxUpdateResponse], error) {
	msg := req.Msg
	if err := validatePluginSlot(msg.MapType, msg.Slot); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if msg.Index == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("index 0 is the no-aux sentinel"))
	}
	raw, err := s.encodePluginAuxPayload(msg.MapType, msg.Slot, msg.GetRaw(), msg.GetJson())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	owner := bpf.AuxOwnerPluginTag(msg.MapType, msg.Slot)
	if err := s.mapOps.PutPluginAux(msg.Index, raw, owner); err != nil {
		return nil, ownerMismatchToConnectErr(err)
	}
	return connect.NewResponse(&v1.PluginAuxUpdateResponse{}), nil
}

func (s *PluginServer) PluginAuxGet(
	ctx context.Context,
	req *connect.Request[v1.PluginAuxGetRequest],
) (*connect.Response[v1.PluginAuxGetResponse], error) {
	msg := req.Msg
	if err := validatePluginSlot(msg.MapType, msg.Slot); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if msg.Index == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("index 0 is the no-aux sentinel"))
	}
	owner := bpf.AuxOwnerPluginTag(msg.MapType, msg.Slot)
	raw, err := s.mapOps.GetPluginAux(msg.Index, owner)
	if err != nil {
		return nil, ownerMismatchToConnectErr(err)
	}
	return connect.NewResponse(&v1.PluginAuxGetResponse{
		Raw:        raw,
		Owner:      owner,
		HasAuxType: s.AuxType(msg.MapType, msg.Slot) != nil,
	}), nil
}

func (s *PluginServer) PluginAuxFree(
	ctx context.Context,
	req *connect.Request[v1.PluginAuxFreeRequest],
) (*connect.Response[v1.PluginAuxFreeResponse], error) {
	msg := req.Msg
	if err := validatePluginSlot(msg.MapType, msg.Slot); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if msg.Index == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("index 0 is the no-aux sentinel"))
	}
	owner := bpf.AuxOwnerPluginTag(msg.MapType, msg.Slot)
	if err := s.mapOps.FreePluginAux(msg.Index, owner); err != nil {
		return nil, ownerMismatchToConnectErr(err)
	}
	return connect.NewResponse(&v1.PluginAuxFreeResponse{}), nil
}
