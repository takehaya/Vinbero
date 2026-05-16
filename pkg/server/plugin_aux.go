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
	"go.uber.org/zap"
)

// validatePluginSlot is a thin server-side alias for bpf.ValidatePluginSlot;
// kept under this name because every PluginAux RPC handler reads cleaner with
// the unprefixed call site, and to make any future server-only relaxation
// (e.g. allowing reserved slots in a debug mode) a one-liner.
func validatePluginSlot(mapType string, slot uint32) error {
	return bpf.ValidatePluginSlot(mapType, slot)
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

// ownerFor validates the (map_type, slot) pair and, if non-zero, the aux
// index, then returns the owner tag used by every PluginAux op on that slot.
// requireIdx=false is used by Alloc where no index exists yet.
func ownerFor(mapType string, slot, idx uint32, requireIdx bool) (string, error) {
	if err := validatePluginSlot(mapType, slot); err != nil {
		return "", err
	}
	if requireIdx && idx == 0 {
		return "", fmt.Errorf("index 0 is the no-aux sentinel")
	}
	return bpf.AuxOwnerPluginTag(mapType, slot), nil
}

// toRPCError maps a MapOperations error to a connect code. Owner-mismatch
// surfaces as PermissionDenied so clients can distinguish it from transport
// or verification failures; payload-too-large is the caller's mistake and
// surfaces as InvalidArgument; everything else is Internal.
func toRPCError(err error) error {
	switch {
	case errors.Is(err, bpf.ErrOwnerMismatch):
		return connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, bpf.ErrAuxPayloadTooLarge):
		return connect.NewError(connect.CodeInvalidArgument, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}

// PluginAuxAlloc reserves a fresh aux index for (map_type, slot), writes
// the caller's payload, and returns the index.
func (s *PluginServer) PluginAuxAlloc(
	ctx context.Context,
	req *connect.Request[v1.PluginAuxAllocRequest],
) (*connect.Response[v1.PluginAuxAllocResponse], error) {
	msg := req.Msg
	owner, err := ownerFor(msg.MapType, msg.Slot, 0, false)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	raw, err := s.encodePluginAuxPayload(msg.MapType, msg.Slot, msg.GetRaw(), msg.GetJson())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	idx, err := s.mapOps.AllocPluginAux(owner)
	if err != nil {
		return nil, connect.NewError(connect.CodeResourceExhausted, err)
	}
	if err := s.mapOps.PutPluginAux(idx, raw, owner); err != nil {
		// Roll back the alloc so a Put failure doesn't leak the index.
		// FreePluginAux should always succeed here because we just
		// minted idx with the same owner tag, but log unexpected
		// failures so a leaked allocator slot stays observable rather
		// than disappearing into _ assignment.
		if freeErr := s.mapOps.FreePluginAux(idx, owner); freeErr != nil {
			s.logger.Warn("PluginAuxAlloc rollback failed",
				zap.Uint32("index", idx),
				zap.String("owner", owner),
				zap.Error(freeErr),
			)
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&v1.PluginAuxAllocResponse{Index: idx}), nil
}

// PluginAuxUpdate overwrites the payload at an existing aux index that
// the caller's (map_type, slot) already owns.
func (s *PluginServer) PluginAuxUpdate(
	ctx context.Context,
	req *connect.Request[v1.PluginAuxUpdateRequest],
) (*connect.Response[v1.PluginAuxUpdateResponse], error) {
	msg := req.Msg
	owner, err := ownerFor(msg.MapType, msg.Slot, msg.Index, true)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	raw, err := s.encodePluginAuxPayload(msg.MapType, msg.Slot, msg.GetRaw(), msg.GetJson())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := s.mapOps.PutPluginAux(msg.Index, raw, owner); err != nil {
		return nil, toRPCError(err)
	}
	return connect.NewResponse(&v1.PluginAuxUpdateResponse{}), nil
}

// PluginAuxGet returns the on-wire bytes stored at an aux index along
// with its owner tag so the caller can detect cross-tenant binds early.
func (s *PluginServer) PluginAuxGet(
	ctx context.Context,
	req *connect.Request[v1.PluginAuxGetRequest],
) (*connect.Response[v1.PluginAuxGetResponse], error) {
	msg := req.Msg
	owner, err := ownerFor(msg.MapType, msg.Slot, msg.Index, true)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	raw, err := s.mapOps.GetPluginAux(msg.Index, owner)
	if err != nil {
		return nil, toRPCError(err)
	}
	return connect.NewResponse(&v1.PluginAuxGetResponse{
		Raw:        raw,
		Owner:      owner,
		HasAuxType: s.AuxType(msg.MapType, msg.Slot) != nil,
	}), nil
}

// PluginAuxFree zeroes the entry at idx and releases the index back to
// the allocator. Cross-tenant frees surface as PermissionDenied.
func (s *PluginServer) PluginAuxFree(
	ctx context.Context,
	req *connect.Request[v1.PluginAuxFreeRequest],
) (*connect.Response[v1.PluginAuxFreeResponse], error) {
	msg := req.Msg
	owner, err := ownerFor(msg.MapType, msg.Slot, msg.Index, true)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := s.mapOps.FreePluginAux(msg.Index, owner); err != nil {
		return nil, toRPCError(err)
	}
	return connect.NewResponse(&v1.PluginAuxFreeResponse{}), nil
}
