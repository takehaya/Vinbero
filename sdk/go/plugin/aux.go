package plugin

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/api/vinbero/v1/vinberov1connect"
)

// PluginAux is a typed client for the four PluginAux RPCs, parameterized by
// the Go struct T that mirrors the plugin's <program>_aux BTF type. See the
// package doc for the constraints T must satisfy.
type PluginAux[T any] struct {
	client  vinberov1connect.PluginServiceClient
	mapType string
	slot    uint32
}

// NewPluginAux binds a PluginAux helper to a specific (map_type, slot) pair.
// The owner tag server-side is derived from this pair, so all subsequent
// calls on the same PluginAux target the same plugin slot.
func NewPluginAux[T any](client vinberov1connect.PluginServiceClient, mapType string, slot uint32) *PluginAux[T] {
	return &PluginAux[T]{client: client, mapType: mapType, slot: slot}
}

// Alloc encodes v as JSON (so the server can translate via BTF), asks the
// server to reserve an aux slot, and returns the allocated index.
func (p *PluginAux[T]) Alloc(ctx context.Context, v T) (uint32, error) {
	js, err := json.Marshal(v)
	if err != nil {
		return 0, fmt.Errorf("marshal payload: %w", err)
	}
	resp, err := p.client.PluginAuxAlloc(ctx, connect.NewRequest(&v1.PluginAuxAllocRequest{
		MapType: p.mapType,
		Slot:    p.slot,
		Payload: &v1.PluginAuxAllocRequest_Json{Json: string(js)},
	}))
	if err != nil {
		return 0, err
	}
	return resp.Msg.Index, nil
}

// Update rewrites the payload at an existing index. The server verifies the
// index was allocated against the same (map_type, slot) pair before writing.
func (p *PluginAux[T]) Update(ctx context.Context, idx uint32, v T) error {
	js, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	_, err = p.client.PluginAuxUpdate(ctx, connect.NewRequest(&v1.PluginAuxUpdateRequest{
		Index:   idx,
		MapType: p.mapType,
		Slot:    p.slot,
		Payload: &v1.PluginAuxUpdateRequest_Json{Json: string(js)},
	}))
	return err
}

// Get reads the raw bytes at idx and decodes them into T using
// encoding/binary + LittleEndian. T must be a fixed-size structure matching
// the C layout; see the package doc for the full constraints.
func (p *PluginAux[T]) Get(ctx context.Context, idx uint32) (T, error) {
	var zero T
	resp, err := p.client.PluginAuxGet(ctx, connect.NewRequest(&v1.PluginAuxGetRequest{
		Index:   idx,
		MapType: p.mapType,
		Slot:    p.slot,
	}))
	if err != nil {
		return zero, err
	}
	var out T
	if err := binary.Read(bytes.NewReader(resp.Msg.Raw), binary.LittleEndian, &out); err != nil {
		return zero, fmt.Errorf("decode raw: %w", err)
	}
	return out, nil
}

// Free zeroes the entry at idx and returns the slot to the allocator.
func (p *PluginAux[T]) Free(ctx context.Context, idx uint32) error {
	_, err := p.client.PluginAuxFree(ctx, connect.NewRequest(&v1.PluginAuxFreeRequest{
		Index:   idx,
		MapType: p.mapType,
		Slot:    p.slot,
	}))
	return err
}
