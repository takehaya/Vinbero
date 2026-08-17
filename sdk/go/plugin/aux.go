package plugin

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"reflect"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/api/vinbero/v1/vinberov1connect"
)

// SidAuxPluginRawMax mirrors pkg/bpf.SidAuxPluginRawMax. Duplicated to
// keep sdk/go/plugin importable without pulling in the BPF stack; the
// duplication is pinned against the real constant by a test.
const SidAuxPluginRawMax = 256

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
// calls on the same PluginAux target the same plugin slot. Panics if T
// is larger than SidAuxPluginRawMax — that is a programming error the
// caller should fix at compile time, not at runtime in production.
func NewPluginAux[T any](client vinberov1connect.PluginServiceClient, mapType string, slot uint32) *PluginAux[T] {
	var zero T
	if size := reflect.TypeOf(zero).Size(); size > SidAuxPluginRawMax {
		panic(fmt.Sprintf("PluginAux[T] size %d exceeds SidAuxPluginRawMax (%d); "+
			"split T into smaller pieces", size, SidAuxPluginRawMax))
	}
	return &PluginAux[T]{client: client, mapType: mapType, slot: slot}
}

// expectedOwner renders the owner tag this helper's (map_type, slot) pair
// is expected to carry, in the server's current versioned form. SDK callers
// don't import pkg/bpf to keep the dependency surface minimal, so the format
// is duplicated here and pinned against the real one by a test.
func (p *PluginAux[T]) expectedOwner() string {
	return fmt.Sprintf("plugin:%s:%s:%d", auxOwnerVersion, p.mapType, p.slot)
}

// auxOwnerVersion mirrors pkg/bpf.AuxOwnerVersion.
const auxOwnerVersion = "v1"

// ownerMatches reports whether the tag the server returned names this
// helper's slot. Both the versioned form ("plugin:v1:<map_type>:<slot>")
// and the unversioned legacy form ("plugin:<map_type>:<slot>") are
// accepted: an aux index allocated by an older daemon keeps its original
// tag in the pinned map, and rejecting it would make an otherwise valid
// entry unreadable after an upgrade.
func (p *PluginAux[T]) ownerMatches(got string) bool {
	if got == p.expectedOwner() {
		return true
	}
	return got == fmt.Sprintf("plugin:%s:%d", p.mapType, p.slot)
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

// Get reads the raw bytes at idx, verifies the server-reported owner
// matches this PluginAux instance, and decodes the bytes into T using
// encoding/binary with NativeEndian. NativeEndian matches the server's
// BTF encoder (see pkg/server/plugin_aux_encode.go) and the BPF data
// plane's natural alignment. T must satisfy the constraints listed in
// the package doc.
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
	if !p.ownerMatches(resp.Msg.Owner) {
		return zero, fmt.Errorf("aux at idx %d is owned by %q, expected %q",
			idx, resp.Msg.Owner, p.expectedOwner())
	}
	var out T
	if err := binary.Read(bytes.NewReader(resp.Msg.Raw), binary.NativeEndian, &out); err != nil {
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
