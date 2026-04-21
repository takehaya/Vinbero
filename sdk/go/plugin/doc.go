// Package plugin is the Go-side client for Vinbero plugin aux lifecycle
// management. It wraps the PluginAuxAlloc / PluginAuxUpdate / PluginAuxGet /
// PluginAuxFree Connect RPCs so Go programs driving a Vinbero daemon can
// manage plugin state without hand-rolling the proto request structs.
//
// History. ADR-6 in docs/plan/plugin-sdk-enhancement.md originally deleted
// sdk/go/ on YAGNI grounds: Phase 1b exposed Client / ValidateFile / Map[K, V]
// helpers but nothing in the repo imported them. Phase 1d restored this
// package (only) because PluginAux[T] is the motivating use case for a typed
// client: callers want to pass a Go struct matching the plugin's BTF aux
// layout and have the SDK handle encoding + RPC.
//
// Scope. Map[K, V] and the broader validate-from-Go wrappers are still out of
// scope; they will be reintroduced if future phases grow a concrete need.
//
// T layout. PluginAux[T] uses encoding/json to send and encoding/binary
// (LittleEndian) to receive. T must therefore:
//
//   - Be fixed size (no slices, maps, pointers, strings).
//   - Match the C struct field order exactly.
//   - Use field tags (`json:"..."`) that match the BTF field names.
//   - Pack naturally without padding surprises (use [N]byte for fixed arrays).
//
// Plugins that cannot meet these constraints should use the raw-bytes
// variants (PluginAuxAllocRequest.Raw) and marshal themselves.
package plugin
