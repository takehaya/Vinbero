// Package plugin is the Go-side client for Vinbero plugin aux lifecycle
// management. It wraps the PluginAuxAlloc / PluginAuxUpdate / PluginAuxGet /
// PluginAuxFree Connect RPCs so Go programs driving a Vinbero daemon can
// manage plugin state without hand-rolling the proto request structs.
//
// History. An earlier ADR deleted sdk/go/ on YAGNI grounds: the first
// pass exposed Client / ValidateFile / Map[K, V] helpers but nothing in
// the repo imported them. This package was later restored — only — because
// PluginAux[T] is the motivating use case for a typed client: callers
// want to pass a Go struct matching the plugin's BTF aux layout and have
// the SDK handle encoding + RPC. See docs/dev/plugin-sdk-implementation.md
// for the full rationale.
//
// Scope. Map[K, V] and the broader validate-from-Go wrappers are still
// out of scope; they will be reintroduced if a concrete need surfaces.
//
// T layout. PluginAux[T] uses encoding/json to send and encoding/binary
// (NativeEndian) to receive. NativeEndian matches the server's BTF
// encoder and the BPF data plane's in-memory layout (BPF maps are
// host-endian by ABI). T must therefore:
//
//   - Be fixed size (no slices, maps, pointers, strings).
//   - Match the C struct field order exactly.
//   - Use JSON tags (`json:"..."`) that match the BTF field names.
//   - Pack naturally without padding surprises (use [N]byte for fixed arrays).
//   - Have unsafe.Sizeof(T) <= 256 (SidAuxPluginRawMax). NewPluginAux
//     panics at construction time if this is violated.
//
// Plugins that cannot meet these constraints should use the raw-bytes
// variants (PluginAuxAllocRequest.Raw) and marshal themselves.
//
// Persistence. Aux indices allocated via Alloc but not bound to a
// SidFunction live only in the daemon's in-memory allocator. They are
// lost on daemon restart (BPF map pinning is not yet wired through to
// the plugin allocator — see docs/design/ja/persistence.md). Plugin
// authors should either re-allocate at startup or bind the index to a
// SidFunction immediately after allocating. PluginUnregister also does
// NOT free aux indices owned by the slot; call Free per-index before
// unregistering, or expect the daemon to log a warning about orphaned
// aux entries.
package plugin
