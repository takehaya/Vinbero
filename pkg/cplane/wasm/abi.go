// Package wasm runs control-plane plugins as sandboxed WebAssembly
// modules inside vinberod.
//
// The shape mirrors the data-plane plugin SDK on purpose: a third party
// ships bytecode, the daemon validates it against a capability policy at
// registration, and it runs with access to nothing but the host functions
// its declared capabilities link in. Data-plane plugins are eBPF and are
// checked by the kernel verifier; control-plane plugins are WebAssembly
// and are checked by the runtime and by the admission rules here.
//
// # ABI
//
// Everything crossing the boundary is a byte buffer in the guest's linear
// memory, addressed as a (pointer, length) pair. Protobuf carries the
// structure, so the contract lives in the .proto files rather than in
// hand-rolled struct layouts, and the ABI itself stays a small set of
// functions that move bytes.
//
// Buffers are owned by the guest. The host asks the guest to allocate,
// writes into that region, and calls the entry point; the guest frees it
// when it is done. The host keeps no reference to guest memory after a
// call returns -- linear memory can move when it grows, so a retained Go
// slice would silently point at a stale page.
//
// Guest exports:
//
//   - alloc(size i32) -> i32     -- reserve size bytes, return the offset
//   - free(ptr i32, size i32)    -- release a region alloc returned
//   - configure(ptr, len i32) -> i32  -- apply operator config, 0 on success
//   - handle_events(ptr, len i32) -> i64 -- consume an event batch
//   - on_tick(now_ns i64)       -- periodic callback
//
// handle_events returns a (pointer, length) pair packed into an i64, high
// word first, addressing a serialized status message. Returning 0 means
// "the whole batch was handled and there is nothing to report", which is
// the common case and costs no allocation.
//
// Host functions are imported from the "vinbero" module; see host.go.
package wasm

// ABIVersion is the contract version a plugin module declares. It is
// checked at registration, so a module built against an older SDK is
// refused with a clear message instead of trapping on the first call into
// a function whose signature moved.
//
// This is the same lesson the data-plane SDK learned when its ABI grew a
// field and older plugin objects kept loading: a version that is only
// documented is a version nobody checks.
const ABIVersion = 1

// HostModule is the import module name for Vinbero's capability functions.
// WASI runtime services are linked separately as wasi_snapshot_preview1.
const HostModule = "vinbero"

// Guest export names the host calls.
const (
	// ExportABIVersion is a function returning the ABI version the guest
	// was built against. It is a function rather than a global because a
	// global is awkward to export from most languages that target
	// WebAssembly, and a plugin that cannot declare its version cannot be
	// checked.
	ExportABIVersion = "vinbero_abi_version"
	// ExportAlloc reserves guest memory for a host-supplied buffer.
	ExportAlloc = "alloc"
	// ExportFree releases a region obtained from alloc.
	ExportFree = "free"
	// ExportConfigure receives the operator's config blob at instantiation.
	ExportConfigure = "configure"
	// ExportHandleEvents receives a batch of route and state events.
	ExportHandleEvents = "handle_events"
	// ExportOnTick is the periodic callback, carrying a monotonic
	// timestamp so a plugin needs no clock of its own for the common case.
	ExportOnTick = "on_tick"
	// ExportInitialize is the reactor initializer, by the name the WASI
	// reactor ABI gives it. A language runtime that needs to set up before
	// any exported function runs -- zeroing globals, building the
	// allocator, wiring up map hashing -- puts that work here.
	//
	// The host calls it explicitly rather than letting the module declare
	// a start function, so initialization happens under a call budget and
	// after the host is ready, not as a side effect of instantiation.
	ExportInitialize = "_initialize"
)

// GuestMemory is the name of the memory a guest must export. Exactly one,
// defined by the guest: an imported memory would let the module reach a
// region the host did not hand it.
const GuestMemory = "memory"

// Host function names, imported by the guest from HostModule.
const (
	// HostLog writes a line to the daemon log. Always linked: without it a
	// plugin author has no way to debug a module that has no stdout, no
	// filesystem, and whose only other output is the state it writes.
	HostLog = "log"
	// HostNowMonotonic returns nanoseconds from an unspecified epoch,
	// monotonic within a daemon run. Always linked. It deliberately breaks
	// determinism: liveness logic cannot be written without a clock.
	HostNowMonotonic = "now_monotonic"
	// HostApplyBegin opens a desired-set transaction and returns its
	// generation id.
	HostApplyBegin = "apply_begin"
	// HostApplyPut appends a chunk of entries to an open transaction.
	HostApplyPut = "apply_put"
	// HostApplyCommit reconciles the accumulated set and closes the
	// transaction.
	HostApplyCommit = "apply_commit"
	// HostApplyAbort discards an open transaction.
	HostApplyAbort = "apply_abort"
)

// LogLevel values accepted by the log host function. They mirror the
// daemon's own levels; anything else is treated as info rather than
// rejected, since a plugin misnumbering a log level should not lose the
// message.
const (
	LogDebug int32 = iota
	LogInfo
	LogWarn
	LogError
)

// packPtrLen folds a guest pointer and length into the i64 the ABI uses
// for returning a buffer: pointer in the high word, length in the low one.
func packPtrLen(ptr, length uint32) uint64 {
	return uint64(ptr)<<32 | uint64(length)
}

// unpackPtrLen splits the i64 form back into pointer and length.
func unpackPtrLen(v uint64) (ptr, length uint32) {
	return uint32(v >> 32), uint32(v)
}
