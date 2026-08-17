// Command cplane-custom-behavior is a control-plane plugin that steers
// traffic for routes advertised with an operator's own SRv6 endpoint
// behavior.
//
// It is the control-plane half of the case this whole mechanism exists
// for. An operator defines a behavior of their own, gives it a codepoint
// outside the standardized space, and implements the forwarding for it as
// a data-plane plugin in an eBPF slot. This half claims that codepoint,
// watches for VPN routes carrying it, and declares the headend entries
// that send matching traffic through the SID the advertisement named. The
// built-in appliers never see those routes: they would read the codepoint
// as an ordinary service SID and install the wrong thing.
//
// What it does on each route:
//
//   - an advertisement carrying the claimed behavior and an SRv6 SID adds
//     a headend entry for its prefix, steering into that SID;
//   - a withdrawal removes it;
//   - anything else is ignored.
//
// The whole set is re-declared on every change rather than edited in
// place, because the host reconciles a declared set against what this
// plugin already owns. That is also what makes a restart free: the plugin
// comes back empty, the host replays the routes, and the same declaration
// converges on the same state without the plugin remembering anything.
package main

import "unsafe"

// Field numbers from vinbero/v1/cplane_plugin.proto. They are duplicated
// here rather than generated because TinyGo's WebAssembly target has no
// reflection, and the generated bindings need it.
const (
	// PluginEventBatch
	fieldBatchEvents = 1
	// PluginEvent
	fieldEventKind  = 1
	fieldEventRoute = 3
	// PluginRoute
	fieldRouteIsWithdraw       = 2
	fieldRouteEndpointBehavior = 5
	fieldRoutePrefix           = 7
	fieldRouteSrv6Sid          = 8
	// PluginApplyChunk
	fieldChunkHeadendEntries = 1
	// PluginHeadendEntry
	fieldEntryTriggerPrefix = 1
	fieldEntrySegments      = 2
)

// PluginEventKind values this plugin acts on.
const eventKindRoute = 1

// PluginApplyKind values.
const applyKindHeadendV4 = 1

// Log levels, matching the host's.
const (
	logInfo = 1
	logWarn = 2
)

//go:wasmimport vinbero log
func hostLog(level int32, ptr, length int32)

//go:wasmimport vinbero apply_begin
func hostApplyBegin(kind int32) int64

//go:wasmimport vinbero apply_put
func hostApplyPut(generation int64, ptr, length int32) int32

//go:wasmimport vinbero apply_commit
func hostApplyCommit(generation int64) int32

//go:wasmimport vinbero apply_abort
func hostApplyAbort(generation int64)

// claimedBehavior is the codepoint this plugin owns. It sits outside the
// standardized space on purpose: the host refuses a claim on any behavior
// it implements itself, and an operator's own behavior should not collide
// with one IANA may assign later.
//
// configure can override it, so one module can serve deployments that
// numbered their behavior differently.
var claimedBehavior uint64 = 0xFE01

// steered is the set this plugin currently wants installed: prefix to the
// SID traffic for it should be steered into. It is the plugin's whole
// state, and it is rebuilt from replayed routes after a restart rather
// than persisted.
var steered = map[string]string{}

// allocations keeps host-owned buffers alive.
//
// TinyGo's WebAssembly target uses a leaking collector, so nothing here is
// ever reclaimed; the map exists to stop the collector from moving or
// freeing a buffer the host still holds a pointer to, which matters for
// every other collector the SDK might be built with.
var allocations = map[int32][]byte{}

// abiVersion is the host ABI this plugin is built against. The host reads
// it at registration and refuses a mismatch, so a module built for an
// older daemon is turned away with a clear message rather than trapping on
// the first call into a function whose signature moved.
const abiVersion = 1

//go:wasmexport vinbero_abi_version
func vinberoABIVersion() int32 { return abiVersion }

//go:wasmexport alloc
func alloc(size int32) int32 {
	if size <= 0 {
		return 0
	}
	buf := make([]byte, size)
	ptr := int32(uintptr(unsafe.Pointer(&buf[0])))
	allocations[ptr] = buf
	return ptr
}

//go:wasmexport free
func free(ptr, size int32) {
	delete(allocations, ptr)
}

//go:wasmexport configure
func configure(ptr, length int32) int32 {
	if length == 0 {
		return 0
	}
	// The config is a bare varint: the behavior codepoint to claim. A
	// plugin with more to configure would define its own message; this one
	// has exactly one knob and a whole message for it would be ceremony.
	r := &reader{buf: view(ptr, length)}
	v, ok := r.varint()
	if !ok || v == 0 || v > 0xFFFF {
		logf(logWarn, "ignoring an unusable config blob")
		return 1
	}
	claimedBehavior = v
	logf(logInfo, "claiming behavior from config")
	return 0
}

//go:wasmexport handle_events
func handleEvents(ptr, length int32) int64 {
	if length == 0 {
		return 0
	}
	changed := false
	r := &reader{buf: view(ptr, length)}
	for !r.eof() {
		field, wire, ok := r.tag()
		if !ok {
			logf(logWarn, "malformed event batch")
			return 0
		}
		if field != fieldBatchEvents || wire != wireBytes {
			if !r.skip(wire) {
				return 0
			}
			continue
		}
		body, ok := r.bytes()
		if !ok {
			return 0
		}
		if applyEvent(body) {
			changed = true
		}
	}
	if changed {
		declare()
	}
	// This plugin never asks for an event to be quarantined, so it has
	// nothing to report and returns the empty status.
	return 0
}

//go:wasmexport on_tick
func onTick(nowNs int64) {}

// applyEvent folds one event into the desired set, reporting whether it
// changed anything.
func applyEvent(body []byte) bool {
	r := &reader{buf: body}
	var (
		kind  uint64
		route []byte
	)
	for !r.eof() {
		field, wire, ok := r.tag()
		if !ok {
			return false
		}
		switch {
		case field == fieldEventKind && wire == wireVarint:
			kind, ok = r.varint()
		case field == fieldEventRoute && wire == wireBytes:
			route, ok = r.bytes()
		default:
			ok = r.skip(wire)
		}
		if !ok {
			return false
		}
	}
	if kind != eventKindRoute || route == nil {
		return false
	}
	return applyRoute(route)
}

// applyRoute adds or removes one prefix from the desired set.
func applyRoute(body []byte) bool {
	r := &reader{buf: body}
	var (
		withdraw bool
		behavior uint64
		prefix   string
		sid      string
	)
	for !r.eof() {
		field, wire, ok := r.tag()
		if !ok {
			return false
		}
		switch {
		case field == fieldRouteIsWithdraw && wire == wireVarint:
			var v uint64
			v, ok = r.varint()
			withdraw = v != 0
		case field == fieldRouteEndpointBehavior && wire == wireVarint:
			behavior, ok = r.varint()
		case field == fieldRoutePrefix && wire == wireBytes:
			var b []byte
			b, ok = r.bytes()
			prefix = string(b)
		case field == fieldRouteSrv6Sid && wire == wireBytes:
			var b []byte
			b, ok = r.bytes()
			sid = string(b)
		default:
			ok = r.skip(wire)
		}
		if !ok {
			return false
		}
	}
	if prefix == "" {
		return false
	}

	if withdraw {
		// A withdrawal carries no attributes, so its behavior is always
		// zero and cannot be matched against the claim. Matching on the
		// prefix this plugin is holding is the only thing that works --
		// and if it is not holding one, the withdrawal is not its
		// business.
		if _, held := steered[prefix]; !held {
			return false
		}
		delete(steered, prefix)
		logf(logInfo, "withdrew "+prefix)
		return true
	}

	if behavior != claimedBehavior || sid == "" {
		return false
	}
	if steered[prefix] == sid {
		return false // already declared exactly this
	}
	steered[prefix] = sid
	logf(logInfo, "steering "+prefix)
	return true
}

// declare sends the whole desired set to the host.
//
// It is the whole set every time, not a delta: the host diffs it against
// what this plugin already owns, so a declaration is a statement of intent
// that is correct whatever state the data plane was left in by a previous
// instance.
func declare() {
	gen := hostApplyBegin(applyKindHeadendV4)
	if gen == 0 {
		logf(logWarn, "the host refused to open a transaction")
		return
	}
	chunk := encodeChunk()
	if len(chunk) > 0 {
		if hostApplyPut(gen, bytesPtr(chunk), int32(len(chunk))) != 0 {
			logf(logWarn, "the host rejected the declared set")
			hostApplyAbort(gen)
			return
		}
	}
	// An empty set is still committed: that is how the last prefix is
	// pruned when everything has been withdrawn.
	if hostApplyCommit(gen) != 0 {
		logf(logWarn, "the host refused to commit the declared set")
	}
}

// encodeChunk serializes the desired set as a PluginApplyChunk.
func encodeChunk() []byte {
	var w writer
	for prefix, sid := range steered {
		var entry writer
		entry.putString(fieldEntryTriggerPrefix, prefix)
		entry.putString(fieldEntrySegments, sid)
		w.putMessage(fieldChunkHeadendEntries, entry.buf)
	}
	return w.buf
}

// view builds a slice over a region of this module's own memory. The host
// wrote the bytes there through alloc, so the region is one this module
// owns and the slice does not outlive the call it was made for.
func view(ptr, length int32) []byte {
	if length <= 0 {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(uintptr(ptr))), length)
}

// bytesPtr is the address of a slice's first byte, for handing back to the
// host.
func bytesPtr(b []byte) int32 {
	if len(b) == 0 {
		return 0
	}
	return int32(uintptr(unsafe.Pointer(&b[0])))
}

// logf sends a line to the daemon log. Without it a plugin has no output
// at all: the sandbox has no stdout and no filesystem.
func logf(level int32, msg string) {
	b := []byte(msg)
	hostLog(level, bytesPtr(b), int32(len(b)))
}

func main() {}
