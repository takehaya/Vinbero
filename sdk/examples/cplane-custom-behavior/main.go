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
	fieldEventKind     = 1
	fieldEventRoute    = 3
	fieldEventLocalSid = 7
	// PluginRoute
	fieldRouteIsWithdraw       = 2
	fieldRouteEndpointBehavior = 5
	fieldRoutePrefix           = 7
	fieldRouteSrv6Sid          = 8
	// PluginLocalSidAllocated
	fieldAllocatedName = 1
	fieldAllocatedSid  = 2
	// PluginApplyChunk
	fieldChunkHeadendEntries  = 1
	fieldChunkAdvertisedRoute = 2
	fieldChunkLocalSids       = 3
	// PluginHeadendEntry
	fieldEntryTriggerPrefix = 1
	fieldEntrySegments      = 2
	// PluginAdvertisedRoute
	fieldAdvFamily   = 1
	fieldAdvRD       = 2
	fieldAdvPrefix   = 3
	fieldAdvSID      = 4
	fieldAdvBehavior = 5
	// PluginLocalSid
	fieldLocalSidName    = 1
	fieldLocalSidLocator = 2
	fieldLocalSidSlot    = 3
	// The example's own config message.
	fieldConfigBehavior = 1
	fieldConfigLocator  = 2
	fieldConfigPrefix   = 3
	fieldConfigRD       = 4
	fieldConfigSlot     = 5
)

// PluginEventKind values this plugin acts on.
const (
	eventKindRoute       = 1
	eventKindEndOfReplay = 3
	eventKindLocalSID    = 5
)

// PluginApplyKind values.
const (
	applyKindHeadendV4 = 1
	applyKindAdvertise = 3
	applyKindLocalSID  = 4
)

// localSIDName is what this plugin calls the SID it asks for. The host
// picks the address; the name is how this plugin recognizes it, and how a
// redeclaration after a restart is known to mean the same one.
const localSIDName = "self"

// The deployment-specific half of what this plugin does: which locator to
// take its SID from, which prefix to advertise behind it, and which slot
// its data-plane half occupies. All of it comes from the config blob, so
// one build serves every deployment.
var (
	locatorName   string
	advertiseRD   string
	advertisePfx  string
	dataPlaneSlot uint64
	// allocatedSID is the address the host gave this plugin, empty until
	// the local-SID event arrives.
	allocatedSID string
)

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
	// The config is this plugin's own protobuf message. The host does not
	// interpret it: a plugin defines whatever shape it needs and the
	// operator supplies the encoded bytes.
	r := &reader{buf: view(ptr, length)}
	for !r.eof() {
		field, wire, ok := r.tag()
		if !ok {
			logf(logWarn, "ignoring an unusable config blob")
			return 1
		}
		switch {
		case field == fieldConfigBehavior && wire == wireVarint:
			var v uint64
			v, ok = r.varint()
			if ok && v > 0 && v <= 0xFFFF {
				claimedBehavior = v
			}
		case field == fieldConfigLocator && wire == wireBytes:
			var b []byte
			b, ok = r.bytes()
			locatorName = string(b)
		case field == fieldConfigPrefix && wire == wireBytes:
			var b []byte
			b, ok = r.bytes()
			advertisePfx = string(b)
		case field == fieldConfigRD && wire == wireBytes:
			var b []byte
			b, ok = r.bytes()
			advertiseRD = string(b)
		case field == fieldConfigSlot && wire == wireVarint:
			dataPlaneSlot, ok = r.varint()
		default:
			ok = r.skip(wire)
		}
		if !ok {
			logf(logWarn, "ignoring an unusable config blob")
			return 1
		}
	}
	logf(logInfo, "configured")
	// Asking for the local SID here is what starts the sequence: the host
	// allocates it, tells this plugin the address, and only then can it
	// advertise anything.
	declareLocalSID()
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
		kind     uint64
		route    []byte
		localSID []byte
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
		case field == fieldEventLocalSid && wire == wireBytes:
			localSID, ok = r.bytes()
		default:
			ok = r.skip(wire)
		}
		if !ok {
			return false
		}
	}
	switch kind {
	case eventKindRoute:
		if route == nil {
			return false
		}
		return applyRoute(route)
	case eventKindEndOfReplay:
		// The host has finished telling this instance what the network
		// looks like. Declare unconditionally, even if nothing changed.
		//
		// After a restart the host keeps the entries the previous
		// instance installed, and this instance knows nothing about them.
		// If the replay brings back no matching route -- everything was
		// withdrawn while it was down, or this node simply has none --
		// then without declaring here the stale entries are never pruned
		// and blackhole until an unrelated route happens to arrive.
		return true
	case eventKindLocalSID:
		if localSID == nil {
			return false
		}
		applyLocalSID(localSID)
		return false // it changes what is advertised, not what is steered
	default:
		return false
	}
}

// applyLocalSID records the address the host allocated and advertises the
// prefix behind it.
//
// This is the point the whole sequence was for: the plugin now has an
// address of its own, pointing at its own data-plane half, and can tell
// its peers to send traffic for the configured prefix to it -- naming its
// own behavior codepoint in the SID TLV, which is what makes the far end
// hand the route to the plugin there rather than to vinbero's appliers.
func applyLocalSID(body []byte) {
	r := &reader{buf: body}
	var name, sid string
	for !r.eof() {
		field, wire, ok := r.tag()
		if !ok {
			return
		}
		switch {
		case field == fieldAllocatedName && wire == wireBytes:
			var b []byte
			b, ok = r.bytes()
			name = string(b)
		case field == fieldAllocatedSid && wire == wireBytes:
			var b []byte
			b, ok = r.bytes()
			sid = string(b)
		default:
			ok = r.skip(wire)
		}
		if !ok {
			return
		}
	}
	if name != localSIDName || sid == "" {
		return
	}
	allocatedSID = sid
	logf(logInfo, "allocated local SID "+sid)
	advertiseSelf()
}

// declareLocalSID asks the host for an address pointing at this plugin's
// data-plane slot.
func declareLocalSID() {
	if locatorName == "" || dataPlaneSlot == 0 {
		// Nothing was configured, so this deployment only wants the
		// receive side. That is a perfectly ordinary way to run.
		return
	}
	var entry writer
	entry.putString(fieldLocalSidName, localSIDName)
	entry.putString(fieldLocalSidLocator, locatorName)
	entry.putTag(fieldLocalSidSlot, wireVarint)
	entry.putVarint(dataPlaneSlot)

	var chunk writer
	chunk.putMessage(fieldChunkLocalSids, entry.buf)
	commit(applyKindLocalSID, chunk.buf)
}

// advertiseSelf declares the routes this plugin wants originated: the
// configured prefix, reachable at the SID it was given, named with its own
// behavior codepoint.
func advertiseSelf() {
	if allocatedSID == "" || advertisePfx == "" || advertiseRD == "" {
		return
	}
	var route writer
	route.putString(fieldAdvFamily, "vpnv4")
	route.putString(fieldAdvRD, advertiseRD)
	route.putString(fieldAdvPrefix, advertisePfx)
	route.putString(fieldAdvSID, allocatedSID)
	route.putTag(fieldAdvBehavior, wireVarint)
	route.putVarint(claimedBehavior)

	var chunk writer
	chunk.putMessage(fieldChunkAdvertisedRoute, route.buf)
	commit(applyKindAdvertise, chunk.buf)
}

// commit runs one desired-set transaction with a single chunk.
func commit(kind int32, chunk []byte) {
	gen := hostApplyBegin(kind)
	if gen == 0 {
		logf(logWarn, "the host refused to open a transaction")
		return
	}
	if len(chunk) > 0 {
		if hostApplyPut(gen, bytesPtr(chunk), int32(len(chunk))) != 0 {
			logf(logWarn, "the host rejected the declared set")
			hostApplyAbort(gen)
			return
		}
	}
	if hostApplyCommit(gen) != 0 {
		logf(logWarn, "the host refused to commit the declared set")
	}
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
// An empty set is still committed: that is how the last prefix is pruned
// when everything has been withdrawn.
func declare() {
	commit(applyKindHeadendV4, encodeChunk())
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
