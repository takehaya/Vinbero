//go:build tinygo && wasm_unknown

package guest

import (
	"unsafe"

	"github.com/takehaya/vinbero/sdk/go/cplane"
)

// Handlers run serially in the guest. Configure must copy any config bytes it
// retains. Events contain owned data, so they may be retained by a RouteView.
// Nil callbacks are no-ops; an empty Events result means all events were handled.
type Handlers struct {
	Configure func([]byte) error
	Events    func([]cplane.Event) []cplane.EventResult
	Tick      func(int64)
}

var handlers Handlers
var registered bool
var allocations = map[uint32][]byte{}

func Register(h Handlers) {
	if registered {
		panic("cplane: handlers already registered")
	}
	handlers, registered = h, true
}

//go:wasmexport vinbero_abi_version
func abiVersion() uint32 { return 1 }

//go:wasmexport alloc
func alloc(size uint32) uint32 {
	if size == 0 {
		return 0
	}
	buf := make([]byte, size)
	ptr := uint32(uintptr(unsafe.Pointer(&buf[0])))
	allocations[ptr] = buf
	return ptr
}

//go:wasmexport free
func free(ptr, size uint32) { delete(allocations, ptr) }

func buffer(ptr, length uint32) []byte {
	if length == 0 {
		return nil
	}
	buf, ok := allocations[ptr]
	if !ok || uint64(length) > uint64(len(buf)) {
		panic("cplane: invalid host buffer")
	}
	return buf[:length]
}

//go:wasmexport configure
func configure(ptr, length uint32) uint32 {
	if handlers.Configure != nil {
		if err := handlers.Configure(buffer(ptr, length)); err != nil {
			Log(cplane.LogWarn, err.Error())
			return 1
		}
	}
	return 0
}

//go:wasmexport handle_events
func handleEvents(ptr, length uint32) uint64 {
	events, err := cplane.DecodeEvents(buffer(ptr, length))
	if err != nil {
		panic("cplane: malformed event batch")
	}
	if handlers.Events == nil {
		return 0
	}
	status := cplane.EncodeResults(handlers.Events(events))
	if len(status) == 0 {
		return 0
	}
	out := alloc(uint32(len(status)))
	copy(allocations[out], status)
	return uint64(out)<<32 | uint64(len(status))
}

//go:wasmexport on_tick
func onTick(now int64) {
	if handlers.Tick != nil {
		handlers.Tick(now)
	}
}

//go:wasmimport vinbero log
func hostLog(level int32, ptr, length uint32)

//go:wasmimport vinbero now_monotonic
func hostNow() int64

//go:wasmimport vinbero apply_begin
func hostBegin(kind uint32) uint64

//go:wasmimport vinbero apply_put
func hostPut(generation uint64, ptr, length uint32) int32

//go:wasmimport vinbero apply_commit
func hostCommit(generation uint64) int32

//go:wasmimport vinbero apply_abort
func hostAbort(generation uint64)

func pointer(buf []byte) uint32 {
	if len(buf) == 0 {
		return 0
	}
	return uint32(uintptr(unsafe.Pointer(&buf[0])))
}

func Log(level cplane.LogLevel, message string) {
	data := []byte(message)
	hostLog(int32(level), pointer(data), uint32(len(data)))
}
func NowMonotonic() int64 { return hostNow() }

// Host is the WASM declaration transport for cplane.Client. Plugins that only
// observe events need not reference Host; TinyGo removes its unused imports.
type Host struct{}

func (Host) Begin(kind cplane.Kind) uint64 { return hostBegin(uint32(kind)) }
func (Host) Put(gen uint64, chunk []byte) cplane.Status {
	return cplane.Status(hostPut(gen, pointer(chunk), uint32(len(chunk))))
}
func (Host) Commit(gen uint64) cplane.Status { return cplane.Status(hostCommit(gen)) }
func (Host) Abort(gen uint64)                { hostAbort(gen) }
