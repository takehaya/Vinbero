package wasm

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"go.uber.org/zap"
)

// Limits bound what one plugin instance may consume. Zero fields take the
// defaults from DefaultLimits.
type Limits struct {
	// MaxModuleBytes caps the compiled module's source size.
	MaxModuleBytes int
	// MaxMemoryPages caps linear memory, in 64 KiB pages.
	MaxMemoryPages uint32
	// CallTimeout bounds one call into the guest.
	//
	// wazero has no fuel metering: the only way to stop a running guest is
	// to cancel its context, which closes the module. A call that overruns
	// therefore costs the instance, not just the call, and the plugin is
	// re-instantiated and replayed. Budgets are per call rather than per
	// batch of work for that reason -- a long replay is delivered in
	// chunks so each chunk gets its own budget, instead of one deadline
	// that a large RIB is guaranteed to blow.
	CallTimeout time.Duration
	// MaxBufferBytes caps a single buffer handed to or returned by the
	// guest.
	MaxBufferBytes int
}

// DefaultLimits are deliberately modest: a control-plane plugin reacts to
// route events, and one that needs more than this is doing something the
// design did not anticipate, which is worth surfacing as an error rather
// than absorbing silently.
func DefaultLimits() Limits {
	return Limits{
		MaxModuleBytes: 16 << 20, // 16 MiB
		MaxMemoryPages: 256,      // 16 MiB of linear memory
		CallTimeout:    2 * time.Second,
		MaxBufferBytes: 4 << 20, // 4 MiB
	}
}

// withDefaults fills zero fields from DefaultLimits.
func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxModuleBytes <= 0 {
		l.MaxModuleBytes = d.MaxModuleBytes
	}
	if l.MaxMemoryPages == 0 {
		l.MaxMemoryPages = d.MaxMemoryPages
	}
	if l.CallTimeout <= 0 {
		l.CallTimeout = d.CallTimeout
	}
	if l.MaxBufferBytes <= 0 {
		l.MaxBufferBytes = d.MaxBufferBytes
	}
	return l
}

// Errors the admission and call paths return. They are sentinels so the
// RPC layer can map a rejected module to InvalidArgument and a runaway one
// to something an operator reads differently.
var (
	// ErrAdmission means the module was refused before it ever ran.
	ErrAdmission = errors.New("wasm: module rejected")
	// ErrCallTimeout means a call exceeded its budget; the instance is
	// gone and must be re-instantiated.
	ErrCallTimeout = errors.New("wasm: call exceeded its budget")
	// ErrClosed means the instance was closed.
	ErrClosed = errors.New("wasm: instance closed")
)

// HostOps is what a plugin can reach through host functions. The runtime
// itself knows nothing about routes or BPF maps: it moves bytes and
// enforces budgets, and this interface is where the capability surface
// (pkg/cplane) is plugged in.
type HostOps interface {
	// Log records a message from the plugin under its own name.
	Log(level int32, msg string)
	// ApplyBegin opens a desired-set transaction, returning its id.
	ApplyBegin(kind uint32) (uint64, error)
	// ApplyPut appends a serialized chunk to an open transaction.
	ApplyPut(generation uint64, chunk []byte) error
	// ApplyCommit reconciles what the transaction accumulated.
	ApplyCommit(generation uint64) error
	// ApplyAbort discards an open transaction.
	ApplyAbort(generation uint64)
}

// Instance is one running plugin module.
//
// It owns a wazero Runtime of its own rather than sharing one across
// plugins. Host functions are then closed over this instance's identity,
// so a plugin cannot name another plugin's owner tag in a call -- the
// identity is not a parameter it can forge, it is bound at link time.
type Instance struct {
	name     string
	caps     Capabilities
	limits   Limits
	logger   *zap.Logger
	ops      HostOps
	started  time.Time
	runtime  wazero.Runtime
	compiled wazero.CompiledModule

	mu     sync.Mutex
	mod    api.Module
	closed bool

	// callMu serializes every call into the guest.
	//
	// wazero's Function.Call is not goroutine-safe, and a plugin has one
	// linear memory and one allocator behind it: two concurrent calls
	// would have alloc hand out the same offset twice and let one event
	// batch overwrite another. Concurrency is real here rather than
	// theoretical -- a snapshot replay runs on the goroutine that
	// registered the plugin while live updates arrive on the BGP watch
	// goroutine -- so the lock is what makes the instance safe to share.
	callMu sync.Mutex
}

// Config describes one plugin to instantiate.
type Config struct {
	// Name identifies the plugin; it appears in logs and is the identity
	// host functions are bound to.
	Name string
	// Module is the WebAssembly binary.
	Module []byte
	// ConfigBlob is the operator's configuration, passed to the guest's
	// configure export. Deployment-specific settings ride here so changing
	// them does not mean rebuilding the module.
	ConfigBlob []byte
	// Limits bound this instance. Zero fields take defaults.
	Limits Limits
	// Ops is the capability surface host functions call into.
	Ops HostOps
	// Capabilities are what this plugin was granted. Only the host
	// functions they cover are linked, so an ungranted one is not a call
	// that fails but a function the module cannot reach.
	Capabilities Capabilities
	// Logger receives the runtime's own messages and the plugin's.
	Logger *zap.Logger
}

// Instantiate compiles, admits, and starts a plugin module.
//
// The order matters: the module is compiled and checked before anything of
// it runs. wazero would otherwise call a module's start function during
// instantiation, so a module could execute before it had been admitted.
func Instantiate(ctx context.Context, cfg Config) (*Instance, error) {
	if cfg.Name == "" {
		return nil, fmt.Errorf("%w: empty plugin name", ErrAdmission)
	}
	if cfg.Ops == nil {
		return nil, fmt.Errorf("wasm: instantiate %q: nil host ops", cfg.Name)
	}
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	logger = logger.With(zap.String("plugin", cfg.Name))
	limits := cfg.Limits.withDefaults()

	if len(cfg.Module) == 0 {
		return nil, fmt.Errorf("%w: empty module", ErrAdmission)
	}
	if len(cfg.Module) > limits.MaxModuleBytes {
		return nil, fmt.Errorf("%w: module is %d bytes, limit %d",
			ErrAdmission, len(cfg.Module), limits.MaxModuleBytes)
	}

	rtCfg := wazero.NewRuntimeConfig().
		WithMemoryLimitPages(limits.MaxMemoryPages).
		WithCloseOnContextDone(true)
	rt := wazero.NewRuntimeWithConfig(ctx, rtCfg)

	inst := &Instance{
		name:    cfg.Name,
		caps:    cfg.Capabilities,
		limits:  limits,
		logger:  logger,
		ops:     cfg.Ops,
		started: time.Now(),
		runtime: rt,
	}

	compiled, err := rt.CompileModule(ctx, cfg.Module)
	if err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("%w: compile: %w", ErrAdmission, err)
	}
	inst.compiled = compiled

	if err := admit(compiled, cfg.Capabilities); err != nil {
		_ = rt.Close(ctx)
		return nil, err
	}
	if err := inst.linkHost(ctx); err != nil {
		_ = rt.Close(ctx)
		return nil, err
	}

	// WithStartFunctions() clears the default _start: a reactor-style
	// plugin has no main, and running one before the host is ready would
	// execute guest code outside any call budget.
	modCfg := wazero.NewModuleConfig().
		WithName(cfg.Name).
		WithStartFunctions()
	mod, err := rt.InstantiateModule(ctx, compiled, modCfg)
	if err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("wasm: instantiate %q: %w", cfg.Name, err)
	}
	inst.mod = mod

	// Language runtimes that need to initialize do it here. TinyGo and
	// Rust both emit a reactor initializer, and calling an exported
	// function before it has run finds uninitialized globals and traps --
	// which is exactly what a plugin author sees if the host forgets this.
	if err := inst.initialize(ctx); err != nil {
		_ = inst.Close(ctx)
		return nil, err
	}

	// The version is read after initialization, because a language runtime
	// may compute it, and before anything else, so a module built against
	// a different ABI is refused rather than left to trap on the first
	// call into a function whose signature moved.
	if err := inst.checkABIVersion(ctx); err != nil {
		_ = inst.Close(ctx)
		return nil, err
	}

	if err := inst.configure(ctx, cfg.ConfigBlob); err != nil {
		_ = inst.Close(ctx)
		return nil, err
	}
	logger.Info("control-plane plugin instantiated",
		zap.Int("module_bytes", len(cfg.Module)),
		zap.Int("config_bytes", len(cfg.ConfigBlob)),
		zap.Strings("capabilities", cfg.Capabilities.Names()))
	return inst, nil
}

// Name is the plugin's identity.
func (i *Instance) Name() string { return i.name }

// Capabilities are what this plugin was granted.
func (i *Instance) Capabilities() Capabilities { return i.caps }

// Close tears the instance and its runtime down. Safe to call twice.
func (i *Instance) Close(ctx context.Context) error {
	i.mu.Lock()
	if i.closed {
		i.mu.Unlock()
		return nil
	}
	i.closed = true
	i.mu.Unlock()
	return i.runtime.Close(ctx)
}

// initialize runs the guest's reactor initializer, if it has one.
//
// A module without it is fine: a hand-written module with no runtime to
// set up has nothing to do here.
func (i *Instance) initialize(ctx context.Context) error {
	fn := i.mod.ExportedFunction(ExportInitialize)
	if fn == nil {
		return nil
	}
	callCtx, cancel := i.callContext(ctx)
	defer cancel()
	if _, err := fn.Call(callCtx); err != nil {
		return fmt.Errorf("wasm: %s: %w", ExportInitialize, i.classify(callCtx, err))
	}
	return nil
}

// checkABIVersion refuses a module built against an ABI this host does not
// implement.
func (i *Instance) checkABIVersion(ctx context.Context) error {
	fn := i.mod.ExportedFunction(ExportABIVersion)
	if fn == nil {
		return fmt.Errorf("%w: module exports no %q", ErrAdmission, ExportABIVersion)
	}
	callCtx, cancel := i.callContext(ctx)
	defer cancel()
	res, err := fn.Call(callCtx)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrAdmission, ExportABIVersion, i.classify(callCtx, err))
	}
	if len(res) == 0 {
		return fmt.Errorf("%w: %s returned nothing", ErrAdmission, ExportABIVersion)
	}
	if got := int32(res[0]); got != ABIVersion {
		return fmt.Errorf("%w: module declares ABI version %d, this daemon implements %d",
			ErrAdmission, got, ABIVersion)
	}
	return nil
}

// configure hands the operator's config blob to the guest before any event
// is delivered. A guest without the export is accepted: a plugin that
// needs no configuration should not have to carry an empty function.
func (i *Instance) configure(ctx context.Context, blob []byte) error {
	fn := i.mod.ExportedFunction(ExportConfigure)
	if fn == nil {
		if len(blob) > 0 {
			return fmt.Errorf("%w: config supplied but the module exports no %s",
				ErrAdmission, ExportConfigure)
		}
		return nil
	}
	rc, err := i.callWithBuffer(ctx, fn, blob)
	if err != nil {
		return fmt.Errorf("wasm: %s: %w", ExportConfigure, err)
	}
	if rc != 0 {
		return fmt.Errorf("wasm: %s rejected the config (status %d)", ExportConfigure, int32(rc))
	}
	return nil
}

// HandleEvents delivers a serialized event batch and returns the guest's
// serialized status, which is nil when the guest reported nothing.
func (i *Instance) HandleEvents(ctx context.Context, batch []byte) ([]byte, error) {
	i.callMu.Lock()
	defer i.callMu.Unlock()
	fn := i.mod.ExportedFunction(ExportHandleEvents)
	if fn == nil {
		return nil, fmt.Errorf("wasm: module exports no %s", ExportHandleEvents)
	}
	packed, err := i.callWithBuffer(ctx, fn, batch)
	if err != nil {
		return nil, fmt.Errorf("wasm: %s: %w", ExportHandleEvents, err)
	}
	ptr, length := unpackPtrLen(packed)
	if length == 0 {
		return nil, nil
	}
	if int(length) > i.limits.MaxBufferBytes {
		// Give the region back even though the call failed: a plugin that
		// keeps returning an oversized status would otherwise leak its own
		// linear memory once per batch until its allocator gives up.
		i.freeGuest(ctx, ptr, length)
		return nil, fmt.Errorf("wasm: %s returned %d bytes, limit %d",
			ExportHandleEvents, length, i.limits.MaxBufferBytes)
	}
	out, ok := i.mod.Memory().Read(ptr, length)
	if !ok {
		return nil, fmt.Errorf("wasm: %s returned an out-of-range buffer (ptr=%d len=%d)",
			ExportHandleEvents, ptr, length)
	}
	// Copy before the guest may reuse or grow the region: a Go slice into
	// linear memory stops being valid the moment the guest allocates.
	status := append([]byte(nil), out...)
	i.freeGuest(ctx, ptr, length)
	return status, nil
}

// Tick invokes the periodic callback with a monotonic timestamp. A module
// without the export is a no-op, so a purely event-driven plugin need not
// define one.
func (i *Instance) Tick(ctx context.Context, nowNs int64) error {
	i.callMu.Lock()
	defer i.callMu.Unlock()
	fn := i.mod.ExportedFunction(ExportOnTick)
	if fn == nil {
		return nil
	}
	callCtx, cancel := i.callContext(ctx)
	defer cancel()
	if _, err := fn.Call(callCtx, uint64(nowNs)); err != nil {
		return fmt.Errorf("wasm: %s: %w", ExportOnTick, i.classify(callCtx, err))
	}
	return nil
}

// callWithBuffer copies buf into guest memory, calls fn(ptr, len), and
// frees the region afterwards.
//
// The guest allocates and the host writes: the alternative, letting the
// host pick an address, would mean the host deciding what is free inside
// an allocator it does not own.
func (i *Instance) callWithBuffer(ctx context.Context, fn api.Function, buf []byte) (uint64, error) {
	if len(buf) > i.limits.MaxBufferBytes {
		return 0, fmt.Errorf("buffer is %d bytes, limit %d", len(buf), i.limits.MaxBufferBytes)
	}
	callCtx, cancel := i.callContext(ctx)
	defer cancel()

	var ptr uint32
	if len(buf) > 0 {
		allocFn := i.mod.ExportedFunction(ExportAlloc)
		if allocFn == nil {
			return 0, fmt.Errorf("module exports no %s", ExportAlloc)
		}
		res, err := allocFn.Call(callCtx, uint64(len(buf)))
		if err != nil {
			return 0, fmt.Errorf("alloc: %w", i.classify(callCtx, err))
		}
		if len(res) == 0 || res[0] == 0 {
			return 0, errors.New("alloc returned a null pointer")
		}
		ptr = uint32(res[0])
		if !i.mod.Memory().Write(ptr, buf) {
			return 0, fmt.Errorf("writing %d bytes at %d is out of range", len(buf), ptr)
		}
		defer i.freeGuest(ctx, ptr, uint32(len(buf)))
	}

	res, err := fn.Call(callCtx, uint64(ptr), uint64(len(buf)))
	if err != nil {
		return 0, i.classify(callCtx, err)
	}
	if len(res) == 0 {
		return 0, nil
	}
	return res[0], nil
}

// freeGuest returns a region to the guest allocator, best effort: the call
// is already over, and a failing free is worth a log rather than turning a
// successful delivery into an error.
func (i *Instance) freeGuest(ctx context.Context, ptr, length uint32) {
	if ptr == 0 || length == 0 {
		return
	}
	freeFn := i.mod.ExportedFunction(ExportFree)
	if freeFn == nil {
		return
	}
	callCtx, cancel := i.callContext(ctx)
	defer cancel()
	if _, err := freeFn.Call(callCtx, uint64(ptr), uint64(length)); err != nil {
		i.logger.Debug("plugin free failed", zap.Error(err))
	}
}

// callContext applies the per-call budget. Cancelling it closes the
// module, which is why a timeout is reported as an instance-level failure.
func (i *Instance) callContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, i.limits.CallTimeout)
}

// classify turns a wazero error into ErrCallTimeout when the deadline is
// what stopped it, so the caller can tell "this plugin is too slow" from
// "this plugin trapped".
func (i *Instance) classify(callCtx context.Context, err error) error {
	if callCtx.Err() != nil && errors.Is(callCtx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w after %s: %w", ErrCallTimeout, i.limits.CallTimeout, err)
	}
	return err
}
