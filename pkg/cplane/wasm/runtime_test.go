package wasm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

// The fixtures are checked-in WebAssembly built from the .wat sources
// beside them (make cplane-wasm-testdata). Committing the binaries keeps
// the tests hermetic; the text sources are what a reviewer reads.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name+".wasm"))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// recordingOps captures what the host functions were asked to do.
type recordingOps struct {
	mu       sync.Mutex
	logs     []string
	chunks   [][]byte
	commits  []uint64
	aborts   []uint64
	nextGen  uint64
	beginErr error
	putErr   error
	commitAs error
}

func (r *recordingOps) Log(level int32, msg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logs = append(r.logs, fmt.Sprintf("%d:%s", level, msg))
}

func (r *recordingOps) ApplyBegin(uint32) (uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.beginErr != nil {
		return 0, r.beginErr
	}
	r.nextGen++
	return r.nextGen, nil
}

func (r *recordingOps) ApplyPut(_ uint64, chunk []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.putErr != nil {
		return r.putErr
	}
	r.chunks = append(r.chunks, chunk)
	return nil
}

func (r *recordingOps) ApplyCommit(gen uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.commitAs != nil {
		return r.commitAs
	}
	r.commits = append(r.commits, gen)
	return nil
}

func (r *recordingOps) ApplyAbort(gen uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.aborts = append(r.aborts, gen)
}

func (r *recordingOps) snapshot() ([]string, [][]byte, []uint64, []uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.logs...), append([][]byte(nil), r.chunks...),
		append([]uint64(nil), r.commits...), append([]uint64(nil), r.aborts...)
}

func instantiate(t *testing.T, name string, cfg Config) (*Instance, error) {
	t.Helper()
	cfg.Module = fixture(t, name)
	if cfg.Capabilities == nil {
		// Most tests are not about the gate, so they run with everything
		// granted. The ones that are about it pass a set explicitly.
		caps, err := ParseCapabilities([]string{
			string(CapHeadend), string(CapAdvertise), string(CapLocalSID),
		})
		if err != nil {
			t.Fatalf("default capabilities: %v", err)
		}
		cfg.Capabilities = caps
	}
	if cfg.Name == "" {
		cfg.Name = name
	}
	if cfg.Ops == nil {
		cfg.Ops = &recordingOps{}
	}
	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop()
	}
	return Instantiate(context.Background(), cfg)
}

func mustInstantiate(t *testing.T, name string, cfg Config) *Instance {
	t.Helper()
	inst, err := instantiate(t, name, cfg)
	if err != nil {
		t.Fatalf("instantiate %s: %v", name, err)
	}
	t.Cleanup(func() { _ = inst.Close(context.Background()) })
	return inst
}

func TestInstantiateAndRoundTripBatch(t *testing.T) {
	inst := mustInstantiate(t, "echo", Config{})
	batch := []byte("route-event-batch")
	status, err := inst.HandleEvents(context.Background(), batch)
	if err != nil {
		t.Fatalf("handle events: %v", err)
	}
	if !bytes.Equal(status, batch) {
		t.Fatalf("status = %q, want the batch echoed back (%q)", status, batch)
	}
}

// A guest reporting nothing is the common case and must cost no
// allocation: returning 0 means "handled, nothing to say".
func TestHandleEventsEmptyStatus(t *testing.T) {
	inst := mustInstantiate(t, "echo", Config{})
	status, err := inst.HandleEvents(context.Background(), nil)
	if err != nil {
		t.Fatalf("handle events: %v", err)
	}
	if status != nil {
		t.Fatalf("status = %q, want nil", status)
	}
}

func TestConfigureReachesGuest(t *testing.T) {
	blob := []byte("color=100")
	inst := mustInstantiate(t, "echo", Config{ConfigBlob: blob})
	fn := inst.mod.ExportedFunction("config_len")
	res, err := fn.Call(context.Background())
	if err != nil {
		t.Fatalf("config_len: %v", err)
	}
	if int(res[0]) != len(blob) {
		t.Fatalf("guest saw %d config bytes, want %d", res[0], len(blob))
	}
}

// A plugin needing no configuration should not have to carry an empty
// configure export -- but supplying config to a module that cannot receive
// it is a mistake worth reporting rather than dropping.
func TestConfigWithoutConfigureExportIsRejected(t *testing.T) {
	_, err := instantiate(t, "apply", Config{ConfigBlob: []byte("x")})
	if err == nil {
		t.Fatal("config supplied to a module with no configure export was accepted")
	}
	if !errors.Is(err, ErrAdmission) {
		t.Fatalf("error = %v, want ErrAdmission", err)
	}
}

func TestHostLogReachesOps(t *testing.T) {
	ops := &recordingOps{}
	inst := mustInstantiate(t, "echo", Config{Ops: ops})
	ctx := context.Background()

	msg := []byte("hello from the plugin")
	allocRes, err := inst.mod.ExportedFunction(ExportAlloc).Call(ctx, uint64(len(msg)))
	if err != nil {
		t.Fatalf("alloc: %v", err)
	}
	ptr := uint32(allocRes[0])
	if !inst.mod.Memory().Write(ptr, msg) {
		t.Fatal("write to guest memory failed")
	}
	if _, err := inst.mod.ExportedFunction("emit_log").Call(ctx, uint64(ptr), uint64(len(msg))); err != nil {
		t.Fatalf("emit_log: %v", err)
	}

	logs, _, _, _ := ops.snapshot()
	if len(logs) != 1 || logs[0] != "1:hello from the plugin" {
		t.Fatalf("logs = %v, want the plugin's message at level 1", logs)
	}
}

// The clock is monotonic and its epoch is per instance, so a plugin can
// only ever compare two readings.
func TestHostClockIsMonotonic(t *testing.T) {
	inst := mustInstantiate(t, "echo", Config{})
	ctx := context.Background()
	read := func() int64 {
		res, err := inst.mod.ExportedFunction("read_clock").Call(ctx)
		if err != nil {
			t.Fatalf("read_clock: %v", err)
		}
		return int64(res[0])
	}
	first := read()
	time.Sleep(2 * time.Millisecond)
	second := read()
	if second < first {
		t.Fatalf("clock went backwards: %d then %d", first, second)
	}
	if second == first {
		t.Fatalf("clock did not advance across a 2ms sleep: %d", first)
	}
}

// The transaction sequence must reach the capability layer intact: the
// declaration only takes effect at commit.
func TestApplyTransactionReachesOps(t *testing.T) {
	ops := &recordingOps{}
	inst := mustInstantiate(t, "apply", Config{Ops: ops})
	declared := []byte("desired-set-chunk")
	if _, err := inst.HandleEvents(context.Background(), declared); err != nil {
		t.Fatalf("handle events: %v", err)
	}
	_, chunks, commits, aborts := ops.snapshot()
	if len(chunks) != 1 || !bytes.Equal(chunks[0], declared) {
		t.Fatalf("chunks = %v, want the declared set", chunks)
	}
	if len(commits) != 1 {
		t.Fatalf("commits = %v, want exactly one", commits)
	}
	if len(aborts) != 0 {
		t.Fatalf("aborts = %v, want none", aborts)
	}
}

// A chunk that the host refuses must leave the guest able to abort, and
// nothing may be committed.
func TestApplyPutFailureLeadsToAbort(t *testing.T) {
	ops := &recordingOps{putErr: errors.New("malformed chunk")}
	inst := mustInstantiate(t, "apply", Config{Ops: ops})
	if _, err := inst.HandleEvents(context.Background(), []byte("bad")); err != nil {
		t.Fatalf("handle events: %v", err)
	}
	_, _, commits, aborts := ops.snapshot()
	if len(commits) != 0 {
		t.Fatalf("commits = %v, want none after a rejected chunk", commits)
	}
	if len(aborts) != 1 {
		t.Fatalf("aborts = %v, want the guest to have aborted", aborts)
	}
}

// The chunk must be copied out of linear memory: the transaction outlives
// the call, and the guest's allocator will reuse the region.
func TestApplyPutCopiesChunk(t *testing.T) {
	ops := &recordingOps{}
	inst := mustInstantiate(t, "apply", Config{Ops: ops})
	declared := []byte("chunk-bytes")
	if _, err := inst.HandleEvents(context.Background(), declared); err != nil {
		t.Fatalf("handle events: %v", err)
	}
	_, chunks, _, _ := ops.snapshot()
	if len(chunks) != 1 {
		t.Fatalf("chunks = %v, want one", chunks)
	}
	// Scribble over the whole of the guest's memory; the captured chunk
	// must be unaffected.
	mem := inst.mod.Memory()
	zeros := make([]byte, 4096)
	if !mem.Write(0, zeros) {
		t.Fatal("scribbling over guest memory failed")
	}
	if !bytes.Equal(chunks[0], declared) {
		t.Fatalf("captured chunk changed with guest memory: %q", chunks[0])
	}
}

func TestAdmissionRejections(t *testing.T) {
	tests := []struct {
		fixture string
		reason  string
	}{
		{fixture: "wasi", reason: "WASI imports"},
		{fixture: "nomemory", reason: "no exported memory"},
		{fixture: "importmem", reason: "imported memory"},
		{fixture: "badsig", reason: "wrong handle_events signature"},
		{fixture: "noalloc", reason: "missing alloc"},
		{fixture: "unknownhost", reason: "unknown host import"},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			inst, err := instantiate(t, tt.fixture, Config{})
			if err == nil {
				_ = inst.Close(context.Background())
				t.Fatalf("module with %s was admitted", tt.reason)
			}
			if !errors.Is(err, ErrAdmission) {
				t.Fatalf("error = %v, want ErrAdmission (%s)", err, tt.reason)
			}
		})
	}
}

// A guest that never returns is stopped by the call budget. wazero cannot
// preempt, so this costs the instance: the error says so, and the caller
// re-instantiates.
func TestCallBudgetStopsRunawayGuest(t *testing.T) {
	inst := mustInstantiate(t, "spin", Config{
		Limits: Limits{CallTimeout: 50 * time.Millisecond},
	})
	start := time.Now()
	_, err := inst.HandleEvents(context.Background(), []byte("x"))
	if err == nil {
		t.Fatal("a guest that loops forever returned successfully")
	}
	if !errors.Is(err, ErrCallTimeout) {
		t.Fatalf("error = %v, want ErrCallTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("budget took %s to fire", elapsed)
	}
}

// A trap is the guest's panic. It must surface as an error, not take the
// daemon with it.
func TestGuestTrapIsReportedNotFatal(t *testing.T) {
	inst := mustInstantiate(t, "trap", Config{})
	_, err := inst.HandleEvents(context.Background(), []byte("x"))
	if err == nil {
		t.Fatal("a trapping guest returned successfully")
	}
	if errors.Is(err, ErrCallTimeout) {
		t.Fatalf("a trap was misreported as a timeout: %v", err)
	}
	// The host is still healthy afterwards.
	if _, err := instantiate(t, "echo", Config{}); err != nil {
		t.Fatalf("the runtime was unusable after a guest trap: %v", err)
	}
}

func TestModuleSizeLimit(t *testing.T) {
	_, err := instantiate(t, "echo", Config{Limits: Limits{MaxModuleBytes: 8}})
	if err == nil {
		t.Fatal("an oversized module was admitted")
	}
	if !errors.Is(err, ErrAdmission) {
		t.Fatalf("error = %v, want ErrAdmission", err)
	}
}

func TestBufferSizeLimit(t *testing.T) {
	inst := mustInstantiate(t, "echo", Config{Limits: Limits{MaxBufferBytes: 4}})
	if _, err := inst.HandleEvents(context.Background(), []byte("longer than four")); err == nil {
		t.Fatal("an oversized batch was accepted")
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	inst, err := instantiate(t, "echo", Config{})
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	ctx := context.Background()
	if err := inst.Close(ctx); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := inst.Close(ctx); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestInstantiateRejectsEmptyModuleAndName(t *testing.T) {
	ctx := context.Background()
	if _, err := Instantiate(ctx, Config{Name: "x", Ops: &recordingOps{}}); !errors.Is(err, ErrAdmission) {
		t.Fatalf("empty module = %v, want ErrAdmission", err)
	}
	if _, err := Instantiate(ctx, Config{Module: fixture(t, "echo"), Ops: &recordingOps{}}); !errors.Is(err, ErrAdmission) {
		t.Fatalf("empty name = %v, want ErrAdmission", err)
	}
}

// deniedError stands in for a capability-layer refusal (a key another
// owner holds). The runtime recognizes it by behavior, not by identity,
// which is what keeps this package independent of the layer above it.
type deniedError struct{}

func (deniedError) Error() string { return "denied by policy" }
func (deniedError) Denied() bool  { return true }

// A commit refused because another owner holds the key is something the
// plugin can act on, so it must be distinguishable from a host failure.
func TestCommitDeniedIsDistinctFromInternal(t *testing.T) {
	if got := commitStatus(fmt.Errorf("wrapped: %w", deniedError{})); got != StatusDenied {
		t.Errorf("policy refusal mapped to %d, want StatusDenied (%d)", got, StatusDenied)
	}
	if got := commitStatus(errors.New("map write failed")); got != StatusInternal {
		t.Errorf("host failure mapped to %d, want StatusInternal (%d)", got, StatusInternal)
	}
}

func TestPackUnpackPtrLen(t *testing.T) {
	for _, tc := range []struct{ ptr, length uint32 }{
		{0, 0},
		{1024, 16},
		{0xFFFFFFFF, 0xFFFFFFFF},
	} {
		ptr, length := unpackPtrLen(packPtrLen(tc.ptr, tc.length))
		if ptr != tc.ptr || length != tc.length {
			t.Errorf("round trip of (%d, %d) gave (%d, %d)", tc.ptr, tc.length, ptr, length)
		}
	}
}

// A module built against a different ABI is refused at registration. The
// alternative is discovering the mismatch when a call into a function
// whose signature moved traps, which is far harder to read.
func TestABIVersionMismatchIsRejected(t *testing.T) {
	for _, name := range []string{"oldabi", "noabi"} {
		t.Run(name, func(t *testing.T) {
			inst, err := instantiate(t, name, Config{})
			if err == nil {
				_ = inst.Close(context.Background())
				t.Fatal("a module with the wrong ABI version was admitted")
			}
			if !errors.Is(err, ErrAdmission) {
				t.Fatalf("error = %v, want ErrAdmission", err)
			}
		})
	}
}

// The WebAssembly start section runs during instantiation, before the host
// has called anything. WithStartFunctions() does not cover it, so without
// a budget on instantiation itself a module that loops there hangs the
// registration RPC forever rather than being refused.
func TestStartSectionCannotHangRegistration(t *testing.T) {
	start := time.Now()
	inst, err := Instantiate(context.Background(), Config{
		Name:   "spinstart",
		Module: fixture(t, "spinstart"),
		Limits: Limits{CallTimeout: 50 * time.Millisecond},
		Ops:    &recordingOps{},
	})
	if err == nil {
		_ = inst.Close(context.Background())
		t.Fatal("a module whose start section loops forever was instantiated")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("instantiation took %s to give up; the start section is running unbudgeted", elapsed)
	}
}

// A host function imported with the right arity but the wrong types has to
// be refused as a bad module. wazero's linker would refuse it too, but as
// a link failure -- and the caller who can fix it would be told the host
// broke instead.
func TestImportWithWrongTypesIsRefusedAsAdmission(t *testing.T) {
	_, err := Instantiate(context.Background(), Config{
		Name:         "badimport",
		Module:       fixture(t, "badimport"),
		Capabilities: Capabilities{CapHeadend: {}},
		Ops:          &recordingOps{},
	})
	if err == nil {
		t.Fatal("a module importing apply_begin with the wrong types was admitted")
	}
	if !errors.Is(err, ErrAdmission) {
		t.Fatalf("error = %v, want ErrAdmission", err)
	}
}

// The reactor initializer is called with no arguments, so one exported
// under any other shape is a module defect, catchable before it runs.
func TestInitializerWithArgumentsIsRefused(t *testing.T) {
	_, err := Instantiate(context.Background(), Config{
		Name:   "badinit",
		Module: fixture(t, "badinit"),
		Ops:    &recordingOps{},
	})
	if err == nil {
		t.Fatal("a module exporting _initialize with a parameter was admitted")
	}
	if !errors.Is(err, ErrAdmission) {
		t.Fatalf("error = %v, want ErrAdmission", err)
	}
}
