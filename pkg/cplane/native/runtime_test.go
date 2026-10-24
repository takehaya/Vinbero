package native

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/wire"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

type recorder struct {
	begins, puts, commits, aborts, logs int
	chunks                              [][]byte
	failure                             error
	panicCommit                         bool
}

func (r *recorder) Log(int32, string) { r.logs++ }
func (r *recorder) ApplyBegin(kind uint32) (uint64, error) {
	if kind != uint32(cplane.CompositionSet) {
		return 0, errors.New("wrong kind")
	}
	r.begins++
	return uint64(r.begins), nil
}
func (r *recorder) ApplyPut(_ uint64, chunk []byte) error {
	r.puts++
	r.chunks = append(r.chunks, chunk)
	return nil
}
func (r *recorder) ApplyCommit(uint64) error {
	r.commits++
	if r.panicCommit {
		panic("commit panic")
	}
	return r.failure
}
func (r *recorder) ApplyAbort(uint64) { r.aborts++ }

func configuration(observe bool) []byte {
	var b, ctx wire.Encoder
	b.Uint(1, 1)
	payload := `{"context":"mobile","source":"fd00:feed::1","args_offset":7,"observe_only":false}`
	if observe {
		payload = strings.Replace(payload, "false", "true", 1)
	}
	b.Bytes(2, []byte(payload))
	b.String(3, cplane.BGPPathCodec)
	ctx.String(1, "mobile")
	ctx.String(2, "mup_ipv4")
	ctx.String(2, "mup_ipv6")
	b.Message(4, ctx)
	return b
}
func config(r *recorder, observe bool) Config {
	id := MUPComposition
	if observe {
		id = MUPCompositionObserver
	}
	return Config{Config: wasm.Config{Name: "test", Ops: r, ConfigBlob: configuration(observe), Capabilities: wasm.Capabilities{wasm.CapMUP: {}}}, Implementation: id, Version: ImplementationVersion}
}
func replay() []byte {
	var batch wire.Encoder
	for _, kind := range []cplane.EventKind{cplane.EventStartOfReplay, cplane.EventEndOfReplay} {
		var e wire.Encoder
		e.Uint(1, uint64(kind))
		e.String(5, cplane.BGPSource)
		batch.Message(1, e)
	}
	return batch
}
func instantiate(t *testing.T, r *recorder, observe bool) *Instance {
	t.Helper()
	i, err := Instantiate(context.Background(), config(r, observe))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = i.Close(context.Background()) })
	return i
}

func TestCatalogAndAdmission(t *testing.T) {
	write, ok := Lookup(MUPComposition)
	if !ok || !write.Write || len(write.Identity) != 64 {
		t.Fatalf("descriptor: %+v", write)
	}
	observe, ok := Lookup(MUPCompositionObserver)
	if !ok || observe.Write || observe.Identity == write.Identity {
		t.Fatalf("observer descriptor: %+v", observe)
	}
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{"unknown", func(c *Config) { c.Implementation = "missing" }},
		{"version", func(c *Config) { c.Version = "2" }},
		{"empty name", func(c *Config) { c.Name = "" }},
		{"module", func(c *Config) { c.Module = []byte{1} }},
		{"no host", func(c *Config) { c.Ops = nil }},
		{"no write grant", func(c *Config) { c.Capabilities = nil }},
		{"observer cannot write", func(c *Config) { c.Implementation = MUPCompositionObserver }},
		{"bad envelope", func(c *Config) { c.ConfigBlob = []byte(`{}`) }},
		{"config buffer", func(c *Config) { c.Limits.MaxBufferBytes = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &recorder{}
			cfg := config(r, false)
			tc.change(&cfg)
			_, err := Instantiate(context.Background(), cfg)
			if !errors.Is(err, wasm.ErrAdmission) {
				t.Fatalf("error: %v", err)
			}
			if r.begins+r.puts+r.commits != 0 {
				t.Fatal("rejected configuration wrote host state")
			}
		})
	}
	cfg := config(&recorder{}, true)
	cfg.Capabilities = nil
	i, err := Instantiate(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	_ = i.Close(context.Background())
}

func TestEncodedReplayRetryAndIndependentInstances(t *testing.T) {
	r := &recorder{failure: errors.New("commit refused")}
	i := instantiate(t, r, false)
	if out, err := i.HandleEvents(context.Background(), replay()); err != nil || len(out) != 0 {
		t.Fatalf("status=%x err=%v", out, err)
	}
	if r.commits != 1 || r.puts != 1 {
		t.Fatalf("host: %+v", r)
	}
	var chunk v1.PluginApplyChunk
	if err := proto.Unmarshal(r.chunks[0], &chunk); err != nil || chunk.DesiredRevision != 2 {
		t.Fatalf("chunk=%+v err=%v", &chunk, err)
	}
	r.failure = nil
	if err := i.Tick(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if r.commits != 2 {
		t.Fatal("failed revision not retried")
	}
	_ = i.Tick(context.Background(), 2)
	if r.commits != 2 {
		t.Fatal("successful revision retried")
	}
	other := &recorder{}
	second := instantiate(t, other, false)
	_ = second.Tick(context.Background(), 3)
	if other.commits != 0 {
		t.Fatal("instances shared ready state")
	}
	if _, err := second.HandleEvents(context.Background(), replay()); err != nil || other.commits != 1 {
		t.Fatalf("other: %+v err=%v", other, err)
	}
	observer := &recorder{}
	readOnly := instantiate(t, observer, true)
	if _, err := readOnly.HandleEvents(context.Background(), replay()); err != nil || observer.begins != 0 {
		t.Fatalf("observer wrote: %+v %v", observer, err)
	}
}

func TestEventStatusesAndBuffers(t *testing.T) {
	i := instantiate(t, &recorder{}, false)
	var e, b wire.Encoder
	e.Uint(1, uint64(cplane.EventRoute))
	e.Uint(2, 42)
	b.Message(1, e)
	out, err := i.HandleEvents(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	var status v1.PluginEventStatus
	if err := proto.Unmarshal(out, &status); err != nil || len(status.Results) != 1 || status.Results[0].Sequence != 42 || status.Results[0].Disposition != v1.PluginEventDisposition_PLUGIN_EVENT_DISPOSITION_INPUT_INCOMPLETE {
		t.Fatalf("status=%+v err=%v", &status, err)
	}
	if _, err := i.HandleEvents(context.Background(), []byte{0xff}); err == nil {
		t.Fatal("malformed batch accepted")
	}
	i.limit = 1
	if _, err := i.HandleEvents(context.Background(), replay()); err == nil {
		t.Fatal("oversized batch accepted")
	}
	resultLimited := instantiate(t, &recorder{}, false)
	resultLimited.limit = len(b)
	if out, err := resultLimited.HandleEvents(context.Background(), b); err == nil || out != nil {
		t.Fatalf("oversized result accepted: %x %v", out, err)
	}
}

func TestPanicCloseAndCooperativeCancellation(t *testing.T) {
	r := &recorder{panicCommit: true}
	i := instantiate(t, r, false)
	if _, err := i.HandleEvents(context.Background(), replay()); !errors.Is(err, ErrPanic) {
		t.Fatalf("panic error: %v", err)
	}
	if r.aborts != 1 {
		t.Fatal("panicked transaction was not aborted")
	}
	if err := i.Tick(context.Background(), 0); !errors.Is(err, ErrClosed) {
		t.Fatalf("panic instance not closed: %v", err)
	}
	if err := i.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	j := instantiate(t, &recorder{}, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := j.HandleEvents(ctx, replay()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	err := j.call(ctx, func() error { cancel(); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cooperative cancellation: %v", err)
	}
	if err := j.Tick(context.Background(), 0); !errors.Is(err, ErrClosed) {
		t.Fatalf("canceled instance not closed: %v", err)
	}
}

type deniedError struct{}

func (deniedError) Error() string { return "denied" }
func (deniedError) Denied() bool  { return true }

func TestHostStatusOwnershipAndLogLimits(t *testing.T) {
	r := &recorder{}
	h := &host{ops: r, logger: zap.NewNop(), limit: 4, active: context.Background()}
	input := []byte{1, 2}
	if h.Put(1, input) != cplane.StatusOK {
		t.Fatal("put failed")
	}
	input[0] = 9
	if r.chunks[0][0] != 1 {
		t.Fatal("host retained borrowed input")
	}
	if h.Put(1, make([]byte, 5)) != cplane.StatusInvalid || h.Put(0, nil) != cplane.StatusInvalid {
		t.Fatal("buffer or generation not bounded")
	}
	r.failure = fmtWrappedDenied()
	if h.Commit(1) != cplane.StatusDenied {
		t.Fatal("denial status lost")
	}
	r.failure = errors.New("failure")
	if h.Commit(1) != cplane.StatusInternal {
		t.Fatal("internal status lost")
	}
	for range 64 {
		h.log(cplane.LogInfo, "bounded")
	}
	h.log(cplane.LogInfo, "dropped")
	if r.logs != 64 || h.logDropped != 1 {
		t.Fatalf("log budget: %+v %+v", r, h)
	}
	h.logWindow = time.Time{}
	h.log(cplane.LogInfo, strings.Repeat("x", 4097))
	if r.logs != 64 || h.logCount != 1 {
		t.Fatal("oversized log escaped or did not consume budget")
	}
	h.active = nil
	if h.Begin(cplane.CompositionSet) != 0 || h.Commit(1) != cplane.StatusInternal || r.aborts != 1 {
		t.Fatal("inactive host accepted a transaction")
	}
}
func fmtWrappedDenied() error { return errors.Join(errors.New("wrapped"), deniedError{}) }
