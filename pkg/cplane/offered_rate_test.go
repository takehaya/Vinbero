package cplane

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	gp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/cplane/native"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	"google.golang.org/protobuf/proto"
)

// This opt-in experiment exercises the real manager, policy, worker and host
// reconciler with in-memory forwarding maps. It does not measure BGP transport
// or BPF writes. Per-call budgets and queue/hold limits retain their production
// defaults; the live-delivery batch policy is selected explicitly.
//
// VINBERO_CPLANE_OFFERED_RATE=1 VINBERO_CPLANE_BACKEND=native|wasm
// VINBERO_CPLANE_RATE=<updates/s> VINBERO_CPLANE_DURATION=10s
//
//	(or VINBERO_CPLANE_BURST=512, without RATE or DURATION)
//
// VINBERO_CPLANE_TRACE_DIR=<new directory>
// VINBERO_CPLANE_WASM=<fresh writing module> (required for wasm)
// VINBERO_CPLANE_BATCH_EVENTS=1|16 (default 1; host live-delivery policy)
// go test ./pkg/cplane -run '^TestCplaneOfferedRate$' -count=1 -timeout=10m
func TestCplaneOfferedRate(t *testing.T) {
	if os.Getenv("VINBERO_CPLANE_OFFERED_RATE") != "1" {
		t.Skip("set VINBERO_CPLANE_OFFERED_RATE=1 to run the offered-rate experiment")
	}
	dir := os.Getenv("VINBERO_CPLANE_TRACE_DIR")
	if dir == "" {
		t.Fatal("VINBERO_CPLANE_TRACE_DIR must name a new directory")
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	r := &offeredReport{Origin: time.Now(), GoVersion: runtime.Version(), GOMAXPROCS: runtime.GOMAXPROCS(0)}
	defer func() {
		r.Passed = !t.Failed() && r.Drained && r.ReferenceEqual
		if err := r.write(dir); err != nil {
			t.Errorf("save offered-rate evidence: %v", err)
		}
	}()
	if err := r.run(t, dir); err != nil {
		r.Error = err.Error()
		t.Error(err)
	}
}

type offeredEmit struct {
	Tag                          uint32
	Session                      int
	PlannedNS, DecisionNS        int64
	EmitStartNS, EmitEndNS       int64
	Missed, CallbackFound        bool
	ObservedLive, ObservedReplay int
}

type offeredEvent struct {
	Kind     string
	Sequence uint64
	Tag      uint32
	InReplay bool
	Epoch    uint64
}

type offeredCall struct {
	ID                           uint64
	PrepareStartNS, PrepareEndNS int64
	EntryNS, ReturnNS            int64
	InstanceChange               bool
	Events                       []offeredEvent
	InputTags                    []uint32
	PrepareError, Error          string
	Status                       []byte
	DecodedStatus                *v1.PluginEventStatus
	StatusDecodeError            string
}

type offeredSample struct {
	TimeNS                                              int64
	Stats                                               PluginStats
	Submitted, Processed, Dropped                       uint64
	Queue, Pending                                      int
	Holding, OwesSnapshot, Snapshotting, InputReplaying bool
}

func (s offeredSample) ready() bool {
	return s.Stats.InputReady && s.Stats.InputFault == "" && !s.Stats.CleanupPending &&
		!s.Stats.Dead && s.Stats.PendingDeclarations == 0 && s.Stats.OutputFailure == "" &&
		s.Stats.DesiredRevision > 0 && s.Stats.DesiredRevision == s.Stats.AppliedRevision &&
		s.Submitted == s.Processed && s.Queue == 0 && s.Pending == 0 &&
		!s.Holding && !s.OwesSnapshot && !s.Snapshotting && !s.InputReplaying
}

type offeredMaps struct {
	V4, V6                                                     map[string]bpf.HeadendEntry
	Owner4, Owner6                                             map[string]bpf.OwnerTag
	Uplinks4, Uplinks6, UplinkEntries, FDB, Peers, PeerEntries int
}

type offeredFailure struct {
	TimeNS int64
	Error  string
}

type offeredOutcomes struct {
	Emitted, SchedulerMissed, CallbackMissing            int
	ObservedLiveTags, ObservedReplayTags, UnobservedTags int
	LiveObservations, ReplayObservations                 int
	HandlerCalls, HandlerErrors, PrepareErrors           int
	ReplayStarts, ReplayEnds, ObservedInstanceChanges    int
	RuntimeFailures                                      int
}

type offeredReport struct {
	BatchEvents                                    int
	Origin                                         time.Time
	GoVersion                                      string
	GOMAXPROCS                                     int
	Backend, Mode, ModuleSHA256, InputSHA256       string
	Rate, Slots                                    int
	DurationNS, LoadStartNS, LoadEndNS, DrainEndNS int64
	Passed, Drained, ReferenceEqual                bool
	Error                                          string
	Initial, Final, Reference                      offeredSample
	FinalMaps, ReferenceMaps                       offeredMaps
	InitialRIB, FinalRIB                           []bgp.RouteEvent
	Emits                                          []offeredEmit
	Calls                                          []offeredCall
	Samples                                        []offeredSample
	Failures                                       []offeredFailure
	Outcomes                                       offeredOutcomes
	Notes                                          []string
	mu                                             sync.Mutex
}

func (r *offeredReport) now() int64 { return time.Since(r.Origin).Nanoseconds() }

func (r *offeredReport) run(t *testing.T, dir string) error {
	r.Backend = os.Getenv("VINBERO_CPLANE_BACKEND")
	if r.Backend != BackendNative && r.Backend != BackendWASM {
		return fmt.Errorf("VINBERO_CPLANE_BACKEND must be native or wasm")
	}
	burst, rate := os.Getenv("VINBERO_CPLANE_BURST"), os.Getenv("VINBERO_CPLANE_RATE")
	if burst != "" {
		if burst != "512" || rate != "" || os.Getenv("VINBERO_CPLANE_DURATION") != "" {
			return fmt.Errorf("burst must be 512 and excludes RATE and DURATION")
		}
		r.Mode, r.Slots = "burst", 512
	} else {
		var err error
		r.Rate, err = strconv.Atoi(rate)
		if err != nil || r.Rate < 1 || r.Rate > 10000 {
			return fmt.Errorf("RATE must be 1..10000 updates/s")
		}
		duration := os.Getenv("VINBERO_CPLANE_DURATION")
		if duration == "" {
			duration = "10s"
		}
		d, err := time.ParseDuration(duration)
		if err != nil || d < time.Second || d > time.Minute {
			return fmt.Errorf("DURATION must be 1s..60s")
		}
		r.Mode, r.DurationNS = "rate", int64(d)
		r.Slots = int((int64(d)*int64(r.Rate) + int64(time.Second) - 1) / int64(time.Second))
		if r.Slots > 100000 {
			return fmt.Errorf("experiment is bounded to 100000 offered slots")
		}
	}
	reg, err := offeredRegistration(r.Backend)
	if err != nil {
		return err
	}
	r.BatchEvents = int(reg.Input.MaxBatchEvents)
	if len(reg.Module) != 0 {
		sum := sha256.Sum256(reg.Module)
		r.ModuleSHA256 = hex.EncodeToString(sum[:])
	}
	r.InitialRIB = make([]bgp.RouteEvent, 65)
	for i := 0; i < 64; i++ {
		r.InitialRIB[i] = offeredSession(t, i, 0)
	}
	r.InitialRIB[64] = offeredDiscovery(t)
	updates := make([]bgp.RouteEvent, r.Slots)
	r.Emits = make([]offeredEmit, r.Slots)
	for i := range updates {
		tag, session := uint32(i+1), i%64
		updates[i] = offeredSession(t, session, tag)
		initialKey, ok := inputSDKRoute(EncodeRouteEvent(r.InitialRIB[session])).BGPKey()
		updateKey, updateOK := inputSDKRoute(EncodeRouteEvent(updates[i])).BGPKey()
		if !ok || !updateOK || initialKey != updateKey || updates[i].Source.PathID != 0 {
			return fmt.Errorf("tag %d changed the session BGP key", tag)
		}
		r.Emits[i] = offeredEmit{Tag: tag, Session: session}
	}
	// The exact planned wire inputs are frozen before any instance or timer starts.
	inputFile, err := os.Create(filepath.Join(dir, "inputs.bin"))
	if err != nil {
		return err
	}
	hash := sha256.New()
	for _, events := range [][]bgp.RouteEvent{r.InitialRIB, updates} {
		for _, event := range events {
			raw, e := proto.MarshalOptions{Deterministic: true}.Marshal(EncodeRouteEvent(event))
			if e != nil {
				inputFile.Close()
				return e
			}
			var size [4]byte
			binary.BigEndian.PutUint32(size[:], uint32(len(raw)))
			for _, part := range [][]byte{size[:], raw} {
				if _, e = inputFile.Write(part); e != nil {
					inputFile.Close()
					return e
				}
				hash.Write(part)
			}
		}
	}
	if err = inputFile.Close(); err != nil {
		return err
	}
	r.InputSHA256 = hex.EncodeToString(hash.Sum(nil))
	src := &compositionSource{newFakeSource()}
	src.setRib(r.InitialRIB...)
	maps := newServiceFake()
	m, err := offeredManager(src, maps)
	if err != nil {
		return err
	}
	defer m.Close(context.Background())
	if err = m.Register(context.Background(), reg); err != nil {
		return err
	}
	if r.Initial, err = r.drain(m, reg.Name); err != nil {
		return fmt.Errorf("initial replay: %w", err)
	}
	if r.Initial.Stats.HeadendEntries != 64 {
		return fmt.Errorf("initial replay produced %d headends, want 64", r.Initial.Stats.HeadendEntries)
	}
	if err = r.instrument(m, reg.Name, maps); err != nil {
		return err
	}
	// Exclude the instrumentation barrier from the load's submitted/processed
	// deltas. This is the last readiness wait before open-loop emission starts.
	if r.Initial, err = r.drain(m, reg.Name); err != nil {
		return fmt.Errorf("observation setup: %w", err)
	}
	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				s := r.sample(m, reg.Name)
				r.mu.Lock()
				r.Samples = append(r.Samples, s)
				r.mu.Unlock()
			}
		}
	}()
	var stopOnce sync.Once
	stopSampling := func() { stopOnce.Do(func() { close(stop); <-stopped }) }
	defer stopSampling()
	r.LoadStartNS = r.now()
	for i := range updates {
		e := &r.Emits[i]
		e.PlannedNS = r.LoadStartNS
		if r.Mode == "rate" {
			e.PlannedNS += int64(i) * int64(time.Second) / int64(r.Rate)
			if wait := e.PlannedNS - r.now(); wait > 0 {
				time.Sleep(time.Duration(wait))
			}
		}
		e.DecisionNS = r.now()
		if r.Mode == "rate" {
			next := r.LoadStartNS + int64(i+1)*int64(time.Second)/int64(r.Rate)
			if end := r.LoadStartNS + r.DurationNS; next > end {
				next = end
			}
			if e.DecisionNS >= next {
				e.Missed = true
				continue
			}
		}
		// SnapshotTo takes a copy under this same lock. Skipped slots never enter
		// the authoritative RIB. An emitted update survives a queue drop there.
		src.mu.Lock()
		src.rib[e.Session] = updates[i]
		src.mu.Unlock()
		e.EmitStartNS = r.now()
		e.CallbackFound = src.emit(reg.Name, updates[i])
		e.EmitEndNS = r.now()
	}
	if r.Mode == "rate" {
		if wait := r.LoadStartNS + r.DurationNS - r.now(); wait > 0 {
			time.Sleep(time.Duration(wait))
		}
	}
	r.LoadEndNS = r.now()
	r.Final, err = r.drain(m, reg.Name)
	r.DrainEndNS = r.now()
	r.Drained = err == nil
	stopSampling()
	src.mu.Lock()
	r.FinalRIB = append([]bgp.RouteEvent(nil), src.rib...)
	src.mu.Unlock()
	r.FinalMaps = offeredMapSnapshot(maps)
	if err != nil {
		return fmt.Errorf("final drain: %w", err)
	}
	// A fresh native instance receives only the latest authoritative RIB. It
	// independently checks eventual state after drops/replays of either backend.
	refSrc := &compositionSource{newFakeSource()}
	refSrc.setRib(r.FinalRIB...)
	refMaps := newServiceFake()
	ref, err := offeredManager(refSrc, refMaps)
	if err != nil {
		return err
	}
	defer ref.Close(context.Background())
	refReg, err := offeredRegistration(BackendNative)
	if err != nil {
		return err
	}
	if err = ref.Register(context.Background(), refReg); err != nil {
		return err
	}
	if r.Reference, err = r.drain(ref, refReg.Name); err != nil {
		return fmt.Errorf("reference replay: %w", err)
	}
	r.ReferenceMaps = offeredMapSnapshot(refMaps)
	r.ReferenceEqual = reflect.DeepEqual(r.FinalMaps, r.ReferenceMaps) && len(r.FinalMaps.V4) == 64 &&
		len(r.FinalMaps.V6) == 0 && r.FinalMaps.Uplinks4 == 0 && r.FinalMaps.Uplinks6 == 0 &&
		r.FinalMaps.UplinkEntries == 0 && r.FinalMaps.FDB == 0 && r.FinalMaps.Peers == 0 && r.FinalMaps.PeerEntries == 0
	if !r.ReferenceEqual {
		return fmt.Errorf("final forwarding maps differ from the fresh full-replay reference or expected downlink-only inventory")
	}
	for _, e := range r.Emits {
		if !e.Missed && !e.CallbackFound {
			return fmt.Errorf("tag %d had no source subscription callback", e.Tag)
		}
	}
	return nil
}

func offeredRegistration(backend string) (Registration, error) {
	batchEvents := os.Getenv("VINBERO_CPLANE_BATCH_EVENTS")
	if batchEvents == "" {
		batchEvents = "1"
	}
	if batchEvents != "1" && batchEvents != "16" {
		return Registration{}, fmt.Errorf("BATCH_EVENTS must be 1 or 16")
	}
	batchLimit, _ := strconv.Atoi(batchEvents)
	scope, err := ParseScope(ScopeSpec{HeadendPrefixes: []string{"10.64.0.0/16"}})
	if err != nil {
		return Registration{}, err
	}
	caps, err := wasm.ParseCapabilities([]string{"headend", "mup"})
	if err != nil {
		return Registration{}, err
	}
	reg := Registration{Name: "offered-rate", Backend: backend, Scope: scope, Capabilities: caps,
		Config: []byte(`{"context":"mobile","source":"fd00:feed::1","args_offset":7,"observe_only":false}`),
		Input:  &v1.CplaneInputPolicy{Version: 1, Contexts: []*v1.CplaneInputContext{{Name: "mobile", Grants: []*v1.CplaneInputGrant{{Families: []string{"mup_ipv4", "mup_ipv6"}, RouteTargets: []string{"65000:7"}}}, DelegateMupTypes: []uint32{3}}}},
	}
	reg.Input.MaxBatchEvents = uint32(batchLimit)
	if backend == BackendNative {
		reg.NativeID, reg.NativeVersion = native.MUPComposition, native.ImplementationVersion
	} else {
		path := os.Getenv("VINBERO_CPLANE_WASM")
		if path == "" {
			return reg, fmt.Errorf("WASM requires an explicit fresh VINBERO_CPLANE_WASM module")
		}
		reg.Module, err = os.ReadFile(path)
	}
	return reg, err
}

func offeredManager(src *compositionSource, maps *serviceFake) (*Manager, error) {
	return NewManager(ManagerConfig{AllowNative: true, Source: src, Headend: maps, ForwardingMaps: maps,
		ResolveMUPInstance: func(string) (uint32, error) { return 7, nil },
		ResolveInputTarget: func(bgp.RouteEvent) (string, uint16, bool) { return "", 0, true },
	})
}

func offeredSession(t *testing.T, session int, tag uint32) bgp.RouteEvent {
	var teid [4]byte
	value := uint32(256)
	if tag != 0 {
		value = 1024 + tag
	}
	binary.BigEndian.PutUint32(teid[:], value)
	prefix := fmt.Sprintf("10.64.0.%d/32", session)
	n := gp.NewMUPType1SessionTransformedRoute(gp.NewRouteDistinguisherTwoOctetAS(65000, 7), netip.MustParsePrefix(prefix), netip.AddrFrom4(teid), 9, netip.MustParseAddr("172.16.0.1"), nil)
	r := nativeInput(t, n, rtAttribute("65000:7"))
	r.BgpPath.RouteKey = []byte(prefix)
	return bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, Source: bgp.PathSource{Peer: netip.MustParseAddr(r.Peer)},
		MUP:     &bgp.MUPRoute{Type: bgp.MUPRouteTypeT1ST, RD: "65000:7", RTs: []string{"65000:7"}, Prefix: prefix, TEID: value, TEIDLen: 32, QFI: 9, Endpoint: "172.16.0.1"},
		BGPPath: &bgp.EncodedBGPPath{Codec: r.BgpPath.Codec, AFI: uint16(r.BgpPath.Afi), SAFI: uint8(r.BgpPath.Safi), NLRI: r.BgpPath.Nlri, RouteKey: r.BgpPath.RouteKey, Attributes: r.BgpPath.Attributes, Metadata: bgp.BGPPathMetadata{LocalPathID: tag}},
	}
}

func offeredDiscovery(t *testing.T) bgp.RouteEvent {
	n := gp.NewMUPInterworkSegmentDiscoveryRoute(gp.NewRouteDistinguisherTwoOctetAS(65000, 7), netip.MustParsePrefix("172.16.0.0/24"))
	sid := gp.NewPathAttributePrefixSID(gp.NewSRv6ServiceTLV(gp.TLVTypeSRv6L3Service, gp.NewSRv6InformationSubTLV(netip.MustParseAddr("fd00:a:0:100::"), gp.ENDM_GTP4E, gp.NewSRv6SIDStructureSubSubTLV(32, 16, 8, 72, 0, 0))))
	r := nativeInput(t, n, rtAttribute("65000:7"), sid)
	return bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, Source: bgp.PathSource{Peer: netip.MustParseAddr(r.Peer)},
		MUP:     &bgp.MUPRoute{Type: bgp.MUPRouteTypeISD, RD: "65000:7", RTs: []string{"65000:7"}, Prefix: "172.16.0.0/24"},
		BGPPath: &bgp.EncodedBGPPath{Codec: r.BgpPath.Codec, AFI: uint16(r.BgpPath.Afi), SAFI: uint8(r.BgpPath.Safi), NLRI: r.BgpPath.Nlri, RouteKey: r.BgpPath.RouteKey, Attributes: r.BgpPath.Attributes},
	}
}

func (r *offeredReport) sample(m *Manager, name string) offeredSample {
	s := offeredSample{TimeNS: r.now()}
	s.Stats, _ = m.StatsFor(name)
	m.mu.Lock()
	p := m.plugins[name]
	s.Snapshotting = p.snapshotting
	m.mu.Unlock()
	w := p.worker
	w.mu.Lock()
	s.Submitted, s.Processed, s.Dropped = w.submitted, w.processed, w.dropped
	s.Queue, s.Pending, s.Holding, s.OwesSnapshot = len(w.queue), len(w.pending), w.holding, w.owesSnapshot
	w.mu.Unlock()
	p.ops.mu.Lock()
	s.InputReplaying = p.ops.inputReplaying
	p.ops.mu.Unlock()
	return s
}

func (r *offeredReport) drain(m *Manager, name string) (offeredSample, error) {
	deadline := time.Now().Add(time.Minute)
	var previous offeredSample
	for {
		s := r.sample(m, name)
		if s.ready() && previous.ready() && s.Submitted == previous.Submitted && s.Processed == previous.Processed {
			return s, nil
		}
		if s.Stats.Dead || time.Now().After(deadline) {
			return s, fmt.Errorf("not ready within drain limit: %+v", s)
		}
		previous = s
		time.Sleep(10 * time.Millisecond)
	}
}

func (r *offeredReport) instrument(m *Manager, name string, maps *serviceFake) error {
	m.mu.Lock()
	p := m.plugins[name]
	m.mu.Unlock()
	ready := make(chan struct{})
	if !p.worker.submitBarrier(func() {
		w, prepare, fail := p.worker, p.worker.prepare, p.worker.onFail
		var id, epoch uint64
		var replay bool
		last := p.inst
		// Restart replaces worker.handler. prepare remains worker-owned and wraps
		// the current instance anew before every call, including after a restart.
		w.prepare = func(batch *v1.PluginEventBatch) (*v1.PluginEventBatch, error) {
			id++
			call := offeredCall{ID: id, PrepareStartNS: r.now()}
			for _, e := range batch.Events {
				call.InputTags = append(call.InputTags, e.GetRoute().GetBgpPath().GetMetadata().GetLocalPathId())
			}
			prepared, err := prepare(batch)
			call.PrepareEndNS = r.now()
			if err != nil {
				call.PrepareError = err.Error()
				r.mu.Lock()
				r.Calls = append(r.Calls, call)
				r.mu.Unlock()
				return prepared, err
			}
			for _, e := range prepared.Events {
				if e.Kind == v1.PluginEventKind_PLUGIN_EVENT_KIND_START_OF_REPLAY {
					epoch++
					replay = true
				}
				call.Events = append(call.Events, offeredEvent{Kind: e.Kind.String(), Sequence: e.Sequence, Tag: e.GetRoute().GetBgpPath().GetMetadata().GetLocalPathId(), InReplay: replay, Epoch: epoch})
				if e.Kind == v1.PluginEventKind_PLUGIN_EVENT_KIND_END_OF_REPLAY {
					replay = false
				}
			}
			m.mu.Lock()
			current := p.inst
			m.mu.Unlock()
			call.InstanceChange, last = current != last, current
			w.handler = func(ctx context.Context, raw []byte) ([]byte, error) {
				call.EntryNS = r.now()
				status, err := current.HandleEvents(ctx, raw)
				call.ReturnNS = r.now()
				call.Status = append([]byte(nil), status...)
				if err != nil {
					call.Error = err.Error()
				}
				r.mu.Lock()
				r.Calls = append(r.Calls, call)
				r.mu.Unlock()
				// fakeHeadendOps normally retains every write for assertions. Bound
				// that unused history outside the measured handler interval.
				maps.mu.Lock()
				maps.writes = maps.writes[:0]
				maps.mu.Unlock()
				return status, err
			}
			return prepared, nil
		}
		w.onFail = func(err error) {
			r.mu.Lock()
			r.Failures = append(r.Failures, offeredFailure{TimeNS: r.now(), Error: err.Error()})
			r.mu.Unlock()
			fail(err)
		}
		maps.mu.Lock()
		maps.writes = maps.writes[:0]
		maps.mu.Unlock()
		close(ready)
	}) {
		return fmt.Errorf("worker stopped before installing observation hooks")
	}
	select {
	case <-ready:
		return nil
	case <-time.After(time.Minute):
		return fmt.Errorf("observation barrier timed out")
	}
}

func offeredMapSnapshot(f *serviceFake) offeredMaps {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := offeredMaps{V4: map[string]bpf.HeadendEntry{}, V6: map[string]bpf.HeadendEntry{}, Owner4: cloneMap(f.owner4), Owner6: cloneMap(f.owner6),
		Uplinks4: len(f.uplinks), Uplinks6: len(f.uplinks6), UplinkEntries: len(f.entries), FDB: len(f.fdb), Peers: len(f.peers), PeerEntries: len(f.peerEntries)}
	for k, v := range f.v4 {
		s.V4[k] = *v
	}
	for k, v := range f.v6 {
		s.V6[k] = *v
	}
	return s
}

func (r *offeredReport) write(dir string) error {
	// All worker and sampler goroutines have stopped before this deferred writer.
	r.Notes = []string{
		"N=64 ST1 sessions plus one ISD; updates replace stable keys using unique TEIDs and non-key metadata tags.",
		"inputs.bin contains 65 initial PluginRoute frames then every planned update, each prefixed by its big-endian uint32 byte length; skipped slots do not enter the authoritative RIB.",
		"All *_ns timestamps are monotonic offsets from Origin; origin includes untimed fixture construction, initialization and replay.",
		"callback_found only means the source found and invoked a subscription; it does not prove queue acceptance.",
		"Live emit-start/end to handler-entry values bound an emit-call-based pre-handler interval, including policy preparation and encoding; they are not exact queue residence times. Negative lower bounds are retained.",
		"Observed replay tags are duplicates or recovery observations, not separate successful live updates; no emit-based latency is assigned to them.",
		"Handler service spans only HandleEvents. Instrumentation and 100ms full-stat sampling still consume resources outside this span and affect offered-load behavior.",
		"Stats snapshots are not atomic across subsystems. DroppedEvents counts batches, can overlap replay, and cannot be assigned exactly to individual update tags.",
		"Stats.Restarts is consecutive failures since the last successful call, not a cumulative count. Runtime failure callbacks and observed instance changes are recorded separately.",
		"Passed means initial readiness, final drain and final full-replay map equivalence; it does not assert that every emitted update was delivered or that transient failures did not occur.",
		"Final non-headend maps are expected empty and remain immutable in this downlink-only fixture; the forwarding sink is in-memory, not BPF. Optional controller ticks are disabled and all production limits retain their defaults, apart from the explicit live-batch policy being compared. Handler service and failure are per group, not per update.",
	}
	r.Outcomes.RuntimeFailures = len(r.Failures)
	for i := range r.Calls {
		call := &r.Calls[i]
		if call.EntryNS != 0 {
			r.Outcomes.HandlerCalls++
		}
		if call.Error != "" {
			r.Outcomes.HandlerErrors++
		}
		if call.PrepareError != "" {
			r.Outcomes.PrepareErrors++
		}
		if call.InstanceChange {
			r.Outcomes.ObservedInstanceChanges++
		}
		if call.EntryNS != 0 && call.Error == "" {
			call.DecodedStatus = &v1.PluginEventStatus{}
			if err := proto.Unmarshal(call.Status, call.DecodedStatus); err != nil {
				call.StatusDecodeError = err.Error()
				call.DecodedStatus = nil
			}
		}
		for _, e := range call.Events {
			if e.Kind == v1.PluginEventKind_PLUGIN_EVENT_KIND_START_OF_REPLAY.String() {
				r.Outcomes.ReplayStarts++
			}
			if e.Kind == v1.PluginEventKind_PLUGIN_EVENT_KIND_END_OF_REPLAY.String() {
				r.Outcomes.ReplayEnds++
			}
			if e.Tag > 0 && int(e.Tag) <= len(r.Emits) && call.EntryNS != 0 {
				if e.InReplay {
					r.Emits[e.Tag-1].ObservedReplay++
				} else {
					r.Emits[e.Tag-1].ObservedLive++
				}
			}
		}
	}
	for _, e := range r.Emits {
		if e.Missed {
			r.Outcomes.SchedulerMissed++
			continue
		}
		if e.EmitStartNS == 0 {
			continue
		}
		r.Outcomes.Emitted++
		if !e.CallbackFound {
			r.Outcomes.CallbackMissing++
		}
		if e.ObservedLive > 0 {
			r.Outcomes.ObservedLiveTags++
		}
		if e.ObservedReplay > 0 {
			r.Outcomes.ObservedReplayTags++
		}
		if e.ObservedLive == 0 && e.ObservedReplay == 0 {
			r.Outcomes.UnobservedTags++
		}
		r.Outcomes.LiveObservations += e.ObservedLive
		r.Outcomes.ReplayObservations += e.ObservedReplay
	}
	writeJSON := func(name string, value any) error {
		raw, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, name), append(raw, '\n'), 0o644)
	}
	if err := writeJSON("report.json", r); err != nil {
		return err
	}
	f, err := os.Create(filepath.Join(dir, "emits.csv"))
	if err != nil {
		return err
	}
	w := csv.NewWriter(f)
	w.Write([]string{"tag", "session", "planned_ns", "decision_ns", "emit_start_ns", "emit_end_ns", "scheduler_missed", "callback_found_not_acceptance", "observed_live", "observed_replay"})
	for _, e := range r.Emits {
		w.Write([]string{fmt.Sprint(e.Tag), fmt.Sprint(e.Session), fmt.Sprint(e.PlannedNS), fmt.Sprint(e.DecisionNS), fmt.Sprint(e.EmitStartNS), fmt.Sprint(e.EmitEndNS), fmt.Sprint(e.Missed), fmt.Sprint(e.CallbackFound), fmt.Sprint(e.ObservedLive), fmt.Sprint(e.ObservedReplay)})
	}
	w.Flush()
	err = w.Error()
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	f, err = os.Create(filepath.Join(dir, "observations.csv"))
	if err != nil {
		return err
	}
	w = csv.NewWriter(f)
	w.Write([]string{"call", "tag", "sequence", "kind", "replay_epoch", "in_observed_replay", "prepare_start_ns", "prepare_end_ns", "entry_ns", "return_ns", "service_ns", "prehandler_from_emit_start_ns", "prehandler_from_emit_end_ns", "return_from_emit_start_ns", "runtime_error", "prepare_error"})
	for _, c := range r.Calls {
		for _, e := range c.Events {
			service, fromStart, fromEnd, untilReturn := "", "", "", ""
			if c.EntryNS != 0 {
				service = fmt.Sprint(c.ReturnNS - c.EntryNS)
				if !e.InReplay && e.Tag > 0 && int(e.Tag) <= len(r.Emits) && r.Emits[e.Tag-1].EmitStartNS != 0 {
					emit := r.Emits[e.Tag-1]
					fromStart, fromEnd, untilReturn = fmt.Sprint(c.EntryNS-emit.EmitStartNS), fmt.Sprint(c.EntryNS-emit.EmitEndNS), fmt.Sprint(c.ReturnNS-emit.EmitStartNS)
				}
			}
			w.Write([]string{fmt.Sprint(c.ID), fmt.Sprint(e.Tag), fmt.Sprint(e.Sequence), e.Kind, fmt.Sprint(e.Epoch), fmt.Sprint(e.InReplay), fmt.Sprint(c.PrepareStartNS), fmt.Sprint(c.PrepareEndNS), fmt.Sprint(c.EntryNS), fmt.Sprint(c.ReturnNS), service, fromStart, fromEnd, untilReturn, c.Error, c.PrepareError})
		}
	}
	w.Flush()
	err = w.Error()
	closeErr = f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func TestOfferedReadinessGate(t *testing.T) {
	s := offeredSample{Stats: PluginStats{InputReady: true, DesiredRevision: 1, AppliedRevision: 1}}
	if !s.ready() {
		t.Fatal("healthy idle sample was rejected")
	}
	for name, change := range map[string]func(*offeredSample){
		"pending":        func(s *offeredSample) { s.Pending = 1 },
		"holding":        func(s *offeredSample) { s.Holding = true },
		"debt":           func(s *offeredSample) { s.OwesSnapshot = true },
		"snapshot":       func(s *offeredSample) { s.Snapshotting = true },
		"input replay":   func(s *offeredSample) { s.InputReplaying = true },
		"unprocessed":    func(s *offeredSample) { s.Submitted = 1 },
		"unapplied":      func(s *offeredSample) { s.Stats.DesiredRevision++ },
		"output failure": func(s *offeredSample) { s.Stats.OutputFailure = "failure" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := s
			change(&changed)
			if changed.ready() {
				t.Fatal("non-drained state accepted")
			}
		})
	}
}
