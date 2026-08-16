package cplane

import (
	"context"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

// testBatch builds a one-event batch whose replay source names it, so a
// test can tell deliveries apart by their contents.
func testBatch(t *testing.T, name string) *v1.PluginEventBatch {
	t.Helper()
	return &v1.PluginEventBatch{Events: []*v1.PluginEvent{{
		Kind:         v1.PluginEventKind_PLUGIN_EVENT_KIND_END_OF_REPLAY,
		ReplaySource: name,
	}}}
}

// batchName reads back what testBatch put in.
func batchName(t *testing.T, encoded []byte) string {
	t.Helper()
	var batch v1.PluginEventBatch
	if err := proto.Unmarshal(encoded, &batch); err != nil {
		t.Fatalf("decode delivered batch: %v", err)
	}
	if len(batch.GetEvents()) != 1 {
		t.Fatalf("delivered batch holds %d events, want 1", len(batch.GetEvents()))
	}
	return batch.GetEvents()[0].GetReplaySource()
}

// A snapshot holds live events so they arrive after it. Releasing them has
// to keep them in order too: clearing the hold before draining lets an
// event arriving mid-drain jump ahead of ones already waiting.
func TestHeldEventsKeepTheirOrderWhenReleased(t *testing.T) {
	var (
		mu   sync.Mutex
		seen []string
	)
	arrived := make(chan struct{})
	w := newWorker("order", zap.NewNop(),
		func(_ context.Context, encoded []byte) ([]byte, error) {
			mu.Lock()
			seen = append(seen, batchName(t, encoded))
			n := len(seen)
			mu.Unlock()
			if n == 3 {
				close(arrived)
			}
			return nil, nil
		},
		func(error) {}, func(*v1.PluginEventStatus) {}, nil, 0, nil)
	defer w.close()

	w.beginSnapshot()
	w.submit(testBatch(t, "A"))
	w.submit(testBatch(t, "B"))

	// C races the release of the hold. Whichever moment it lands in, it
	// must not overtake A or B.
	go w.submit(testBatch(t, "C"))
	w.endSnapshot()

	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("the worker did not deliver all three batches")
	}
	mu.Lock()
	defer mu.Unlock()
	if seen[0] != "A" || seen[1] != "B" {
		t.Fatalf("delivery order %v; the held events were overtaken", seen)
	}
}
