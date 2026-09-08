//go:build bench

package benchrq1

// Self-check for the convergence instrument.
//
// Calibration uses a 151 us timing budget. These tests measure achieved
// sampling density and recover a route change injected at a known instant.

import (
	"fmt"
	"net/netip"
	"os"
	"sort"
	"sync"
	"testing"
	"time"
)

func loopback(port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
}

func TestSenderRejectsUnrepresentableRate(t *testing.T) {
	sender, err := NewSender(SenderConfig{
		Target: loopback(9999), Rate: 1_000_000_001, Duration: time.Second,
	})
	if sender != nil {
		_ = sender.Close()
	}
	if err == nil {
		t.Fatal("accepted a rate with a zero nanosecond pacing interval")
	}
}

func TestSenderDoesNotWaitForSampleOutsideDuration(t *testing.T) {
	r, err := NewReceiver("test", loopback(0))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Stop()
	port, err := r.LocalPort()
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSender(SenderConfig{Target: loopback(port), Rate: 1, Duration: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if err := s.Run(); err != nil {
		t.Fatal(err)
	}
	if got := len(s.Records()); got > 1 {
		t.Fatalf("sent %d probes although the second sample falls outside Duration", got)
	}
}

// freePort asks the kernel for an unused UDP port by binding one and closing it.
func freePort(t *testing.T) uint16 {
	t.Helper()
	r, err := NewReceiver("probe", loopback(0))
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	port, err := r.LocalPort()
	if err != nil {
		r.Stop()
		t.Fatalf("LocalPort: %v", err)
	}
	r.Stop()
	return port
}

// TestRQ1ProbeRate measures the sample density the instrument reaches on this
// host. The number it prints is the resolution floor of every later
// convergence measurement: a latency of the same order as the gap is noise.
func TestRQ1ProbeRate(t *testing.T) {
	for _, rate := range []int{10_000, 50_000, 100_000, 200_000} {
		t.Run(fmt.Sprintf("rate-%d", rate), func(t *testing.T) {
			port := freePort(t)
			recv, err := NewReceiver("a", loopback(port))
			if err != nil {
				t.Fatalf("NewReceiver: %v", err)
			}
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := recv.Run(); err != nil {
					t.Errorf("receiver: %v", err)
				}
			}()

			snd, err := NewSender(SenderConfig{
				Target:   loopback(port),
				Tag:      1,
				Rate:     rate,
				Duration: time.Second,
			})
			if err != nil {
				recv.Stop()
				t.Fatalf("NewSender: %v", err)
			}
			if err := snd.Run(); err != nil {
				_ = snd.Close()
				recv.Stop()
				t.Fatalf("sender: %v", err)
			}
			_ = snd.Close()
			time.Sleep(300 * time.Millisecond)
			recv.Stop()
			wg.Wait()

			sent := snd.Records()
			got := recv.Records()
			if len(sent) < 2 {
				t.Fatalf("sent %d packets, expected many", len(sent))
			}

			span := sent[len(sent)-1].SentAt.Sub(sent[0].SentAt)
			achieved := float64(len(sent)-1) / span.Seconds()

			gaps := make([]time.Duration, 0, len(got))
			sort.Slice(got, func(i, j int) bool { return got[i].RecvAt.Before(got[j].RecvAt) })
			for i := 1; i < len(got); i++ {
				gaps = append(gaps, got[i].RecvAt.Sub(got[i-1].RecvAt))
			}
			sort.Slice(gaps, func(i, j int) bool { return gaps[i] < gaps[j] })

			var p50, p99 time.Duration
			if len(gaps) > 0 {
				p50 = gaps[len(gaps)*50/100]
				p99 = gaps[len(gaps)*99/100]
			}
			lossPct := 100 * float64(len(sent)-len(got)) / float64(len(sent))

			t.Logf("target=%d pps achieved=%.0f pps sent=%d recv=%d loss=%.2f%% arrival gap p50=%v p99=%v",
				rate, achieved, len(sent), len(got), lossPct, p50, p99)
		})
	}
}

// TestRQ1ProbeTimestamps checks that kernel receive timestamps are usable: they
// must be monotonic in arrival order and close to the send instant on loopback,
// where the true one-way delay is microseconds.
func TestRQ1ProbeTimestamps(t *testing.T) {
	port := freePort(t)
	recv, err := NewReceiver("a", loopback(port))
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := recv.Run(); err != nil {
			t.Errorf("receiver: %v", err)
		}
	}()

	snd, err := NewSender(SenderConfig{
		Target:   loopback(port),
		Tag:      1,
		Rate:     50_000,
		Duration: 500 * time.Millisecond,
	})
	if err != nil {
		recv.Stop()
		t.Fatalf("NewSender: %v", err)
	}
	if err := snd.Run(); err != nil {
		_ = snd.Close()
		recv.Stop()
		t.Fatalf("sender: %v", err)
	}
	_ = snd.Close()
	time.Sleep(300 * time.Millisecond)
	recv.Stop()
	wg.Wait()

	sentAt := make(map[uint64]time.Time)
	for _, s := range snd.Records() {
		sentAt[s.Seq] = s.SentAt
	}

	got := recv.Records()
	if len(got) == 0 {
		t.Fatal("no packets received")
	}

	deltas := make([]time.Duration, 0, len(got))
	negative := 0
	for i, r := range got {
		if i > 0 && r.RecvAt.Before(got[i-1].RecvAt) {
			t.Fatal("kernel timestamps moved backwards in receiver order")
		}
		s, ok := sentAt[r.Seq]
		if !ok {
			t.Fatalf("received seq %d that was never recorded as sent", r.Seq)
		}
		d := r.RecvAt.Sub(s)
		if d < 0 {
			negative++
		}
		deltas = append(deltas, d)
	}
	sort.Slice(deltas, func(i, j int) bool { return deltas[i] < deltas[j] })

	p50 := deltas[len(deltas)*50/100]
	p99 := deltas[len(deltas)*99/100]
	t.Logf("loopback one-way delta p50=%v p99=%v negative=%d of %d", p50, p99, negative, len(deltas))

	// A negative delta means the kernel stamp precedes the user-space send
	// stamp, which would make convergence latencies unreadable.
	if negative > len(deltas)/100 {
		t.Fatalf("kernel receive timestamps precede send timestamps in %d of %d samples", negative, len(deltas))
	}
	// Compare the observed loopback delay against the calibration budget.
	if os.Getenv("BENCH_CALIBRATE") == "1" && p50 > 151*time.Microsecond {
		t.Fatalf("loopback delta p50 %v exceeds the 151us calibration budget", p50)
	}
}

// TestRQ1ProbeAnalyze injects a known change instant and checks that Analyze
// recovers it. Two receivers stand in for the old and new endpoints; the sender
// is retargeted mid-run, which is what a converged route change looks like from
// the traffic's point of view.
func TestRQ1ProbeAnalyze(t *testing.T) {
	portOld := freePort(t)
	portNew := freePort(t)

	oldRecv, err := NewReceiver("pe-old", loopback(portOld))
	if err != nil {
		t.Fatalf("NewReceiver old: %v", err)
	}
	newRecv, err := NewReceiver("pe-new", loopback(portNew))
	if err != nil {
		oldRecv.Stop()
		t.Fatalf("NewReceiver new: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = oldRecv.Run() }()
	go func() { defer wg.Done(); _ = newRecv.Run() }()

	const rate = 100_000
	const half = 250 * time.Millisecond

	// Both senders are constructed before the change instant is stamped.
	// Socket setup and the record buffer allocation cost hundreds of
	// microseconds, which would otherwise be charged to the instrument and
	// swamp the difference the experiment has to resolve.
	sndOld, err := NewSender(SenderConfig{Target: loopback(portOld), Tag: 1, Rate: rate, Duration: half})
	if err != nil {
		t.Fatalf("NewSender old: %v", err)
	}
	sndNew, err := NewSender(SenderConfig{Target: loopback(portNew), Tag: 1, Rate: rate, Duration: half})
	if err != nil {
		_ = sndOld.Close()
		t.Fatalf("NewSender new: %v", err)
	}

	if err := sndOld.Run(); err != nil {
		t.Fatalf("sender old: %v", err)
	}
	_ = sndOld.Close()

	changeAt := time.Now()

	if err := sndNew.Run(); err != nil {
		t.Fatalf("sender new: %v", err)
	}
	_ = sndNew.Close()

	time.Sleep(300 * time.Millisecond)
	oldRecv.Stop()
	newRecv.Stop()
	wg.Wait()

	// The second sender restarts sequence numbers at zero, so offset them to
	// keep the correlation keys unique across the change.
	sent := sndOld.Records()
	const seqOffset = 1 << 32
	for _, s := range sndNew.Records() {
		sent = append(sent, SendRecord{Seq: s.Seq + seqOffset, Tag: s.Tag, SentAt: s.SentAt})
	}
	received := oldRecv.Records()
	for _, r := range newRecv.Records() {
		received = append(received, RecvRecord{Seq: r.Seq + seqOffset, Tag: r.Tag, Endpoint: r.Endpoint, RecvAt: r.RecvAt})
	}

	got := Analyze(sent, received, changeAt, "pe-old", "pe-new")
	t.Logf("detected=%v latency=%v firstSeq=%d lost=%d misdelivered=%d sampleGap=%v",
		got.Detected, got.Latency, got.FirstSeq, got.Lost, got.Misdelivered, got.SampleGap)

	if !got.Detected {
		t.Fatal("convergence not detected although traffic moved to the new endpoint")
	}
	// The retarget is instantaneous here, so the reported latency is the
	// instrument's own error, which must fit the calibration budget.
	if os.Getenv("BENCH_CALIBRATE") == "1" && got.Latency > 151*time.Microsecond {
		t.Fatalf("instrument error %v exceeds the 151us calibration budget", got.Latency)
	}
	if os.Getenv("BENCH_CALIBRATE") == "1" && got.SampleGap > 20*time.Microsecond {
		t.Fatalf("sample gap %v too coarse to resolve a 151us difference", got.SampleGap)
	}
}
