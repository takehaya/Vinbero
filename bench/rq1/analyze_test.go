//go:build bench

package benchrq1

import (
	"testing"
	"time"
)

func TestAnalyzeUsesArrivalTimeAndCountsLoss(t *testing.T) {
	ns := func(n int64) time.Time { return time.Unix(0, n) }
	sent := []SendRecord{{Seq: 1, SentAt: ns(101)}, {Seq: 2, SentAt: ns(102)}, {Seq: 3, SentAt: ns(103)}, {Seq: 4, SentAt: ns(104)}, {Seq: 5, SentAt: ns(90)}}
	recv := []RecvRecord{
		{Seq: 2, Endpoint: "new", RecvAt: ns(150)},
		{Seq: 5, Endpoint: "new", RecvAt: ns(110)},  // in flight when the route changed
		{Seq: 99, Endpoint: "new", RecvAt: ns(105)}, // absent from the sender log
		{Seq: 5, Endpoint: "new", RecvAt: ns(99)},   // outside the observation window
		{Seq: 1, Endpoint: "old", RecvAt: ns(120)},
		{Seq: 3, Endpoint: "new", RecvAt: ns(130)},
		{Seq: 3, Endpoint: "new", RecvAt: ns(140)}, // duplicate
	}
	got := Analyze(sent, recv, ns(100), "old", "new")
	if !got.Detected || got.Latency != 10 || got.FirstSeq != 5 || got.Lost != 1 || got.Misdelivered != 0 || got.SampleGap != 10 {
		t.Fatalf("unexpected verdict: %+v", got)
	}
}

func TestAnalyzeDuplicateAcrossEndpointsStillDetectsNewPath(t *testing.T) {
	change := time.Now()
	sent := []SendRecord{{Seq: 1, SentAt: change}}
	recv := []RecvRecord{
		{Seq: 1, Endpoint: "old", RecvAt: change.Add(time.Microsecond)},
		{Seq: 1, Endpoint: "new", RecvAt: change.Add(2 * time.Microsecond)},
	}
	got := Analyze(sent, recv, change, "old", "new")
	if !got.Detected || got.Latency != 2*time.Microsecond || got.Lost != 0 || got.Misdelivered != 1 {
		t.Fatalf("unexpected verdict: %+v", got)
	}
}
