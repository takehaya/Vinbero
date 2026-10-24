//go:build bench

package main

import (
	"math"
	"testing"
	"time"

	benchrq1 "github.com/takehaya/vinbero/bench/rq1"
)

func TestCalibrationSummary(t *testing.T) {
	var sent []benchrq1.SendRecord
	var recv []benchrq1.RecvRecord
	for i := range 101 {
		at := time.Unix(0, int64(1000000+i*10000))
		sent = append(sent, benchrq1.SendRecord{Seq: uint64(i), SentAt: at})
		recv = append(recv, benchrq1.RecvRecord{Seq: uint64(i), RecvAt: at.Add(time.Microsecond)})
	}
	got, err := calibrationSummary(sent, recv, 100000, 1010*time.Microsecond)
	if err != nil {
		t.Fatal(err)
	}
	if got.AchievedPPS != 100000 || got.GapMedianUS != 10 || got.GapP99US != 10 ||
		got.DelayMedianUS != 1 || got.Lost != 0 || got.Received != 101 || got.ScheduledSlots != 101 || got.UnsentSlots != 0 {
		t.Fatalf("wrong clean calibration: %+v", got)
	}
	recv = append(recv[1:], recv[1], benchrq1.RecvRecord{Seq: 999},
		benchrq1.RecvRecord{Seq: 2, RecvAt: sent[2].SentAt.Add(-time.Microsecond)})
	got, err = calibrationSummary(sent, recv, 100000, 1010*time.Microsecond)
	if err != nil {
		t.Fatal(err)
	}
	if got.Lost != 1 || got.Duplicates != 2 || got.Unknown != 1 || got.NegativeDelays != 1 {
		t.Fatalf("incorrect degraded calibration: %+v", got)
	}
}

func TestCalibrationRejectsMissingAndInvalidSamples(t *testing.T) {
	for _, sent := range [][]benchrq1.SendRecord{nil, {{Seq: 1}}, {{Seq: 1}, {Seq: 1}}, {{Seq: 1}, {Seq: 2}}} {
		if _, err := calibrationSummary(sent, nil, 100000, time.Second); err == nil {
			t.Fatalf("accepted invalid calibration: %+v", sent)
		}
	}
}

func TestCalibrationDoesNotHideAnUnsentTailBehindCorrectPPS(t *testing.T) {
	at := time.Unix(0, 1000000)
	sent := []benchrq1.SendRecord{{Seq: 0, SentAt: at}, {Seq: 1, SentAt: at.Add(10 * time.Microsecond)}}
	recv := []benchrq1.RecvRecord{{Seq: 0, RecvAt: at.Add(time.Microsecond)},
		{Seq: 1, RecvAt: at.Add(11 * time.Microsecond)}}
	got, err := calibrationSummary(sent, recv, 100000, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(got.AchievedPPS-100000) > 0.000001 || got.Lost != 0 || got.GapP99US != 10 || got.UnsentSlots != 99998 {
		t.Fatalf("short successful prefix hid missing scheduled sends: %+v", got)
	}
}
