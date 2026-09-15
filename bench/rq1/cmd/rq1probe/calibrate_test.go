//go:build bench

package main

import (
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
	got, err := calibrationSummary(sent, recv, 100000)
	if err != nil {
		t.Fatal(err)
	}
	if got.AchievedPPS != 100000 || got.GapMedianUS != 10 || got.GapP99US != 10 ||
		got.DelayMedianUS != 1 || got.Lost != 0 || got.Received != 101 {
		t.Fatalf("wrong clean calibration: %+v", got)
	}
	recv = append(recv[1:], recv[1], benchrq1.RecvRecord{Seq: 999},
		benchrq1.RecvRecord{Seq: 2, RecvAt: sent[2].SentAt.Add(-time.Microsecond)})
	got, err = calibrationSummary(sent, recv, 100000)
	if err != nil {
		t.Fatal(err)
	}
	if got.Lost != 1 || got.Duplicates != 2 || got.Unknown != 1 || got.NegativeDelays != 1 {
		t.Fatalf("incorrect degraded calibration: %+v", got)
	}
}

func TestCalibrationRejectsMissingAndInvalidSamples(t *testing.T) {
	for _, sent := range [][]benchrq1.SendRecord{nil, {{Seq: 1}}, {{Seq: 1}, {Seq: 1}}, {{Seq: 1}, {Seq: 2}}} {
		if _, err := calibrationSummary(sent, nil, 100000); err == nil {
			t.Fatalf("accepted invalid calibration: %+v", sent)
		}
	}
}
