//go:build bench

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"time"

	benchrq1 "github.com/takehaya/vinbero/bench/rq1"
)

type calibration struct {
	Rate           int     `json:"rate"`
	DurationNS     int64   `json:"duration_ns"`
	ScheduledSlots int     `json:"scheduled_slots"`
	UnsentSlots    int     `json:"unsent_schedule_slots"`
	Sent           int     `json:"sent"`
	Received       int     `json:"received"`
	Lost           int     `json:"lost"`
	Duplicates     int     `json:"duplicates"`
	Unknown        int     `json:"unknown"`
	NegativeDelays int     `json:"negative_delays"`
	AchievedPPS    float64 `json:"achieved_pps"`
	GapMedianUS    float64 `json:"gap_median_us"`
	GapP99US       float64 `json:"gap_p99_us"`
	DelayMedianUS  float64 `json:"delay_median_us"`
}

func calibrationSummary(sent []benchrq1.SendRecord, received []benchrq1.RecvRecord, rate int, duration time.Duration) (calibration, error) {
	out := calibration{Rate: rate, DurationNS: int64(duration), Sent: len(sent)}
	if rate <= 0 || rate > 1_000_000 || duration <= 0 || duration > 10*time.Second || len(sent) < 2 {
		return out, fmt.Errorf("calibration needs rate 1..1000000, duration (0,10s], and at least two sends")
	}
	gap := time.Second / time.Duration(rate)
	out.ScheduledSlots = int((duration + gap - 1) / gap)
	out.UnsentSlots = out.ScheduledSlots - out.Sent
	if out.UnsentSlots < 0 {
		return out, fmt.Errorf("calibration has more sends than scheduled slots")
	}
	bySeq := make(map[uint64]time.Time, len(sent))
	first, last := sent[0].SentAt, sent[0].SentAt
	for _, s := range sent {
		if _, duplicate := bySeq[s.Seq]; duplicate {
			return out, fmt.Errorf("duplicate sender sequence %d", s.Seq)
		}
		bySeq[s.Seq] = s.SentAt
		if s.SentAt.Before(first) {
			first = s.SentAt
		}
		if s.SentAt.After(last) {
			last = s.SentAt
		}
	}
	if !last.After(first) {
		return out, fmt.Errorf("calibration has no positive send interval")
	}
	out.AchievedPPS = float64(len(sent)-1) / last.Sub(first).Seconds()
	arrivals := make(map[uint64]time.Time, len(received))
	for _, r := range received {
		if _, known := bySeq[r.Seq]; !known {
			out.Unknown++
			continue
		}
		if prior, duplicate := arrivals[r.Seq]; duplicate {
			out.Duplicates++
			if !r.RecvAt.Before(prior) {
				continue
			}
		}
		arrivals[r.Seq] = r.RecvAt
	}
	out.Received = len(arrivals)
	out.Lost = len(sent) - len(arrivals)
	if len(arrivals) < 2 {
		return out, fmt.Errorf("calibration needs at least two known arrivals")
	}
	timestamps, delays := make([]int64, 0, len(arrivals)), make([]int64, 0, len(arrivals))
	for seq, at := range arrivals {
		timestamps = append(timestamps, at.UnixNano())
		delay := at.Sub(bySeq[seq]).Nanoseconds()
		delays = append(delays, delay)
		if delay < 0 {
			out.NegativeDelays++
		}
	}
	slices.Sort(timestamps)
	gaps := make([]int64, 0, len(timestamps)-1)
	for i := 1; i < len(timestamps); i++ {
		gaps = append(gaps, timestamps[i]-timestamps[i-1])
	}
	slices.Sort(gaps)
	slices.Sort(delays)
	medianUS := func(v []int64) float64 {
		return (float64(v[(len(v)-1)/2]) + float64(v[len(v)/2])) / 2000
	}
	out.GapMedianUS = medianUS(gaps)
	out.GapP99US = float64(gaps[(len(gaps)*99+99)/100-1]) / 1000
	out.DelayMedianUS = medianUS(delays)
	return out, nil
}

func runCalibrate(args []string) {
	fs := flag.NewFlagSet("calibrate", flag.ExitOnError)
	rate := fs.Int("rate", 100_000, "packets per second")
	duration := fs.Duration("duration", time.Second, "loopback sending duration")
	_ = fs.Parse(args)
	if *rate <= 0 || *rate > 1_000_000 || *duration <= 0 || *duration > 10*time.Second {
		fatal("calibrate requires rate 1..1000000 and duration in (0,10s]")
	}
	address := netip.MustParseAddr("127.0.0.1")
	recv, err := benchrq1.NewReceiver("loopback", netip.AddrPortFrom(address, 0))
	if err != nil {
		fatal("calibrate receiver: %v", err)
	}
	defer recv.Stop()
	port, err := recv.LocalPort()
	if err != nil {
		fatal("calibrate receiver port: %v", err)
	}
	sender, err := benchrq1.NewSender(benchrq1.SenderConfig{
		Target: netip.AddrPortFrom(address, port), Tag: 1, Rate: *rate, Duration: *duration,
	})
	if err != nil {
		fatal("calibrate sender: %v", err)
	}
	defer func() { _ = sender.Close() }()
	done := make(chan error, 1)
	go func() { done <- recv.Run() }()
	if err := sender.Run(); err != nil {
		fatal("calibrate send: %v", err)
	}
	// Drain arrivals already queued at the socket before stopping the receiver.
	time.Sleep(300 * time.Millisecond)
	recv.Stop()
	if err := <-done; err != nil {
		fatal("calibrate receive: %v", err)
	}
	result, err := calibrationSummary(sender.Records(), recv.Records(), *rate, *duration)
	if err != nil {
		fatal("calibrate: %v", err)
	}
	must(json.NewEncoder(os.Stdout).Encode(result))
}
