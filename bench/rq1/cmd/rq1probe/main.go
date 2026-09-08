//go:build bench

// Command rq1probe drives the RQ1 convergence instrument from a shell, so the
// sender and the receivers can live in different network namespaces.
//
// The Go test in bench/rq1 exercises the same code in one process; this binary
// exists because a real topology puts the traffic source and the endpoints on
// opposite sides of a data plane, and `ip netns exec` is the only way in.
//
// Records are written as CSV so the analysis step can correlate them without
// the two sides sharing memory. Timestamps are Unix nanoseconds against the
// wall clock, which is shared across namespaces on one host.
package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	benchrq1 "github.com/takehaya/vinbero/bench/rq1"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "send":
		runSend(os.Args[2:])
	case "recv":
		runRecv(os.Args[2:])
	case "analyze":
		runAnalyze(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage:
  rq1probe send -target ADDR:PORT -rate PPS -duration DUR -tag N -out FILE
  rq1probe recv -bind ADDR:PORT -name NAME -out FILE [-duration DUR]
  rq1probe analyze -sent FILE -recv FILE[,FILE...] -change-ns N -old NAME -new NAME

recv runs until the duration elapses, or until SIGINT or SIGTERM when no
duration is given.
`)
	os.Exit(2)
}

func runSend(args []string) {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	target := fs.String("target", "", "destination address:port")
	rate := fs.Int("rate", 100_000, "packets per second")
	duration := fs.Duration("duration", time.Second, "how long to send")
	tag := fs.Uint("tag", 1, "endpoint this traffic is meant to reach")
	out := fs.String("out", "", "CSV output path; stdout when empty")
	startAt := fs.String("start-at", "", "wall clock unix nanoseconds to begin at")
	_ = fs.Parse(args)

	ap, err := netip.ParseAddrPort(*target)
	if err != nil {
		fatal("parse -target: %v", err)
	}

	snd, err := benchrq1.NewSender(benchrq1.SenderConfig{
		Target:   ap,
		Tag:      uint32(*tag),
		Rate:     *rate,
		Duration: *duration,
	})
	if err != nil {
		fatal("sender: %v", err)
	}
	defer func() { _ = snd.Close() }()

	// Constructing the sender costs hundreds of microseconds for the socket
	// and the record buffer. When a caller wants traffic already flowing at
	// a known instant, it passes that instant here so the setup is paid
	// before the clock that matters starts.
	if *startAt != "" {
		ns, err := strconv.ParseInt(*startAt, 10, 64)
		if err != nil {
			fatal("parse -start-at: %v", err)
		}
		for time.Now().UnixNano() < ns {
			time.Sleep(200 * time.Microsecond)
		}
	}

	if err := snd.Run(); err != nil {
		fatal("send: %v", err)
	}

	w, closeFn := openOut(*out)
	defer closeFn()
	cw := csv.NewWriter(w)
	defer func() { cw.Flush(); must(cw.Error()) }()
	must(cw.Write([]string{"seq", "tag", "sent_unix_ns"}))
	for _, r := range snd.Records() {
		must(cw.Write([]string{
			strconv.FormatUint(r.Seq, 10),
			strconv.FormatUint(uint64(r.Tag), 10),
			strconv.FormatInt(r.SentAt.UnixNano(), 10),
		}))
	}
}

func runRecv(args []string) {
	fs := flag.NewFlagSet("recv", flag.ExitOnError)
	bind := fs.String("bind", "", "address:port to listen on")
	name := fs.String("name", "endpoint", "endpoint name recorded with each arrival")
	out := fs.String("out", "", "CSV output path; stdout when empty")
	duration := fs.Duration("duration", 0, "stop after this long; 0 waits for a signal")
	_ = fs.Parse(args)

	ap, err := netip.ParseAddrPort(*bind)
	if err != nil {
		fatal("parse -bind: %v", err)
	}

	recv, err := benchrq1.NewReceiver(*name, ap)
	if err != nil {
		fatal("receiver: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- recv.Run() }()

	// Announce readiness so a driver script can start traffic without
	// racing the bind.
	fmt.Fprintln(os.Stderr, "ready")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)
	if err := waitReceiver(done, recv.Stop, *duration, sig); err != nil {
		fatal("receiver: %v", err)
	}

	w, closeFn := openOut(*out)
	defer closeFn()
	cw := csv.NewWriter(w)
	defer func() { cw.Flush(); must(cw.Error()) }()
	must(cw.Write([]string{"seq", "tag", "endpoint", "recv_unix_ns"}))
	for _, r := range recv.Records() {
		must(cw.Write([]string{
			strconv.FormatUint(r.Seq, 10),
			strconv.FormatUint(uint64(r.Tag), 10),
			r.Endpoint,
			strconv.FormatInt(r.RecvAt.UnixNano(), 10),
		}))
	}
}

func waitReceiver(done <-chan error, stop func(), duration time.Duration, sig <-chan os.Signal) error {
	var elapsed <-chan time.Time
	if duration > 0 {
		timer := time.NewTimer(duration)
		defer timer.Stop()
		elapsed = timer.C
	}
	select {
	case err := <-done:
		stop()
		if err != nil {
			return err
		}
		return fmt.Errorf("receiver stopped before completion")
	case <-elapsed:
	case <-sig:
	}
	stop()
	return <-done
}

func runAnalyze(args []string) {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	sentPath := fs.String("sent", "", "sender CSV")
	recvPaths := fs.String("recv", "", "comma separated receiver CSVs")
	changeNs := fs.Int64("change-ns", 0, "wall clock unix nanoseconds of the route change")
	oldName := fs.String("old", "", "endpoint the route pointed to before the change")
	newName := fs.String("new", "", "endpoint the route points to after the change")
	_ = fs.Parse(args)

	if *sentPath == "" || *recvPaths == "" || *changeNs == 0 {
		fatal("analyze needs -sent, -recv and -change-ns")
	}

	sent := readSent(*sentPath)
	var received []benchrq1.RecvRecord
	for _, p := range splitComma(*recvPaths) {
		received = append(received, readRecv(p)...)
	}

	got := benchrq1.Analyze(sent, received, time.Unix(0, *changeNs), *oldName, *newName)
	fmt.Printf("detected=%v latency_us=%.1f first_seq=%d lost=%d misdelivered=%d sample_gap_us=%.1f\n",
		got.Detected,
		float64(got.Latency.Nanoseconds())/1000,
		got.FirstSeq,
		got.Lost,
		got.Misdelivered,
		float64(got.SampleGap.Nanoseconds())/1000,
	)
	if !got.Detected {
		os.Exit(3)
	}
}

func splitComma(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func readSent(path string) []benchrq1.SendRecord {
	rows := readCSV(path)
	out := make([]benchrq1.SendRecord, 0, len(rows))
	for _, r := range rows {
		if len(r) < 3 {
			continue
		}
		seq, err1 := strconv.ParseUint(r[0], 10, 64)
		tag, err2 := strconv.ParseUint(r[1], 10, 32)
		ns, err3 := strconv.ParseInt(r[2], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		out = append(out, benchrq1.SendRecord{
			Seq:    seq,
			Tag:    uint32(tag),
			SentAt: time.Unix(0, ns),
		})
	}
	return out
}

func readRecv(path string) []benchrq1.RecvRecord {
	rows := readCSV(path)
	out := make([]benchrq1.RecvRecord, 0, len(rows))
	for _, r := range rows {
		if len(r) < 4 {
			continue
		}
		seq, err1 := strconv.ParseUint(r[0], 10, 64)
		tag, err2 := strconv.ParseUint(r[1], 10, 32)
		ns, err3 := strconv.ParseInt(r[3], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		out = append(out, benchrq1.RecvRecord{
			Seq:      seq,
			Tag:      uint32(tag),
			Endpoint: r[2],
			RecvAt:   time.Unix(0, ns),
		})
	}
	return out
}

func readCSV(path string) [][]string {
	f, err := os.Open(path)
	if err != nil {
		fatal("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		fatal("read %s: %v", path, err)
	}
	if len(rows) == 0 {
		return nil
	}
	// drop the header
	return rows[1:]
}

func openOut(path string) (*os.File, func()) {
	if path == "" {
		return os.Stdout, func() {}
	}
	f, err := os.Create(path)
	if err != nil {
		fatal("create %s: %v", path, err)
	}
	return f, func() { must(f.Close()) }
}

func must(err error) {
	if err != nil {
		fatal("write: %v", err)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "rq1probe: "+format+"\n", args...)
	os.Exit(1)
}
