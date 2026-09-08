//go:build bench

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAnalyzeHelper(t *testing.T) {
	if os.Getenv("VINBERO_PROBE_ANALYZE_TEST") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			runAnalyze(os.Args[i+1:])
			os.Exit(0)
		}
	}
	t.Fatal("missing helper arguments")
}

func TestAnalyzeCommandRequiresObservableGap(t *testing.T) {
	dir := t.TempDir()
	sentPath := filepath.Join(dir, "sent.csv")
	recvPath := filepath.Join(dir, "recv.csv")
	if err := os.WriteFile(sentPath, []byte("seq,tag,sent_unix_ns\n1,1,90\n2,1,101\n3,1,102\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, rows string
		valid      bool
	}{
		{"one arrival", "2,1,new,110\n", false},
		{"coincident arrivals", "1,1,new,110\n2,1,old,110\n", false},
		{"nanosecond gap", "1,1,new,110\n2,1,old,111\n3,1,new,112\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(recvPath, []byte("seq,tag,endpoint,recv_unix_ns\n"+tc.rows), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestAnalyzeHelper$", "--", "-sent", sentPath,
				"-recv", recvPath, "-change-ns", "100", "-old", "old", "-new", "new")
			cmd.Env = append(os.Environ(), "VINBERO_PROBE_ANALYZE_TEST=1")
			output, err := cmd.CombinedOutput()
			if tc.valid {
				if err != nil || !strings.Contains(string(output), "latency_us=0.010 first_seq=1 lost=0 misdelivered=0 sample_gap_us=0.001") {
					t.Fatalf("unexpected verdict: %s (%v)", output, err)
				}
			} else if err == nil || !strings.Contains(string(output), "cannot estimate a positive sample gap") {
				t.Fatalf("accepted unresolved sampling interval: %s (%v)", output, err)
			}
		})
	}
}

func TestReceiverFailurePropagatesBeforeAndDuringStop(t *testing.T) {
	want := errors.New("recvmsg failed")
	for _, early := range []bool{true, false} {
		done := make(chan error, 1)
		stopped := false
		if early {
			done <- want
		}
		err := waitReceiver(done, func() {
			stopped = true
			if !early {
				done <- want
			}
		}, time.Millisecond, nil)
		if !stopped || !errors.Is(err, want) {
			t.Fatalf("early=%v: stopped=%v, err=%v", early, stopped, err)
		}
	}
}

func TestCorruptCaptureIsRejected(t *testing.T) {
	for _, capture := range []struct {
		name, header, valid string
		bad                 []string
	}{
		{"sender", "seq,tag,sent_unix_ns\n", "1,1,100\n", []string{"1,1\n", "bad,1,100\n", "1,-1,100\n", "1,1,NaN\n", "1,1,0\n", "1,1,100,extra\n", "1,1,100\n1,1,101\n"}},
		{"receiver", "seq,tag,endpoint,recv_unix_ns\n", "1,1,new,100\n", []string{"1,1,new\n", "bad,1,new,100\n", "1,-1,new,100\n", "1,1,new,NaN\n", "1,1,,100\n", "1,1,new,-1\n", "1,1,new,100,extra\n"}},
	} {
		t.Run(capture.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "capture.csv")
			read := func() error {
				if capture.name == "sender" {
					_, err := readSent(path)
					return err
				}
				_, err := readRecv(path)
				return err
			}
			if err := os.WriteFile(path, []byte(capture.header+capture.valid), 0600); err != nil {
				t.Fatal(err)
			}
			if err := read(); err != nil {
				t.Fatal(err)
			}
			invalid := []string{"", "wrong,header\n"}
			for _, row := range capture.bad {
				invalid = append(invalid, capture.header+row)
			}
			for _, data := range invalid {
				if err := os.WriteFile(path, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
				if err := read(); err == nil {
					t.Fatalf("accepted %q", data)
				}
			}
		})
	}
}

func TestReceiverNormalDeadline(t *testing.T) {
	done := make(chan error, 1)
	err := waitReceiver(done, func() { done <- nil }, time.Millisecond, nil)
	if err != nil {
		t.Fatal(err)
	}
}
