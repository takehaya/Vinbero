//go:build bench

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
