//go:build bench

package main

import (
	"errors"
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

func TestReceiverNormalDeadline(t *testing.T) {
	done := make(chan error, 1)
	err := waitReceiver(done, func() { done <- nil }, time.Millisecond, nil)
	if err != nil {
		t.Fatal(err)
	}
}
