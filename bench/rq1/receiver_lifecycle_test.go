//go:build bench

package benchrq1

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestReceiverStopBeforeRun(t *testing.T) {
	r, err := NewReceiver("test", loopback(0))
	if err != nil {
		t.Fatal(err)
	}
	r.Stop()
	r.Stop()
	if err := r.Run(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.LocalPort(); err == nil {
		t.Fatal("reported a port from a stopped receiver")
	}
	if _, err := unix.FcntlInt(uintptr(r.fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("socket was not closed: %v", err)
	}
}

func TestReceiverStopJoinsRunBeforeClose(t *testing.T) {
	r, err := NewReceiver("test", loopback(0))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Stop()
	// A receive wait longer than the old fixed shutdown sleep must still be
	// joined. Stop cannot assume that a timeout also schedules the goroutine.
	if err := unix.SetsockoptTimeval(r.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- r.Run() }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		r.runMu.Lock()
		started := r.started
		r.runMu.Unlock()
		if started {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Run did not start")
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	stopped := make(chan struct{})
	go func() { r.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not complete")
	}
	select {
	case <-r.runDone:
	default:
		t.Fatal("Stop closed the socket before Run finished")
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
