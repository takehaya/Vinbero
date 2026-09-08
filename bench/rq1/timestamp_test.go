//go:build bench

package benchrq1

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestReceiverRejectsMissingKernelTimestamp(t *testing.T) {
	r, err := NewReceiver("test", loopback(0))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Stop()
	port, err := r.LocalPort()
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.SetsockoptInt(r.fd, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, 0); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- r.Run() }()
	s, err := NewSender(SenderConfig{Target: loopback(port), Rate: 1000, Duration: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if err := s.Run(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "without a kernel timestamp") {
			t.Fatalf("got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("receiver accepted a packet without its timestamp")
	}
}
