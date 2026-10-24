//go:build bench

package benchrq1

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestReceiverRejectsInvalidBind(t *testing.T) {
	if _, err := NewReceiver("test", netip.AddrPort{}); err == nil {
		t.Fatal("accepted invalid bind address")
	}
}

func TestProbeIPv4MappedIPv6(t *testing.T) {
	address := netip.MustParseAddr("::ffff:127.0.0.1")
	r, err := NewReceiver("mapped", netip.AddrPortFrom(address, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Stop()
	port, err := r.LocalPort()
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- r.Run() }()
	s, err := NewSender(SenderConfig{Target: netip.AddrPortFrom(address, port), Rate: 1000, Duration: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if err := s.Run(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for len(r.Records()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	r.Stop()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if len(r.Records()) == 0 {
		t.Fatal("mapped sender and receiver did not exchange probes")
	}
}

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
