package netlinkwatch

import (
	"net"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

type sinkCall struct {
	table  uint32
	prefix netip.Prefix
	added  bool
}

type fakeSink struct {
	calls []sinkCall
}

func (f *fakeSink) OnRoute(table uint32, prefix netip.Prefix, added bool) {
	f.calls = append(f.calls, sinkCall{table: table, prefix: prefix, added: added})
}

func mustIPNet(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse %q: %v", cidr, err)
	}
	return n
}

func newRoute(table uint32, proto int, dst *net.IPNet) netlink.Route {
	return netlink.Route{
		Table:    int(table),
		Protocol: netlink.RouteProtocol(proto),
		Dst:      dst,
	}
}

func TestRegisterTableRejectsUnknownProtocol(t *testing.T) {
	w := NewRouteWatcher(&fakeSink{}, zap.NewNop())
	if err := w.RegisterTable(100, []string{"bgp"}); err == nil {
		t.Error("registering an unknown redistribute protocol should fail")
	}
}

func TestRegisterTableRejectsEmpty(t *testing.T) {
	w := NewRouteWatcher(&fakeSink{}, zap.NewNop())
	if err := w.RegisterTable(100, nil); err == nil {
		t.Error("registering an empty redistribute list should fail")
	}
}

func TestHandleRouteForwardsConnectedV4(t *testing.T) {
	sink := &fakeSink{}
	w := NewRouteWatcher(sink, zap.NewNop())
	if err := w.RegisterTable(100, []string{"connected"}); err != nil {
		t.Fatalf("RegisterTable: %v", err)
	}
	w.handleRouteUpdate(netlink.RouteUpdate{
		Type:  unix.RTM_NEWROUTE,
		Route: newRoute(100, unix.RTPROT_KERNEL, mustIPNet(t, "10.0.0.0/24")),
	})
	if len(sink.calls) != 1 {
		t.Fatalf("want 1 forwarded route, got %d", len(sink.calls))
	}
	c := sink.calls[0]
	if c.table != 100 || c.prefix.String() != "10.0.0.0/24" || !c.added {
		t.Errorf("forwarded %+v", c)
	}
}

func TestHandleRouteIgnoresUnwatchedTable(t *testing.T) {
	sink := &fakeSink{}
	w := NewRouteWatcher(sink, zap.NewNop())
	if err := w.RegisterTable(100, []string{"connected"}); err != nil {
		t.Fatalf("RegisterTable: %v", err)
	}
	w.handleRouteUpdate(netlink.RouteUpdate{
		Type:  unix.RTM_NEWROUTE,
		Route: newRoute(200, unix.RTPROT_KERNEL, mustIPNet(t, "10.0.0.0/24")),
	})
	if len(sink.calls) != 0 {
		t.Errorf("a route in an unwatched table must be dropped, got %d", len(sink.calls))
	}
}

// TestHandleRouteDropsBGPProtocol is the loop-prevention guard: a route
// Vinbero itself installed (RTPROT_BGP) must never be redistributed back out,
// even when "connected"/"static" are registered. The allowlist excludes it.
func TestHandleRouteDropsBGPProtocol(t *testing.T) {
	sink := &fakeSink{}
	w := NewRouteWatcher(sink, zap.NewNop())
	if err := w.RegisterTable(100, []string{"connected", "static"}); err != nil {
		t.Fatalf("RegisterTable: %v", err)
	}
	w.handleRouteUpdate(netlink.RouteUpdate{
		Type:  unix.RTM_NEWROUTE,
		Route: newRoute(100, unix.RTPROT_BGP, mustIPNet(t, "10.0.0.0/24")),
	})
	if len(sink.calls) != 0 {
		t.Errorf("a BGP-protocol route must not be redistributed (loop), got %d", len(sink.calls))
	}
}

func TestHandleRouteIgnoresNilDst(t *testing.T) {
	sink := &fakeSink{}
	w := NewRouteWatcher(sink, zap.NewNop())
	if err := w.RegisterTable(100, []string{"connected"}); err != nil {
		t.Fatalf("RegisterTable: %v", err)
	}
	w.handleRouteUpdate(netlink.RouteUpdate{
		Type:  unix.RTM_NEWROUTE,
		Route: newRoute(100, unix.RTPROT_KERNEL, nil),
	})
	if len(sink.calls) != 0 {
		t.Errorf("a route with no destination must be dropped, got %d", len(sink.calls))
	}
}

// DumpTable of a table that was never registered returns an error before it
// touches netlink, so a caller (the runtime AddVRF replay) learns the table is
// not being watched instead of silently dumping nothing.
func TestDumpTableUnregisteredReturnsError(t *testing.T) {
	w := NewRouteWatcher(&fakeSink{}, zap.NewNop())
	if err := w.DumpTable(100); err == nil {
		t.Error("DumpTable of an unregistered table should return an error")
	}
}

func TestHandleRouteDelMapsToWithdraw(t *testing.T) {
	sink := &fakeSink{}
	w := NewRouteWatcher(sink, zap.NewNop())
	if err := w.RegisterTable(100, []string{"static"}); err != nil {
		t.Fatalf("RegisterTable: %v", err)
	}
	w.handleRouteUpdate(netlink.RouteUpdate{
		Type:  unix.RTM_DELROUTE,
		Route: newRoute(100, unix.RTPROT_STATIC, mustIPNet(t, "2001:db8::/64")),
	})
	if len(sink.calls) != 1 {
		t.Fatalf("want 1 forwarded route, got %d", len(sink.calls))
	}
	c := sink.calls[0]
	if c.added {
		t.Errorf("RTM_DELROUTE must map to added=false, got %+v", c)
	}
	if c.prefix.String() != "2001:db8::/64" {
		t.Errorf("prefix = %q", c.prefix.String())
	}
}
