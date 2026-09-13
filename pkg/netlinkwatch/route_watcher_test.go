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

// A sink added with AddSink receives route changes alongside the one the
// watcher was built with, and stops once its remove func runs.
func TestAddSinkFansOutAndRemoves(t *testing.T) {
	primary := &fakeSink{}
	w := NewRouteWatcher(primary, zap.NewNop())
	if err := w.RegisterTable(100, []string{"connected"}); err != nil {
		t.Fatalf("register table: %v", err)
	}
	extra := &fakeSink{}
	remove := w.AddSink(extra)

	route := newRoute(100, unix.RTPROT_KERNEL, mustIPNet(t, "192.0.2.0/24"))
	w.handleRouteUpdate(netlink.RouteUpdate{Type: unix.RTM_NEWROUTE, Route: route})
	if len(primary.calls) != 1 || len(extra.calls) != 1 {
		t.Fatalf("fan-out incomplete: primary=%d extra=%d, want 1 each", len(primary.calls), len(extra.calls))
	}

	remove()
	remove() // idempotent
	w.handleRouteUpdate(netlink.RouteUpdate{Type: unix.RTM_NEWROUTE, Route: route})
	if len(primary.calls) != 2 {
		t.Errorf("primary sink stopped after the extra was removed: got %d, want 2", len(primary.calls))
	}
	if len(extra.calls) != 1 {
		t.Errorf("removed sink still received routes: got %d, want 1", len(extra.calls))
	}
}

// A watcher built with no sink still filters correctly and delivers to sinks
// attached later.
func TestNilPrimarySinkStillDeliversToAddedSink(t *testing.T) {
	w := NewRouteWatcher(nil, zap.NewNop())
	if err := w.RegisterTable(100, []string{"connected"}); err != nil {
		t.Fatalf("register table: %v", err)
	}
	extra := &fakeSink{}
	w.AddSink(extra)

	w.handleRouteUpdate(netlink.RouteUpdate{
		Type:  unix.RTM_NEWROUTE,
		Route: newRoute(100, unix.RTPROT_KERNEL, mustIPNet(t, "192.0.2.0/24")),
	})
	if len(extra.calls) != 1 {
		t.Fatalf("added sink received %d routes, want 1", len(extra.calls))
	}
	// The protocol allowlist still applies with no primary sink.
	w.handleRouteUpdate(netlink.RouteUpdate{
		Type:  unix.RTM_NEWROUTE,
		Route: newRoute(100, unix.RTPROT_BGP, mustIPNet(t, "198.51.100.0/24")),
	})
	if len(extra.calls) != 1 {
		t.Errorf("BGP-protocol route leaked to sink: got %d calls, want 1", len(extra.calls))
	}
}
