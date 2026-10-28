package customcontroller

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/wire"
)

type hostCall struct {
	kind cplane.Kind
	data []byte
}

type recordingHost struct {
	calls []hostCall
}

func (h *recordingHost) Begin(kind cplane.Kind) uint64 {
	h.calls = append(h.calls, hostCall{kind: kind})
	return uint64(len(h.calls))
}
func (h *recordingHost) Put(id uint64, data []byte) cplane.Status {
	h.calls[id-1].data = append(h.calls[id-1].data, data...)
	return cplane.StatusOK
}
func (*recordingHost) Commit(uint64) cplane.Status { return cplane.StatusOK }
func (*recordingHost) Abort(uint64)                {}

func TestTypedConfigurationPreservesWireDeclarations(t *testing.T) {
	var data wire.Encoder
	data.Uint(1, 0xfe02)
	data.String(2, "main")
	data.String(3, "10.7.0.0/24")
	data.String(4, "blue")
	data.Uint(5, 33)
	data.String(7, "2001:db8::1")
	data.String(8, "blue")
	data.String(9, "10.0.1.0/8")
	config := Config{Behavior: 0xfe02, Locator: "main", Prefix: "10.7.0.0/24",
		VRF: "blue", Slot: 33, NextHop: "2001:db8::1", DecapVRF: "blue",
		HeadendPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.1.0/8")}}
	hosts := []*recordingHost{{}, {}}
	old, err := New(data, &cplane.Client{Host: hosts[0]}, nil)
	if err != nil {
		t.Fatal(err)
	}
	typed, err := NewWithConfig(config, &cplane.Client{Host: hosts[1]}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, controller := range []*Controller{old, typed} {
		controller.Update([]cplane.Event{{Kind: cplane.EventLocalSID, LocalSID: cplane.LocalSIDAllocated{Name: "self", SID: "fd00::1"}}})
		controller.Update([]cplane.Event{{Kind: cplane.EventRoute, Route: cplane.Route{Family: "vpnv4", Prefix: "10.1.0.0/24", SRv6SID: "fd00:2::1", EndpointBehavior: 0xfe02}}})
		controller.Tick(1)
	}
	if !reflect.DeepEqual(hosts[0].calls, hosts[1].calls) {
		t.Fatalf("wire and typed declarations differ: %+v / %+v", hosts[0].calls, hosts[1].calls)
	}
}

func TestTypedConfigurationOwnsMutableValues(t *testing.T) {
	config := Config{Locator: "main", Slot: 32, AuxRaw: []byte{1, 2, 3},
		HeadendPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	host := &recordingHost{}
	controller, err := NewWithConfig(config, &cplane.Client{Host: host}, nil)
	if err != nil {
		t.Fatal(err)
	}
	first := append([]byte(nil), host.calls[len(host.calls)-1].data...)
	config.AuxRaw[0] = 99
	config.HeadendPrefixes[0] = netip.MustParsePrefix("192.0.2.0/24")
	controller.Tick(1)
	if !reflect.DeepEqual(first, host.calls[len(host.calls)-1].data) || controller.config.AuxRaw[0] != 1 {
		t.Fatal("caller mutation changed retried SID declaration")
	}
	if !controller.acceptsRoute(cplane.Route{Family: "vpnv4", Prefix: "10.1.0.0/24", SRv6SID: "fd00::1", EndpointBehavior: 0xfe01}) {
		t.Fatal("caller mutation changed routing filter")
	}
}
