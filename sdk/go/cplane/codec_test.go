package cplane_test

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/sdk/go/cplane"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestDecodeHostEventsAndOwnTheirBuffers(t *testing.T) {
	batch := &v1.PluginEventBatch{Events: []*v1.PluginEvent{
		{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_ROUTE, Sequence: 99, Route: &v1.PluginRoute{
			Family: "vpnv6", IsWithdraw: true, Peer: "2001:db8::1", PathId: 0xffffffff,
			EndpointBehavior: 0xfe01, Rd: "65000:1", Prefix: "2001:db8:1::/64",
			Srv6Sid: "fc00::1", NextHop: "2001:db8::2", RouteTargets: []string{"65000:1", "65000:2"},
			Color: 42, Mac: "02:00:00:00:00:01", IpAddr: "10.0.0.1", EthernetTag: 12, Esi: []byte{1, 2, 3},
			UnknownAttrs: []*v1.PluginUnknownAttribute{{Type: 253, Flags: 192, Value: []byte{4, 5, 6}}},
		}},
		{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_MAC, Mac: &v1.PluginMacEvent{BdId: 7, Mac: "02:00:00:00:00:02", Added: true}},
		{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_LOCAL_SID, LocalSid: &v1.PluginLocalSidAllocated{Name: "self", Sid: "fc00::2", Locator: "main"}},
		{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_START_OF_REPLAY, ReplaySource: "bgp"},
	}}
	data, err := proto.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	// New host fields of either fixed-width wire type must not break the guest.
	data = protowire.AppendTag(data, 100, protowire.Fixed32Type)
	data = protowire.AppendFixed32(data, 1)
	data = protowire.AppendTag(data, 101, protowire.Fixed64Type)
	data = protowire.AppendFixed64(data, 2)
	events, err := cplane.DecodeEvents(data)
	if err != nil {
		t.Fatal(err)
	}
	clear(data)
	want := []cplane.Event{
		{Kind: cplane.EventRoute, Sequence: 99, Route: cplane.Route{
			Family: "vpnv6", Withdraw: true, Peer: "2001:db8::1", PathID: 0xffffffff,
			EndpointBehavior: 0xfe01, RD: "65000:1", Prefix: "2001:db8:1::/64", SRv6SID: "fc00::1",
			NextHop: "2001:db8::2", RouteTargets: []string{"65000:1", "65000:2"}, Color: 42,
			MAC: "02:00:00:00:00:01", IPAddr: "10.0.0.1", EthernetTag: 12, ESI: []byte{1, 2, 3},
			UnknownAttributes: []cplane.UnknownAttribute{{Type: 253, Flags: 192, Value: []byte{4, 5, 6}}},
		}},
		{Kind: cplane.EventMAC, MAC: cplane.MACEvent{BDID: 7, MAC: "02:00:00:00:00:02", Added: true}},
		{Kind: cplane.EventLocalSID, LocalSID: cplane.LocalSIDAllocated{Name: "self", SID: "fc00::2", Locator: "main"}},
		{Kind: cplane.EventStartOfReplay, ReplaySource: "bgp"},
	}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("decoded events = %+v, want %+v", events, want)
	}
}

func TestMalformedBatchNeverReturnsPartialEvents(t *testing.T) {
	valid, err := proto.Marshal(&v1.PluginEventBatch{Events: []*v1.PluginEvent{{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_END_OF_REPLAY, ReplaySource: "bgp"}}})
	if err != nil {
		t.Fatal(err)
	}
	invalid := [][]byte{
		{0},          // illegal field zero
		{0x0a, 0x80}, // truncated length
		append([]byte{0x0a}, bytes.Repeat([]byte{0xff}, 10)...),
		{0x0a, 0xff, 0xff, 0xff, 0xff, 0x0f},                                   // exceeds 32-bit int
		{0x0a, 2, 8, 0x80},                                                     // truncated nested varint
		{0x0a, 2, 0x0a, 0},                                                     // event kind encoded as bytes
		{0x0a, 11, 8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2}, // uint64 overflow
	}
	for _, tail := range invalid {
		data := append(append([]byte(nil), valid...), tail...)
		if events, err := cplane.DecodeEvents(data); err == nil || events != nil {
			t.Fatalf("accepted malformed tail %x: events=%+v, err=%v", tail, events, err)
		}
	}
}

func TestEncodeEventDisposition(t *testing.T) {
	data := cplane.EncodeResults([]cplane.EventResult{{Sequence: 15, Disposition: cplane.Quarantine, Reason: "unsupported attribute"}})
	var status v1.PluginEventStatus
	if err := proto.Unmarshal(data, &status); err != nil {
		t.Fatal(err)
	}
	want := &v1.PluginEventStatus{Results: []*v1.PluginEventResult{{Sequence: 15, Disposition: v1.PluginEventDisposition_PLUGIN_EVENT_DISPOSITION_QUARANTINE, Reason: "unsupported attribute"}}}
	if !proto.Equal(&status, want) {
		t.Fatalf("status = %v", &status)
	}
}

type recordingHost struct {
	kind                    cplane.Kind
	chunks                  [][]byte
	begins, commits, aborts int
	refuseBegin             bool
	putStatus, commitStatus cplane.Status
}

func (h *recordingHost) Begin(kind cplane.Kind) uint64 {
	h.begins++
	h.kind = kind
	if h.refuseBegin {
		return 0
	}
	return uint64(h.begins)
}
func (h *recordingHost) Put(_ uint64, data []byte) cplane.Status {
	h.chunks = append(h.chunks, append([]byte(nil), data...))
	return h.putStatus
}
func (h *recordingHost) Commit(uint64) cplane.Status { h.commits++; return h.commitStatus }
func (h *recordingHost) Abort(uint64)                { h.aborts++ }

func TestTypedDeclarationsMatchHostProtobuf(t *testing.T) {
	cases := []struct {
		name  string
		kind  cplane.Kind
		apply func(*cplane.Client) error
		want  *v1.PluginApplyChunk
	}{
		{"headend v4", cplane.HeadendV4, func(c *cplane.Client) error {
			return c.ApplyHeadendV4([]cplane.HeadendEntry{{TriggerPrefix: "10.0.0.0/24", Segments: []string{"fc00::1", "fc00::2"}, SrcAddr: "fc00::3", Mode: 16}})
		},
			&v1.PluginApplyChunk{HeadendEntries: []*v1.PluginHeadendEntry{{TriggerPrefix: "10.0.0.0/24", Segments: []string{"fc00::1", "fc00::2"}, SrcAddr: "fc00::3", Mode: 16}}}},
		{"headend v6", cplane.HeadendV6, func(c *cplane.Client) error {
			return c.ApplyHeadendV6([]cplane.HeadendEntry{{TriggerPrefix: "2001:db8::/64", Segments: []string{"fc00::1"}}})
		},
			&v1.PluginApplyChunk{HeadendEntries: []*v1.PluginHeadendEntry{{TriggerPrefix: "2001:db8::/64", Segments: []string{"fc00::1"}}}}},
		{"advertise", cplane.Advertise, func(c *cplane.Client) error {
			return c.ApplyAdvertise([]cplane.AdvertisedRoute{{Family: "vpnv4", Prefix: "10.0.0.0/24", SRv6SID: "fc00::1", EndpointBehavior: 0xfe01, NextHop: "2001:db8::1", VRF: "vpn-a"}})
		},
			&v1.PluginApplyChunk{AdvertisedRoutes: []*v1.PluginAdvertisedRoute{{Family: "vpnv4", Prefix: "10.0.0.0/24", Srv6Sid: "fc00::1", EndpointBehavior: 0xfe01, NextHop: "2001:db8::1", Vrf: "vpn-a"}}}},
		{"local SID", cplane.LocalSIDs, func(c *cplane.Client) error {
			return c.ApplyLocalSIDs([]cplane.LocalSID{{Name: "self", Locator: "main", Slot: 33, AuxRaw: []byte{1, 2, 3}, DecapVRF: "vpn-a"}})
		},
			&v1.PluginApplyChunk{LocalSids: []*v1.PluginLocalSid{{Name: "self", Locator: "main", Slot: 33, AuxRaw: []byte{1, 2, 3}, DecapVrf: "vpn-a"}}}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			host := &recordingHost{}
			if err := tt.apply(&cplane.Client{Host: host}); err != nil {
				t.Fatal(err)
			}
			if host.kind != tt.kind || host.commits != 1 || host.aborts != 0 || len(host.chunks) != 1 {
				t.Fatalf("transport: %+v", host)
			}
			var actual v1.PluginApplyChunk
			if err := proto.Unmarshal(host.chunks[0], &actual); err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(&actual, tt.want) {
				t.Fatalf("declaration = %v, want %v", &actual, tt.want)
			}
		})
	}
}

func TestChunkedDeclarationCommitsOnlyAfterAllEntries(t *testing.T) {
	host := &recordingHost{}
	client := &cplane.Client{Host: host, MaxChunkBytes: 40}
	entries := []cplane.HeadendEntry{
		{TriggerPrefix: "10.0.0.0/24", Segments: []string{"fc00::1"}},
		{TriggerPrefix: "10.0.1.0/24", Segments: []string{"fc00::2"}},
		{TriggerPrefix: "10.0.2.0/24", Segments: []string{"fc00::3"}},
	}
	if err := client.ApplyHeadendV4(entries); err != nil {
		t.Fatal(err)
	}
	if len(host.chunks) != 3 || host.begins != 1 || host.commits != 1 || host.aborts != 0 {
		t.Fatalf("transport: %+v", host)
	}
	for i, chunk := range host.chunks {
		if len(chunk) > client.MaxChunkBytes {
			t.Fatal("chunk limit exceeded")
		}
		var decoded v1.PluginApplyChunk
		if err := proto.Unmarshal(chunk, &decoded); err != nil {
			t.Fatal(err)
		}
		if len(decoded.HeadendEntries) != 1 || decoded.HeadendEntries[0].TriggerPrefix != entries[i].TriggerPrefix {
			t.Fatalf("wrong chunk: %v", &decoded)
		}
	}
}

func TestDeclarationFailureClosesStagingAndEmptySetStillCommits(t *testing.T) {
	entry := []cplane.HeadendEntry{{TriggerPrefix: "10.0.0.0/24", Segments: []string{"fc00::1"}}}
	for _, stage := range []string{"begin", "put", "commit", "oversize", "empty"} {
		t.Run(stage, func(t *testing.T) {
			host := &recordingHost{}
			client := &cplane.Client{Host: host}
			desired := entry
			switch stage {
			case "begin":
				host.refuseBegin = true
			case "put":
				host.putStatus = cplane.StatusDenied
			case "commit":
				host.commitStatus = cplane.StatusInternal
			case "oversize":
				client.MaxChunkBytes = 1
			case "empty":
				desired = nil
			}
			err := client.ApplyHeadendV4(desired)
			if stage == "empty" {
				if err != nil || host.commits != 1 || len(host.chunks) != 0 {
					t.Fatalf("empty set did not commit: %+v %v", host, err)
				}
				return
			}
			if err == nil {
				t.Fatal("failure was ignored")
			}
			if stage == "begin" && !errors.Is(err, cplane.ErrBeginRefused) {
				t.Fatal(err)
			}
			wantAbort := 0
			if stage == "put" || stage == "oversize" {
				wantAbort = 1
			}
			wantCommit := 0
			if stage == "commit" {
				wantCommit = 1
			}
			if host.aborts != wantAbort || host.commits != wantCommit {
				t.Fatalf("failed transport: %+v", host)
			}
		})
	}
}
