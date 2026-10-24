package cplane_test

import (
	"strings"
	"testing"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/sdk/go/cplane"
	"google.golang.org/protobuf/proto"
)

func TestCompositionHeadendsMatchHostProtobufAcrossChunks(t *testing.T) {
	entries := []cplane.HeadendEntry{
		{},
		{TriggerPrefix: "2001:db8:1234:5678::/64", Segments: []string{"2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff", "", "2001:db8::2"}, SrcAddr: "2001:db8::3", Mode: ^uint32(0)},
		{TriggerPrefix: "10.0.0.1/32", Segments: []string{"fd00::1"}, SrcAddr: "fd00::2", Mode: 2},
	}
	host := &recordingHost{}
	client := &cplane.Client{Host: host, MaxChunkBytes: 256}
	set := cplane.Composition{Revision: 99}
	want := &v1.PluginApplyChunk{DesiredRevision: 99}
	for _, entry := range entries {
		context := strings.Repeat("m", 130)
		set.Headends = append(set.Headends, cplane.ForwardingHeadend{Context: context, Entry: entry})
		want.ForwardingHeadends = append(want.ForwardingHeadends, &v1.PluginForwardingHeadend{Context: context, Entry: &v1.PluginHeadendEntry{TriggerPrefix: entry.TriggerPrefix, Segments: entry.Segments, SrcAddr: entry.SrcAddr, Mode: entry.Mode}})
	}
	if err := client.ApplyComposition(set); err != nil {
		t.Fatal(err)
	}
	actual := &v1.PluginApplyChunk{}
	if len(host.chunks) < 2 || host.commits != 1 || host.aborts != 0 {
		t.Fatalf("wrong transaction/chunk boundaries: %+v", host)
	}
	for _, chunk := range host.chunks {
		if len(chunk) > client.MaxChunkBytes {
			t.Fatal("chunk exceeded byte limit")
		}
		decoded := &v1.PluginApplyChunk{}
		if err := proto.Unmarshal(chunk, decoded); err != nil {
			t.Fatal(err)
		}
		proto.Merge(actual, decoded)
	}
	if !proto.Equal(actual, want) {
		t.Fatalf("composition differs from host protobuf: got %v want %v", actual, want)
	}
}
