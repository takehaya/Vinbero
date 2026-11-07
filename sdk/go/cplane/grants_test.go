package cplane_test

import (
	"net/netip"
	"reflect"
	"slices"
	"testing"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/sdk/go/cplane"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestGrantsMatchHostProtobuf(t *testing.T) {
	data, err := proto.Marshal(&v1.PluginGrants{
		Version: 1, Capabilities: []string{"advertise", "headend"}, Families: []string{"vpnv4"},
		Behaviors: []uint32{0xfe01, 0xfe02}, Locators: []string{"main"}, Vrfs: []string{"vpn-a", "vpn-b"},
		HeadendPrefixes: []string{"10.2.0.0/16", "2001:db8::/32"},
		HeadendV4Slots:  []uint32{16}, HeadendV6Slots: []uint32{17}, EndpointSlots: []uint32{33, 0xffffffff},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Unpacked integers and fields from a newer host are accepted too.
	data = protowire.AppendTag(data, 10, protowire.VarintType)
	data = protowire.AppendVarint(data, 34)
	data = protowire.AppendTag(data, 100, protowire.BytesType)
	data = protowire.AppendString(data, "future")
	got, err := cplane.DecodeGrants(data)
	if err != nil {
		t.Fatal(err)
	}
	want := cplane.Grants{
		Capabilities: []string{"advertise", "headend"}, Families: []string{"vpnv4"},
		Behaviors: []uint32{0xfe01, 0xfe02}, Locators: []string{"main"}, VRFs: []string{"vpn-a", "vpn-b"},
		HeadendPrefixes: []netip.Prefix{netip.MustParsePrefix("10.2.0.0/16"), netip.MustParsePrefix("2001:db8::/32")},
		HeadendV4Slots:  []uint32{16}, HeadendV6Slots: []uint32{17}, EndpointSlots: []uint32{33, 0xffffffff, 34},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("grants = %+v, want %+v", got, want)
	}
	if !slices.Contains(got.Capabilities, cplane.CapabilityHeadend) || slices.Contains(got.Capabilities, cplane.CapabilityLocalSID) {
		t.Fatal("capabilities do not follow the grant")
	}
}

func TestGrantsRejectUnknownVersionAndMalformedInput(t *testing.T) {
	if g, err := cplane.DecodeGrants(nil); err != nil || !reflect.DeepEqual(g, cplane.Grants{}) {
		t.Fatalf("empty grants = %+v, %v", g, err)
	}
	for name, msg := range map[string]*v1.PluginGrants{
		"missing version": {Locators: []string{"main"}},
		"future version":  {Version: 2},
		"bad prefix":      {Version: 1, HeadendPrefixes: []string{"10.0.0.0"}},
	} {
		data, err := proto.Marshal(msg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cplane.DecodeGrants(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	tooLarge := protowire.AppendTag(nil, 4, protowire.BytesType)
	tooLarge = protowire.AppendBytes(tooLarge, protowire.AppendVarint(nil, 1<<32))
	truncated := protowire.AppendTag(nil, 8, protowire.BytesType)
	truncated = protowire.AppendBytes(truncated, []byte{0x80})
	for name, data := range map[string][]byte{"overflow": tooLarge, "truncated": truncated} {
		if _, err := cplane.DecodeGrants(append(protowire.AppendVarint([]byte{0x08}, 1), data...)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
