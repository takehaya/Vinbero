package cplane

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	sdk "github.com/takehaya/vinbero/sdk/go/cplane"
)

// The grants a plugin reads are the registration as Register stores it,
// round-tripped through the SDK decoder both backends use.
func TestEncodeGrantsRoundTripsThroughSDK(t *testing.T) {
	scope, err := ParseScope(ScopeSpec{
		Locators: []string{"main"}, VRFs: []string{"vpn-a"},
		HeadendPrefixes: []string{"10.2.0.0/16", "10.1.0.0/16"},
		HeadendV4Slots:  []uint32{16}, EndpointSlots: []uint32{33},
	})
	if err != nil {
		t.Fatal(err)
	}
	caps, err := wasm.ParseCapabilities([]string{"local_sid", "headend"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeGrants(caps, []bgp.Family{bgp.FamilyVPNv4}, []uint16{0xfe01}, scope)
	if err != nil {
		t.Fatal(err)
	}
	got, err := sdk.DecodeGrants(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := sdk.Grants{
		Capabilities: []string{"headend", "local_sid"}, Families: []string{"vpnv4"}, Behaviors: []uint32{0xfe01},
		Locators: []string{"main"}, VRFs: []string{"vpn-a"},
		HeadendPrefixes: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16"), netip.MustParsePrefix("10.2.0.0/16")},
		HeadendV4Slots:  []uint32{16}, EndpointSlots: []uint32{33},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("grants = %+v, want %+v", got, want)
	}
	empty, err := EncodeGrants(nil, nil, nil, Scope{})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := sdk.DecodeGrants(empty); err != nil || !reflect.DeepEqual(got, sdk.Grants{}) {
		t.Fatalf("empty registration grants = %+v, %v", got, err)
	}
}
