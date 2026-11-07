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
	// Repeated families and claims reach the plugin once each, sorted, so a
	// behavior given twice is still the registration's single claim.
	repeated, err := EncodeGrants(nil, []bgp.Family{bgp.FamilyVPNv6, bgp.FamilyVPNv4, bgp.FamilyVPNv6}, []uint16{0xfe02, 0xfe01, 0xfe02}, Scope{})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := sdk.DecodeGrants(repeated); err != nil || !reflect.DeepEqual(got.Families, []string{"vpnv4", "vpnv6"}) ||
		!reflect.DeepEqual(got.Behaviors, []uint32{0xfe01, 0xfe02}) {
		t.Fatalf("repeated registration values = %+v, %v", got, err)
	}
	single, err := EncodeGrants(nil, nil, []uint16{0xfe01, 0xfe01}, Scope{})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := sdk.DecodeGrants(single); err != nil || !reflect.DeepEqual(got.Behaviors, []uint32{0xfe01}) {
		t.Fatalf("repeated claim = %+v, %v", got, err)
	}
	empty, err := EncodeGrants(nil, nil, nil, Scope{})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := sdk.DecodeGrants(empty); err != nil || !reflect.DeepEqual(got, sdk.Grants{}) {
		t.Fatalf("empty registration grants = %+v, %v", got, err)
	}
}
