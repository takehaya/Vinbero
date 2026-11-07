package customcontroller

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/takehaya/vinbero/sdk/go/cplane"
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

func TestJSONConfigurationMatchesTypedDeclarations(t *testing.T) {
	data := []byte(`{"schema_version":1,"routing":{"behavior":65026,"locator":"main","prefix":"10.7.0.1/24",
		"vrf":"blue","slot":33,"next_hop":"2001:db8::1","decap_vrf":"blue","headend_prefixes":["10.0.1.0/8"]}}`)
	config := Config{Behavior: 0xfe02, Locator: "main", Prefix: "10.7.0.0/24",
		VRF: "blue", Slot: 33, NextHop: "2001:db8::1", DecapVRF: "blue",
		HeadendPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	hosts := []*recordingHost{{}, {}}
	decoded, err := New(data, cplane.Grants{}, &cplane.Client{Host: hosts[0]}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.config, config) {
		t.Fatalf("decoded %+v, want %+v", decoded.config, config)
	}
	typed, err := NewWithConfig(config, &cplane.Client{Host: hosts[1]}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, controller := range []*Controller{decoded, typed} {
		controller.Update([]cplane.Event{{Kind: cplane.EventLocalSID, LocalSID: cplane.LocalSIDAllocated{Name: "self", SID: "fd00::1"}}})
		controller.Update([]cplane.Event{{Kind: cplane.EventRoute, Route: cplane.Route{Family: "vpnv4", Prefix: "10.1.0.0/24", SRv6SID: "fd00:2::1", EndpointBehavior: 0xfe02}}})
		controller.Tick(1)
	}
	if !reflect.DeepEqual(hosts[0].calls, hosts[1].calls) {
		t.Fatalf("JSON and typed declarations differ: %+v / %+v", hosts[0].calls, hosts[1].calls)
	}
}

var senderGrants = cplane.Grants{
	Capabilities: []string{"headend", "advertise", "local_sid"}, Behaviors: []uint32{0xfe01},
	Locators: []string{"main"}, VRFs: []string{"vpn-a"}, EndpointSlots: []uint32{33},
	HeadendPrefixes: []netip.Prefix{netip.MustParsePrefix("10.2.0.0/16"), netip.MustParsePrefix("2001:db8::/32")},
}

func TestConfigurationDefaultsFromGrants(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("10.2.0.0/16")}
	for _, tc := range []struct {
		name   string
		data   string
		grants cplane.Grants
		want   Config
	}{
		{"no grants, no config", ``, cplane.Grants{}, Config{Behavior: DefaultBehavior}},
		{"receiver without config", ``, senderGrants, Config{Behavior: 0xfe01, HeadendPrefixes: prefixes}},
		{"receiver with schema only", `{"schema_version":1}`, senderGrants, Config{Behavior: 0xfe01, HeadendPrefixes: prefixes}},
		{"narrower receive prefix", `{"schema_version":1,"routing":{"headend_prefixes":["10.2.3.0/24"]}}`, senderGrants,
			Config{Behavior: 0xfe01, HeadendPrefixes: []netip.Prefix{netip.MustParsePrefix("10.2.3.0/24")}}},
		{"keep a SID", `{"schema_version":1,"routing":{"slot":33}}`, senderGrants,
			Config{Behavior: 0xfe01, Locator: "main", Slot: 33, HeadendPrefixes: prefixes}},
		{"sender", `{"schema_version":1,"routing":{"prefix":"10.1.0.0/16","next_hop":"2001:db8::1"}}`, senderGrants,
			Config{Behavior: 0xfe01, Locator: "main", Slot: 33, VRF: "vpn-a", Prefix: "10.1.0.0/16", NextHop: "2001:db8::1", HeadendPrefixes: prefixes}},
		{"sender with explicit grant values", `{"schema_version":1,"routing":{"behavior":65025,"locator":"main","slot":33,"vrf":"vpn-a","decap_vrf":"vpn-a","prefix":"10.1.0.0/16","next_hop":"2001:db8::1"}}`, senderGrants,
			Config{Behavior: 0xfe01, Locator: "main", Slot: 33, VRF: "vpn-a", DecapVRF: "vpn-a", Prefix: "10.1.0.0/16", NextHop: "2001:db8::1", HeadendPrefixes: prefixes}},
		{"unchecked axes without grants", `{"schema_version":1,"routing":{"behavior":65026,"locator":"other","slot":40,"headend_prefixes":["192.0.2.0/24"]}}`, cplane.Grants{},
			Config{Behavior: 0xfe02, Locator: "other", Slot: 40, HeadendPrefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeConfig([]byte(tc.data), tc.grants)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("config = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestConfigurationContradictingGrantsIsRejected(t *testing.T) {
	several := senderGrants
	several.Behaviors = []uint32{0xfe01, 0xfe02}
	several.Locators = []string{"main", "second"}
	several.EndpointSlots = []uint32{33, 34}
	several.VRFs = []string{"vpn-a", "vpn-b"}
	v6only := senderGrants
	v6only.HeadendPrefixes = []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}
	for _, tc := range []struct {
		name, data string
		grants     cplane.Grants
		want       string
	}{
		{"binary", "\x08\x81\xfc\x03", senderGrants, "configuration must be a JSON object"},
		{"missing schema", `{"routing":{}}`, senderGrants, "schema_version is required"},
		{"unknown key", `{"schema_version":1,"endpoint":{}}`, senderGrants, `unknown key "endpoint"`},
		{"unclaimed behavior", `{"schema_version":1,"routing":{"behavior":65026}}`, senderGrants,
			"routing.behavior 0xFE02 is not claimed by the registration (claims 0xFE01)"},
		{"ambiguous behavior", ``, several, "routing.behavior is required: the registration claims several behaviors (0xFE01, 0xFE02)"},
		{"behavior out of range", `{"schema_version":1,"routing":{"behavior":65536}}`, cplane.Grants{}, "between 1 and 65535"},
		{"prefix outside scope", `{"schema_version":1,"routing":{"headend_prefixes":["10.0.0.0/8"]}}`, senderGrants,
			"routing.headend_prefixes: 10.0.0.0/8 is outside the headend scope (10.2.0.0/16)"},
		{"no IPv4 scope", ``, v6only, "the headend scope grants no IPv4 prefix"},
		{"locator outside scope", `{"schema_version":1,"routing":{"locator":"second","slot":33}}`, senderGrants,
			"routing.locator second is outside the registration's locators (main)"},
		{"ambiguous locator", `{"schema_version":1,"routing":{"behavior":65025,"slot":33}}`, several,
			"routing.locator is required: the registration grants several locators (main, second)"},
		{"slot outside scope", `{"schema_version":1,"routing":{"slot":34}}`, senderGrants,
			"routing.slot 34 is outside the registration's endpoint slots (33)"},
		{"ambiguous slot", `{"schema_version":1,"routing":{"behavior":65025,"locator":"main"}}`, several,
			"routing.slot is required: the registration grants several endpoint slots (33, 34)"},
		{"missing locator", `{"schema_version":1,"routing":{"slot":33}}`, cplane.Grants{},
			"routing.locator is required: the registration grants no locator"},
		{"reserved slot", `{"schema_version":1,"routing":{"locator":"main","slot":31}}`, cplane.Grants{}, "routing.slot must be in [32,64)"},
		{"vrf outside scope", `{"schema_version":1,"routing":{"vrf":"vpn-b","prefix":"10.1.0.0/16","next_hop":"2001:db8::1"}}`, senderGrants,
			"routing.vrf vpn-b is outside the registration's VRFs (vpn-a)"},
		{"ambiguous vrf", `{"schema_version":1,"routing":{"behavior":65025,"locator":"main","slot":33,"prefix":"10.1.0.0/16","next_hop":"2001:db8::1"}}`, several,
			"routing.vrf is required: the registration grants several VRFs (vpn-a, vpn-b)"},
		{"decap vrf outside scope", `{"schema_version":1,"routing":{"decap_vrf":"vpn-b"}}`, senderGrants,
			"routing.decap_vrf vpn-b is outside the registration's VRFs (vpn-a)"},
		{"partial advertisement", `{"schema_version":1,"routing":{"prefix":"10.1.0.0/16"}}`, senderGrants,
			"routing.prefix and routing.next_hop are both required"},
		{"IPv6 advertisement", `{"schema_version":1,"routing":{"prefix":"2001:db8::/64","next_hop":"2001:db8::1"}}`, senderGrants, "routing.prefix: invalid IPv4 prefix"},
		{"IPv4 next hop", `{"schema_version":1,"routing":{"prefix":"10.1.0.0/16","next_hop":"192.0.2.1"}}`, senderGrants, "routing.next_hop"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := &recordingHost{}
			_, err := New([]byte(tc.data), tc.grants, &cplane.Client{Host: host}, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if len(host.calls) != 0 {
				t.Fatal("rejected configuration declared state")
			}
		})
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
