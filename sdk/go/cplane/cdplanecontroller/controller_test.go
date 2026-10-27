package cdplanecontroller

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"

	"github.com/takehaya/vinbero/sdk/go/cplane"
)

const senderConfig = `{"schema_version":1,"routing":{"locator":"main","prefix":"10.7.0.1/24","vrf":"blue","slot":32,"next_hop":"2001:db8::1","decap_vrf":"blue"},"endpoint":{"allowed_underlay_prefix":"2001:db8:ff::1234/64"}}`

func TestEndpointEncoding(t *testing.T) {
	config, err := decodeConfig([]byte(senderConfig))
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString("0100000000000000400000000000000020010db800ff00000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(config.AuxRaw, want) || config.Prefix != "10.7.0.0/24" || config.Behavior != 0xfe01 {
		t.Fatalf("incorrect normalization or encoding: %+v %x", config, config.AuxRaw)
	}
	for _, value := range []string{"::/0", "2001:db8::1/128"} {
		if _, err := EncodeEndpointAux(netip.MustParsePrefix(value)); err != nil {
			t.Fatalf("valid IPv6 policy %s: %v", value, err)
		}
	}
	for _, prefix := range []netip.Prefix{{}, netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("::ffff:192.0.2.1/128")} {
		if _, err := EncodeEndpointAux(prefix); err == nil {
			t.Fatalf("invalid IPv6 policy accepted: %s", prefix)
		}
	}
}

type countingHost struct{ calls int }

func (h *countingHost) Begin(cplane.Kind) uint64       { h.calls++; return uint64(h.calls) }
func (*countingHost) Put(uint64, []byte) cplane.Status { return cplane.StatusOK }
func (*countingHost) Commit(uint64) cplane.Status      { return cplane.StatusOK }
func (*countingHost) Abort(uint64)                     {}

func TestConfigurationRejectedBeforeDeclarations(t *testing.T) {
	cases := map[string]string{
		"malformed":              `{"schema_version":`,
		"null":                   `null`,
		"null scalar":            strings.Replace(senderConfig, `"slot":32`, `"slot":null`, 1),
		"null endpoint":          strings.Replace(senderConfig, `{"allowed_underlay_prefix":"2001:db8:ff::1234/64"}`, `null`, 1),
		"missing schema":         `{"routing":{}}`,
		"unknown schema":         `{"schema_version":2,"routing":{}}`,
		"missing routing":        `{"schema_version":1}`,
		"unknown field":          `{"schema_version":1,"routing":{"headend_prefix":"10.0.0.0/8"}}`,
		"unknown endpoint field": strings.Replace(senderConfig, `allowed_underlay_prefix`, `allowed_source`, 1),
		"trailing object":        senderConfig + `{}`,
		"trailing garbage":       senderConfig + `x`,
		"behavior zero":          `{"schema_version":1,"routing":{"behavior":0}}`,
		"behavior too large":     `{"schema_version":1,"routing":{"behavior":65536}}`,
		"slot reserved":          strings.Replace(senderConfig, `"slot":32`, `"slot":31`, 1),
		"slot too large":         strings.Replace(senderConfig, `"slot":32`, `"slot":64`, 1),
		"slot negative":          strings.Replace(senderConfig, `"slot":32`, `"slot":-1`, 1),
		"slot overflow":          strings.Replace(senderConfig, `"slot":32`, `"slot":4294967296`, 1),
		"incomplete allocation":  `{"schema_version":1,"routing":{"slot":32}}`,
		"missing policy":         `{"schema_version":1,"routing":{"slot":32,"locator":"main","decap_vrf":"blue"}}`,
		"missing decap vrf":      strings.Replace(senderConfig, `,"decap_vrf":"blue"`, ``, 1),
		"receiver policy":        `{"schema_version":1,"routing":{},"endpoint":{"allowed_underlay_prefix":"::/0"}}`,
		"partial advertisement":  strings.Replace(senderConfig, `,"next_hop":"2001:db8::1"`, ``, 1),
		"invalid route":          strings.Replace(senderConfig, `10.7.0.1/24`, `bad`, 1),
		"IPv6 route":             strings.Replace(senderConfig, `10.7.0.1/24`, `2001:db8::/64`, 1),
		"invalid headend":        `{"schema_version":1,"routing":{"headend_prefixes":["bad"]}}`,
		"IPv6 headend":           `{"schema_version":1,"routing":{"headend_prefixes":["2001:db8::/64"]}}`,
		"invalid next hop":       strings.Replace(senderConfig, `"2001:db8::1"`, `"bad"`, 1),
		"IPv4 next hop":          strings.Replace(senderConfig, `"2001:db8::1"`, `"192.0.2.1"`, 1),
		"mapped next hop":        strings.Replace(senderConfig, `"2001:db8::1"`, `"::ffff:192.0.2.1"`, 1),
		"zone next hop":          strings.Replace(senderConfig, `"2001:db8::1"`, `"fe80::1%eth0"`, 1),
		"invalid policy":         strings.Replace(senderConfig, `2001:db8:ff::1234/64`, `bad`, 1),
		"IPv4 policy":            strings.Replace(senderConfig, `2001:db8:ff::1234/64`, `192.0.2.1/32`, 1),
		"mapped policy":          strings.Replace(senderConfig, `2001:db8:ff::1234/64`, `::ffff:192.0.2.1/128`, 1),
		"zone policy":            strings.Replace(senderConfig, `2001:db8:ff::1234/64`, `fe80::1%eth0/64`, 1),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			host := &countingHost{}
			if _, err := New([]byte(data), &cplane.Client{Host: host}, nil); err == nil || host.calls != 0 {
				t.Fatalf("invalid configuration accepted or declared state: calls=%d, error=%v", host.calls, err)
			}
		})
	}
}

func TestReceiverConfiguration(t *testing.T) {
	config, err := decodeConfig([]byte(`{"schema_version":1,"routing":{"behavior":65025,"headend_prefixes":["10.7.1.2/16"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if config.Behavior != 65025 || len(config.AuxRaw) != 0 || len(config.HeadendPrefixes) != 1 || config.HeadendPrefixes[0].String() != "10.7.0.0/16" {
		t.Fatalf("receiver config changed: %+v", config)
	}
}
