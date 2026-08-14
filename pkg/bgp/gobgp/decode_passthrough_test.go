package gobgp

import (
	"bytes"
	"net/netip"
	"testing"

	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// prefixSIDWithBehavior builds a Prefix-SID attribute carrying one SRv6
// service SID with the given endpoint behavior codepoint.
func prefixSIDWithBehavior(sid netip.Addr, behavior uint16) *gobgppkt.PathAttributePrefixSID {
	return &gobgppkt.PathAttributePrefixSID{
		TLVs: []gobgppkt.PrefixSIDTLVInterface{
			&gobgppkt.SRv6ServiceTLV{
				SubTLVs: []gobgppkt.PrefixSIDTLVInterface{
					&gobgppkt.SRv6InformationSubTLV{
						SID:              sid.AsSlice(),
						EndpointBehavior: behavior,
					},
				},
			},
		},
	}
}

func TestDecodeEndpointBehavior(t *testing.T) {
	sid := netip.MustParseAddr("fd00:1:1::100")
	// 0x0013 is End.DT4 (RFC 8986); the exact value does not matter here,
	// only that the codepoint survives the decode unchanged.
	psid := prefixSIDWithBehavior(sid, 0x0013)
	if got := decodeEndpointBehavior([]gobgppkt.PathAttributeInterface{psid}, 0); got != 0x0013 {
		t.Errorf("decodeEndpointBehavior = %#x, want %#x", got, 0x0013)
	}
}

// A codepoint Vinbero implements no behavior for must still come through:
// an operator's own behavior looks exactly like this, and a plugin claiming
// it can only do so if the number reaches the control plane.
func TestDecodeEndpointBehaviorKeepsUnrecognizedCodepoint(t *testing.T) {
	const experimental = 0xFE01
	psid := prefixSIDWithBehavior(netip.MustParseAddr("fd00:1:1::200"), experimental)
	if got := decodeEndpointBehavior([]gobgppkt.PathAttributeInterface{psid}, 0); got != experimental {
		t.Errorf("decodeEndpointBehavior = %#x, want %#x", got, experimental)
	}
}

func TestDecodeEndpointBehaviorAbsent(t *testing.T) {
	if got := decodeEndpointBehavior(nil, 0); got != 0 {
		t.Errorf("decodeEndpointBehavior(nil, 0) = %#x, want 0", got)
	}
	// A Prefix-SID whose SID is the wrong width is skipped, like the SID
	// decode does, rather than reported with a behavior of its own.
	psid := &gobgppkt.PathAttributePrefixSID{
		TLVs: []gobgppkt.PrefixSIDTLVInterface{
			&gobgppkt.SRv6ServiceTLV{
				SubTLVs: []gobgppkt.PrefixSIDTLVInterface{
					&gobgppkt.SRv6InformationSubTLV{SID: []byte{1, 2, 3}, EndpointBehavior: 0x1234},
				},
			},
		},
	}
	if got := decodeEndpointBehavior([]gobgppkt.PathAttributeInterface{psid}, 0); got != 0 {
		t.Errorf("decodeEndpointBehavior with a malformed SID = %#x, want 0", got)
	}
}

// An experimental-type attribute (253 / 254) is what BGP opaque signaling
// rides on. gobgp keeps it as PathAttributeUnknown; the decode must carry
// the body through so a consumer can parse it.
func TestDecodeUnknownAttrs(t *testing.T) {
	body := []byte{0xde, 0xad, 0xbe, 0xef}
	unknown := &gobgppkt.PathAttributeUnknown{
		PathAttribute: gobgppkt.PathAttribute{
			Flags:  gobgppkt.BGP_ATTR_FLAG_OPTIONAL | gobgppkt.BGP_ATTR_FLAG_TRANSITIVE,
			Type:   253,
			Length: uint16(len(body)),
		},
		Value: body,
	}
	got := decodeUnknownAttrs([]gobgppkt.PathAttributeInterface{unknown})
	if len(got) != 1 {
		t.Fatalf("decodeUnknownAttrs returned %d attributes, want 1", len(got))
	}
	if got[0].Type != 253 {
		t.Errorf("Type = %d, want 253", got[0].Type)
	}
	if !bytes.Equal(got[0].Value, body) {
		t.Errorf("Value = %x, want %x", got[0].Value, body)
	}
	wantFlags := uint8(gobgppkt.BGP_ATTR_FLAG_OPTIONAL | gobgppkt.BGP_ATTR_FLAG_TRANSITIVE)
	if got[0].Flags != wantFlags {
		t.Errorf("Flags = %#x, want %#x", got[0].Flags, wantFlags)
	}
}

// The value must be copied: gobgp owns the decoded path, and a consumer may
// hold the event well past the callback that delivered it.
func TestDecodeUnknownAttrsCopiesValue(t *testing.T) {
	body := []byte{1, 2, 3, 4}
	unknown := &gobgppkt.PathAttributeUnknown{
		PathAttribute: gobgppkt.PathAttribute{Type: 254, Length: uint16(len(body))},
		Value:         body,
	}
	got := decodeUnknownAttrs([]gobgppkt.PathAttributeInterface{unknown})
	if len(got) != 1 {
		t.Fatalf("decodeUnknownAttrs returned %d attributes, want 1", len(got))
	}
	body[0] = 0xff // gobgp reusing or mutating its buffer
	if got[0].Value[0] != 1 {
		t.Fatal("decoded value aliases the gobgp-owned buffer")
	}
}

// A path with only attributes Vinbero understands yields no passthrough,
// so the common case allocates nothing.
func TestDecodeUnknownAttrsEmptyForKnownOnly(t *testing.T) {
	psid := prefixSIDWithBehavior(netip.MustParseAddr("fd00:1:1::100"), 0x0013)
	if got := decodeUnknownAttrs([]gobgppkt.PathAttributeInterface{psid}); got != nil {
		t.Errorf("decodeUnknownAttrs = %+v, want nil", got)
	}
}

func TestRouteEventUnknownAttrLookup(t *testing.T) {
	ev := bgp.RouteEvent{UnknownAttrs: []bgp.UnknownAttribute{
		{Type: 253, Value: []byte{1}},
		{Type: 254, Value: []byte{2}},
	}}
	got, ok := ev.UnknownAttr(254)
	if !ok || len(got.Value) != 1 || got.Value[0] != 2 {
		t.Fatalf("UnknownAttr(254) = (%+v, %v), want the type-254 attribute", got, ok)
	}
	if _, ok := ev.UnknownAttr(99); ok {
		t.Error("UnknownAttr(99) reported an attribute that is not present")
	}
}
