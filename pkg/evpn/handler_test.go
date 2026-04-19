package evpn

import (
	"errors"
	"testing"
)

func TestStubHandlerReturnsNotImplemented(t *testing.T) {
	h := NewStubHandler()
	if err := h.ApplyRoute(Route{Type: RouteTypeMACIPAdvertisement}); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("ApplyRoute: expected ErrNotImplemented, got %v", err)
	}
	if err := h.WithdrawRoute(Route{Type: RouteTypeMACIPAdvertisement}); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("WithdrawRoute: expected ErrNotImplemented, got %v", err)
	}
}

// TestPayloadTypes exercises the sealed Payload interface and covers the
// RT2/RT3/RT4 payload variants with a typed switch, the shape future handler
// implementations will use for dispatch.
func TestPayloadTypes(t *testing.T) {
	cases := []Route{
		{Type: RouteTypeMACIPAdvertisement, Payload: MACIPAdvertisement{BDID: 100}},
		{Type: RouteTypeInclusiveMulticast, Payload: InclusiveMulticast{BDID: 100}},
		{Type: RouteTypeEthernetSegment, Payload: EthernetSegment{IsDFCandidate: true}},
	}
	for _, r := range cases {
		switch p := r.Payload.(type) {
		case MACIPAdvertisement, InclusiveMulticast, EthernetSegment:
			_ = p
		default:
			t.Errorf("payload %T does not implement the sealed Payload interface", r.Payload)
		}
	}
}
