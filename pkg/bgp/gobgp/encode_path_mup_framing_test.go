package gobgp

import (
	"bytes"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// A received Type 1 ST route reaches plugins in the framing it arrived in,
// whichever of the two a peer uses for a route without a source address,
// and keeps the destination key that names only RD and prefix.
func TestPluginBGPReceivedST1Framings(t *testing.T) {
	head := []byte{
		0x01, 0x00, 0x03, 0x00, // 3GPP 5G, T1ST, Length (set below)
		0x00, 0x00, 0xfd, 0xe9, 0x00, 0x00, 0x00, 0x01, // RD 65001:1
		0x20, 0x0a, 0x01, 0x00, 0x01, // 10.1.0.1/32
		0x00, 0x00, 0x01, 0x00, // TEID
		0x09,                         // QFI
		0x20, 0xac, 0x10, 0x00, 0x01, // endpoint 172.16.0.1
	}
	source := []byte{0x20, 0xac, 0x10, 0x00, 0xfe}
	tests := []struct {
		name string
		tail []byte
	}{
		{"draft-01 without source", nil},
		{"-03 without source", []byte{0}},
		{"with source", source},
		{"without source, with TLV", []byte{0, 0xc8, 0x02, 0xde, 0xad}},
	}
	const wantKey = "[type:t1st][rd:65001:1][prefix:10.1.0.1/32]"
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := append(append([]byte{}, head...), tt.tail...)
			raw[3] = byte(len(raw) - 4)
			nlri, err := gobgppkt.NLRIFromSlice(gobgppkt.RF_MUP_IPv4, raw)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			got := encodeBGPPath(&apiutil.Path{Family: gobgppkt.RF_MUP_IPv4, Nlri: nlri}, false)
			if got.EncodingError != "" {
				t.Fatalf("EncodingError = %q", got.EncodingError)
			}
			if !bytes.Equal(got.NLRI, raw) {
				t.Errorf("NLRI\n%x\nwant the received\n%x", got.NLRI, raw)
			}
			if string(got.RouteKey) != wantKey {
				t.Errorf("RouteKey = %q, want %q", got.RouteKey, wantKey)
			}
		})
	}
}
