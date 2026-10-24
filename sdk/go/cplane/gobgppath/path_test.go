package gobgppath

import (
	"errors"
	"testing"

	"github.com/takehaya/vinbero/sdk/go/cplane"
)

func TestDecodeRejectsUnavailableUnsupportedAndMalformedPaths(t *testing.T) {
	valid := func() cplane.Route {
		return cplane.Route{Peer: "192.0.2.1", BGPPath: &cplane.BGPPath{
			Codec: cplane.BGPPathCodec, AFI: 1, SAFI: 1, NLRI: []byte{24, 192, 0, 2}, RouteKey: []byte("opaque-host-key"),
		}}
	}
	cases := []struct {
		name string
		edit func(*cplane.Route)
		want error
	}{
		{"unavailable", func(r *cplane.Route) { r.BGPPath = nil }, ErrUnavailable},
		{"codec", func(r *cplane.Route) { r.BGPPath.Codec = "future-codec" }, ErrCodec},
		{"encoding", func(r *cplane.Route) { r.BGPPath.EncodingError = "could not encode" }, ErrEncoding},
		{"peer", func(r *cplane.Route) { r.Peer = "bad peer" }, ErrMalformed},
		{"missing key", func(r *cplane.Route) { r.BGPPath.RouteKey = nil }, ErrMalformed},
		{"missing NLRI", func(r *cplane.Route) { r.BGPPath.NLRI = nil }, ErrMalformed},
		{"truncated NLRI", func(r *cplane.Route) { r.BGPPath.NLRI = []byte{24, 192} }, ErrMalformed},
		{"NLRI trailing bytes", func(r *cplane.Route) { r.BGPPath.NLRI = append(r.BGPPath.NLRI, 0) }, ErrMalformed},
		{"truncated attribute", func(r *cplane.Route) { r.BGPPath.Attributes = [][]byte{{64, 1}} }, ErrMalformed},
		{"attribute trailing bytes", func(r *cplane.Route) { r.BGPPath.Attributes = [][]byte{{64, 1, 1, 0, 0}} }, ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := valid()
			tc.edit(&r)
			if p, err := Decode(r); !errors.Is(err, tc.want) || p != nil {
				t.Fatalf("got %v, %v; want %v", p, err, tc.want)
			}
		})
	}
}
