package cplane

import (
	"fmt"
	"github.com/takehaya/vinbero/sdk/go/cplane/wire"
)

func (c *Client) ApplyComposition(set Composition) error {
	if set.Revision == 0 {
		return fmt.Errorf("composition: nonzero input revision required")
	}
	for _, r := range set.Advertisements {
		if r.Path == nil {
			return fmt.Errorf("composition: missing advertised path")
		}
	}
	count := 1 + len(set.Headends) + len(set.Uplinks) + len(set.EVPN) + len(set.Advertisements)
	return c.apply(CompositionSet, count, func(i int) []byte {
		var body, chunk wire.Encoder
		if i == 0 {
			chunk.Uint(8, set.Revision)
			return chunk
		}
		i--
		if i < len(set.Headends) {
			h := set.Headends[i]
			body.String(1, h.Context)
			body.Message(2, encodeHeadendBody(h.Entry))
			chunk.Message(4, body)
			return chunk
		}
		i -= len(set.Headends)
		if i < len(set.Uplinks) {
			u := set.Uplinks[i]
			body.String(1, u.Context)
			body.String(2, u.Endpoint)
			body.Uint(3, uint64(u.TEID))
			body.Uint(4, uint64(u.TEIDBits))
			for _, s := range u.Segments {
				body.Message(5, []byte(s))
			}
			body.String(6, u.SrcAddr)
			chunk.Message(5, body)
			return chunk
		}
		i -= len(set.Uplinks)
		if i < len(set.EVPN) {
			e := set.EVPN[i]
			body.String(1, e.Context)
			body.String(2, e.MAC)
			for _, s := range e.Segments {
				body.Message(3, []byte(s))
			}
			body.String(4, e.SrcAddr)
			body.String(5, e.RemoteSrc)
			if e.Flood {
				body.Uint(6, 1)
			}
			chunk.Message(6, body)
			return chunk
		}
		i -= len(set.EVPN)
		r := set.Advertisements[i]
		body.String(1, r.Context)
		body.String(2, r.VRF)
		var path wire.Encoder
		path.String(1, r.Path.Codec)
		path.Uint(2, uint64(r.Path.AFI))
		path.Uint(3, uint64(r.Path.SAFI))
		path.Bytes(4, r.Path.NLRI)
		for _, a := range r.Path.Attributes {
			path.Message(5, a)
		}
		body.Message(3, path)
		chunk.Message(7, body)
		return chunk
	})
}
