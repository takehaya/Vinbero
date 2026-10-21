// Package gobgppath decodes the received packet model using GoBGP's native
// NLRI and attribute types. It does not expose GoBGP server operations.
package gobgppath

import (
	"errors"
	"fmt"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/takehaya/vinbero/sdk/go/cplane"
)

var (
	ErrUnavailable = errors.New("gobgppath: full BGP input unavailable")
	ErrCodec       = errors.New("gobgppath: unsupported codec")
	ErrEncoding    = errors.New("gobgppath: host could not encode path")
	ErrMalformed   = errors.New("gobgppath: malformed path")
)

type Path struct {
	Key        cplane.BGPPathKey
	Withdraw   bool
	NLRI       bgp.NLRI
	Attributes []bgp.PathAttributeInterface
	Metadata   cplane.BGPPathMetadata
}

// Decode returns an owned GoBGP model. It does not borrow the event's buffers.
// Use Route.BGPKey first when maintaining a view: a rejected attribute update
// still replaces the previous path, rather than leaving stale state behind.
func Decode(r cplane.Route) (out *Path, err error) {
	if r.BGPPath == nil {
		return nil, ErrUnavailable
	}
	p := r.BGPPath
	if p.Codec != cplane.BGPPathCodec {
		return nil, fmt.Errorf("%w: %q", ErrCodec, p.Codec)
	}
	if p.EncodingError != "" {
		return nil, fmt.Errorf("%w: %s", ErrEncoding, p.EncodingError)
	}
	key, ok := r.BGPKey()
	if !ok || len(p.NLRI) == 0 {
		return nil, fmt.Errorf("%w: missing family, route key, NLRI or peer", ErrMalformed)
	}
	// The packet library is an independent parser. Turn a malformed packet's
	// bounds panic into a rejected event rather than trapping the whole guest.
	defer func() {
		if v := recover(); v != nil {
			out, err = nil, fmt.Errorf("%w: %v", ErrMalformed, v)
		}
	}()
	nlri, err := bgp.NLRIFromSlice(bgp.NewFamily(p.AFI, p.SAFI), append([]byte(nil), p.NLRI...))
	if err != nil {
		return nil, fmt.Errorf("%w: NLRI: %v", ErrMalformed, err)
	}
	if nlri.Len() != len(p.NLRI) {
		return nil, fmt.Errorf("%w: NLRI length", ErrMalformed)
	}
	out = &Path{Key: key, Withdraw: r.Withdraw, NLRI: nlri, Metadata: p.Metadata}
	if p.Metadata.Best != nil {
		best := *p.Metadata.Best
		out.Metadata.Best = &best
	}
	if r.Withdraw {
		return out, nil
	}
	for i, raw := range p.Attributes {
		data := append([]byte(nil), raw...)
		attr, err := bgp.GetPathAttribute(data)
		if err == nil {
			err = attr.DecodeFromBytes(data)
		}
		if err != nil {
			return nil, fmt.Errorf("%w: attribute %d: %v", ErrMalformed, i, err)
		}
		if attr.Len() != len(data) {
			return nil, fmt.Errorf("%w: attribute %d length", ErrMalformed, i)
		}
		out.Attributes = append(out.Attributes, attr)
	}
	return out, nil
}
