// Package gobgppath encodes and decodes packet models using GoBGP's native
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
	ErrEncoding    = errors.New("gobgppath: could not encode path")
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
	out, err = decodePacket(p, !r.Withdraw)
	if err != nil {
		return nil, err
	}
	out.Key, out.Withdraw = key, r.Withdraw
	return out, nil
}

// DecodePacket decodes a packet for an outgoing advertisement without requiring
// host-assigned route identity or a peer. The returned model owns its buffers.
// Use Decode for received routes whose identity must also be validated.
func DecodePacket(p *cplane.BGPPath) (*Path, error) {
	return decodePacket(p, true)
}

func decodePacket(p *cplane.BGPPath, attributes bool) (out *Path, err error) {
	if p == nil {
		return nil, ErrUnavailable
	}
	if p.Codec != cplane.BGPPathCodec {
		return nil, fmt.Errorf("%w: %q", ErrCodec, p.Codec)
	}
	if p.EncodingError != "" {
		return nil, fmt.Errorf("%w: %s", ErrEncoding, p.EncodingError)
	}
	if p.AFI == 0 || p.SAFI == 0 || len(p.NLRI) == 0 {
		return nil, fmt.Errorf("%w: missing family or NLRI", ErrMalformed)
	}
	// Turn malformed packet bounds panics into rejected paths, not guest traps.
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
	out = &Path{NLRI: nlri, Metadata: p.Metadata}
	if p.Metadata.Best != nil {
		best := *p.Metadata.Best
		out.Metadata.Best = &best
	}
	if !attributes {
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
