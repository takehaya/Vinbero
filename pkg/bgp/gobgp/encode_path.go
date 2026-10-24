package gobgp

import (
	"fmt"
	"reflect"

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/takehaya/vinbero/pkg/bgp"
)

func encodeBGPPath(p *apiutil.Path, bestKnown bool) *bgp.EncodedBGPPath {
	out := &bgp.EncodedBGPPath{
		Codec: bgp.BGPPathCodec, AFI: p.Family.Afi(), SAFI: p.Family.Safi(),
		Metadata: bgp.BGPPathMetadata{
			Age: p.Age, PeerASN: p.PeerASN, Stale: p.Stale,
			IsFromExternal: p.IsFromExternal, NoImplicitWithdraw: p.NoImplicitWithdraw,
			IsNexthopInvalid: p.IsNexthopInvalid, LocalPathID: p.LocalID,
		},
	}
	if p.PeerID.IsValid() {
		out.Metadata.PeerRouterID = p.PeerID.String()
	}
	if bestKnown {
		best := p.Best
		out.Metadata.Best = &best
	}
	if p.Nlri == nil || (reflect.ValueOf(p.Nlri).Kind() == reflect.Pointer && reflect.ValueOf(p.Nlri).IsNil()) {
		out.EncodingError = "missing NLRI"
		return out
	}
	nlri := copyPacketValue(reflect.ValueOf(p.Nlri)).Interface().(gobgppkt.NLRI)
	var err error
	out.NLRI, err = nlri.Serialize()
	if err != nil {
		out.EncodingError = fmt.Sprintf("encode NLRI: %v", err)
		return out
	}
	out.RouteKey, err = packetRouteKey(nlri)
	if err != nil {
		out.EncodingError = fmt.Sprintf("encode route key: %v", err)
		return out
	}
	// A withdraw carries the same destination key without stale attributes.
	if p.Withdrawal {
		return out
	}
	for i, attr := range p.Attrs {
		if attr == nil || (reflect.ValueOf(attr).Kind() == reflect.Pointer && reflect.ValueOf(attr).IsNil()) {
			out.EncodingError = fmt.Sprintf("encode attribute %d: nil attribute", i)
			break
		}
		owned := copyPacketValue(reflect.ValueOf(attr)).Interface().(gobgppkt.PathAttributeInterface)
		data, err := owned.Serialize()
		if err != nil {
			out.EncodingError = fmt.Sprintf("encode attribute %d: %v", i, err)
			break
		}
		out.Attributes = append(out.Attributes, data)
	}
	if out.EncodingError != "" {
		out.Attributes = nil // Never expose a successful-looking partial attribute set.
	}
	return out
}

// Some packet serializers mutate nested TLV lengths. Copy the packet graph
// before calling them; GoBGP shares those objects with its RIB and watchers.
// This is for the pinned codec's supported packet types, not arbitrary graphs.
func copyPacketValue(v reflect.Value) reflect.Value {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Slice, reflect.Map:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
	}
	switch v.Kind() {
	case reflect.Pointer:
		out := reflect.New(v.Type().Elem())
		out.Elem().Set(copyPacketValue(v.Elem()))
		return out
	case reflect.Interface:
		out := reflect.New(v.Type()).Elem()
		out.Set(copyPacketValue(v.Elem()))
		return out
	case reflect.Slice:
		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(copyPacketValue(v.Index(i)))
		}
		return out
	case reflect.Map:
		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		iter := v.MapRange()
		for iter.Next() {
			out.SetMapIndex(iter.Key(), copyPacketValue(iter.Value()))
		}
		return out
	case reflect.Struct, reflect.Array:
		out := reflect.New(v.Type()).Elem()
		out.Set(v)
		if v.Kind() == reflect.Array {
			for i := 0; i < v.Len(); i++ {
				out.Index(i).Set(copyPacketValue(v.Index(i)))
			}
		} else {
			for i := 0; i < v.NumField(); i++ {
				// Opaque value types such as netip.Addr have immutable internals.
				if v.Type().Field(i).IsExported() {
					out.Field(i).Set(copyPacketValue(v.Field(i)))
				}
			}
		}
		return out
	default:
		return v
	}
}

// Match the pinned GoBGP table's addrPrefixOnlySerialize/tableKey semantics.
// In particular VPN labels, EVPN ESI/labels, and MUP ST1 session parameters
// can change without creating a new BGP destination. Full NLRI stays separate.
func packetRouteKey(nlri gobgppkt.NLRI) ([]byte, error) {
	switch n := nlri.(type) {
	case *gobgppkt.IPAddrPrefix:
		return append(n.Prefix.Addr().AsSlice(), byte(n.Prefix.Bits())), nil
	case *gobgppkt.LabeledVPNIPAddrPrefix:
		rd, err := n.RD.Serialize()
		if err != nil {
			return nil, err
		}
		key := append(rd, n.Prefix.Addr().AsSlice()...)
		return append(key, byte(n.Prefix.Bits())), nil
	default:
		return []byte(nlri.String()), nil
	}
}
