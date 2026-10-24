package gobgppath

import (
	"fmt"
	"reflect"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/takehaya/vinbero/sdk/go/cplane"
)

// Encode serializes an outgoing packet model using the pinned codec. The caller
// supplies the NLRI's family; this does not grant authority to advertise it.
// Route identity and received-path metadata are assigned by the host, not here.
// NLRI and attributes may be borrowed read-only: serializers receive deep copies
// of the pinned packet types, including nested TLVs whose lengths they mutate.
func Encode(family bgp.Family, nlri bgp.NLRI, attrs []bgp.PathAttributeInterface) (out *cplane.BGPPath, err error) {
	defer func() {
		if v := recover(); v != nil {
			out, err = nil, fmt.Errorf("%w: serialize: %v", ErrEncoding, v)
		}
	}()
	if family.Afi() == 0 || family.Safi() == 0 || nilPacket(nlri) {
		return nil, fmt.Errorf("%w: missing family or NLRI", ErrEncoding)
	}
	out = &cplane.BGPPath{Codec: cplane.BGPPathCodec, AFI: family.Afi(), SAFI: family.Safi()}
	owned := copyPacketValue(reflect.ValueOf(nlri)).Interface().(bgp.NLRI)
	out.NLRI, err = owned.Serialize()
	if err != nil {
		return nil, fmt.Errorf("%w: NLRI: %v", ErrEncoding, err)
	}
	for i, attr := range attrs {
		if nilPacket(attr) {
			return nil, fmt.Errorf("%w: attribute %d is nil", ErrEncoding, i)
		}
		owned := copyPacketValue(reflect.ValueOf(attr)).Interface().(bgp.PathAttributeInterface)
		data, err := owned.Serialize()
		if err != nil {
			return nil, fmt.Errorf("%w: attribute %d: %v", ErrEncoding, i, err)
		}
		out.Attributes = append(out.Attributes, data)
	}
	return out, nil
}

func nilPacket(value any) bool {
	return value == nil || (reflect.ValueOf(value).Kind() == reflect.Pointer && reflect.ValueOf(value).IsNil())
}

// Pinned packet models are acyclic and expose mutable children as exported
// fields. Opaque value fields such as netip.Addr have immutable internals.
// This helper is not a general-purpose graph copier for custom packet types.
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
