package cplane

import "github.com/takehaya/vinbero/sdk/go/cplane/wire"

func decodeBGPPath(data []byte) (*BGPPath, error) {
	out := &BGPPath{}
	err := decodeMessage(data, func(d *wire.Decoder) bool {
		switch d.Field {
		case 1, 4, 5, 6, 7, 8:
			if d.Type != wire.Bytes {
				return false
			}
			switch d.Field {
			case 1:
				out.Codec = string(d.Bytes)
			case 4:
				out.NLRI = append([]byte(nil), d.Bytes...)
			case 5:
				out.Attributes = append(out.Attributes, append([]byte(nil), d.Bytes...))
			case 6:
				out.EncodingError = string(d.Bytes)
			case 8:
				out.RouteKey = append([]byte(nil), d.Bytes...)
			case 7:
				v, err := decodeBGPMetadata(d.Bytes)
				if err != nil {
					return false
				}
				out.Metadata = v
			}
		case 2:
			if d.Type != wire.Varint || d.Uint > 1<<16-1 {
				return false
			}
			out.AFI = uint16(d.Uint)
		case 3:
			if d.Type != wire.Varint || d.Uint > 1<<8-1 {
				return false
			}
			out.SAFI = uint8(d.Uint)
		}
		return true
	})
	return out, err
}

func decodeBGPMetadata(data []byte) (BGPPathMetadata, error) {
	var out BGPPathMetadata
	err := decodeMessage(data, func(d *wire.Decoder) bool {
		if d.Field == 3 {
			if d.Type != wire.Bytes {
				return false
			}
			out.PeerRouterID = string(d.Bytes)
			return true
		}
		switch d.Field {
		case 1, 2, 4, 5, 6, 7, 8, 9:
			if d.Type != wire.Varint {
				return false
			}
		default:
			return true
		}
		switch d.Field {
		case 1:
			out.Age = int64(d.Uint)
		case 2:
			if d.Uint > 1<<32-1 {
				return false
			}
			out.PeerASN = uint32(d.Uint)
		case 4:
			out.Stale = d.Uint != 0
		case 5:
			out.IsFromExternal = d.Uint != 0
		case 6:
			out.NoImplicitWithdraw = d.Uint != 0
		case 7:
			out.IsNexthopInvalid = d.Uint != 0
		case 8:
			if d.Uint > 1<<32-1 {
				return false
			}
			out.LocalPathID = uint32(d.Uint)
		case 9:
			best := d.Uint != 0
			out.Best = &best
		}
		return true
	})
	return out, err
}
