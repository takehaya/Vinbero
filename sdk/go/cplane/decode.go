package cplane

import "github.com/takehaya/vinbero/sdk/go/cplane/wire"

func decodeMessage(data []byte, field func(*wire.Decoder) bool) error {
	d := wire.NewDecoder(data)
	for d.Next() {
		if !field(d) {
			return wire.ErrMalformed
		}
	}
	return d.Err()
}

// DecodeEvents copies all retained data out of the borrowed host buffer. A
// malformed batch returns no events, so callers never act on a truncated replay.
func DecodeEvents(data []byte) ([]Event, error) {
	var events []Event
	err := decodeMessage(data, func(d *wire.Decoder) bool {
		if d.Field != 1 {
			return true
		}
		if d.Type != wire.Bytes {
			return false
		}
		ev, err := decodeEvent(d.Bytes)
		if err != nil {
			return false
		}
		events = append(events, ev)
		return true
	})
	if err != nil {
		return nil, err
	}
	return events, nil
}

// EncodeResults encodes the optional per-event disposition returned to the host.
func EncodeResults(results []EventResult) []byte {
	var out wire.Encoder
	for _, result := range results {
		var r wire.Encoder
		r.Uint(1, result.Sequence)
		r.Uint(2, uint64(result.Disposition))
		r.String(3, result.Reason)
		out.Message(1, r)
	}
	return out
}

func decodeEvent(data []byte) (Event, error) {
	var out Event
	err := decodeMessage(data, func(d *wire.Decoder) bool {
		switch d.Field {
		case 1:
			if d.Type != wire.Varint {
				return false
			}
			if d.Uint > 1<<32-1 {
				return false
			}
			out.Kind = EventKind(d.Uint)
		case 2:
			if d.Type != wire.Varint {
				return false
			}
			out.Sequence = d.Uint
		case 3:
			if d.Type != wire.Bytes {
				return false
			}
			v, err := decodeRoute(d.Bytes)
			if err != nil {
				return false
			}
			out.Route = v
		case 4:
			if d.Type != wire.Bytes {
				return false
			}
			v, err := decodeMACEvent(d.Bytes)
			if err != nil {
				return false
			}
			out.MAC = v
		case 5:
			if d.Type != wire.Bytes {
				return false
			}
			out.ReplaySource = string(d.Bytes)
		case 7:
			if d.Type != wire.Bytes {
				return false
			}
			v, err := decodeLocalSIDAllocated(d.Bytes)
			if err != nil {
				return false
			}
			out.LocalSID = v
		}
		return true
	})
	return out, err
}

func decodeRoute(data []byte) (Route, error) {
	var out Route
	err := decodeMessage(data, func(d *wire.Decoder) bool {
		switch d.Field {
		case 1:
			if d.Type != wire.Bytes {
				return false
			}
			out.Family = string(d.Bytes)
		case 2:
			if d.Type != wire.Varint {
				return false
			}
			out.Withdraw = d.Uint != 0
		case 3:
			if d.Type != wire.Bytes {
				return false
			}
			out.Peer = string(d.Bytes)
		case 4:
			if d.Type != wire.Varint {
				return false
			}
			if d.Uint > 1<<32-1 {
				return false
			}
			out.PathID = uint32(d.Uint)
		case 5:
			if d.Type != wire.Varint {
				return false
			}
			if d.Uint > 1<<32-1 {
				return false
			}
			out.EndpointBehavior = uint32(d.Uint)
		case 6:
			if d.Type != wire.Bytes {
				return false
			}
			out.RD = string(d.Bytes)
		case 7:
			if d.Type != wire.Bytes {
				return false
			}
			out.Prefix = string(d.Bytes)
		case 8:
			if d.Type != wire.Bytes {
				return false
			}
			out.SRv6SID = string(d.Bytes)
		case 9:
			if d.Type != wire.Bytes {
				return false
			}
			out.NextHop = string(d.Bytes)
		case 10:
			if d.Type != wire.Bytes {
				return false
			}
			out.RouteTargets = append(out.RouteTargets, string(d.Bytes))
		case 11:
			if d.Type != wire.Varint {
				return false
			}
			if d.Uint > 1<<32-1 {
				return false
			}
			out.Color = uint32(d.Uint)
		case 12:
			if d.Type != wire.Bytes {
				return false
			}
			out.MAC = string(d.Bytes)
		case 13:
			if d.Type != wire.Bytes {
				return false
			}
			out.IPAddr = string(d.Bytes)
		case 14:
			if d.Type != wire.Varint {
				return false
			}
			if d.Uint > 1<<32-1 {
				return false
			}
			out.EthernetTag = uint32(d.Uint)
		case 15:
			if d.Type != wire.Bytes {
				return false
			}
			out.ESI = append([]byte(nil), d.Bytes...)
		case 16:
			if d.Type != wire.Bytes {
				return false
			}
			v, err := decodeUnknownAttribute(d.Bytes)
			if err != nil {
				return false
			}
			out.UnknownAttributes = append(out.UnknownAttributes, v)
		}
		return true
	})
	return out, err
}

func decodeMACEvent(data []byte) (MACEvent, error) {
	var out MACEvent
	err := decodeMessage(data, func(d *wire.Decoder) bool {
		switch d.Field {
		case 1:
			if d.Type != wire.Varint {
				return false
			}
			if d.Uint > 1<<32-1 {
				return false
			}
			out.BDID = uint32(d.Uint)
		case 2:
			if d.Type != wire.Bytes {
				return false
			}
			out.MAC = string(d.Bytes)
		case 3:
			if d.Type != wire.Varint {
				return false
			}
			out.Added = d.Uint != 0
		}
		return true
	})
	return out, err
}

func decodeLocalSIDAllocated(data []byte) (LocalSIDAllocated, error) {
	var out LocalSIDAllocated
	err := decodeMessage(data, func(d *wire.Decoder) bool {
		switch d.Field {
		case 1:
			if d.Type != wire.Bytes {
				return false
			}
			out.Name = string(d.Bytes)
		case 2:
			if d.Type != wire.Bytes {
				return false
			}
			out.SID = string(d.Bytes)
		case 3:
			if d.Type != wire.Bytes {
				return false
			}
			out.Locator = string(d.Bytes)
		}
		return true
	})
	return out, err
}

func decodeUnknownAttribute(data []byte) (UnknownAttribute, error) {
	var out UnknownAttribute
	err := decodeMessage(data, func(d *wire.Decoder) bool {
		switch d.Field {
		case 1:
			if d.Type != wire.Varint {
				return false
			}
			if d.Uint > 1<<32-1 {
				return false
			}
			out.Type = uint32(d.Uint)
		case 2:
			if d.Type != wire.Varint {
				return false
			}
			if d.Uint > 1<<32-1 {
				return false
			}
			out.Flags = uint32(d.Uint)
		case 3:
			if d.Type != wire.Bytes {
				return false
			}
			out.Value = append([]byte(nil), d.Bytes...)
		}
		return true
	})
	return out, err
}
