package main

// A minimal protobuf codec for the messages this plugin exchanges with
// the host.
//
// The generated Go bindings are not usable here: they need reflection,
// which TinyGo's WebAssembly targets do not support. What crosses the
// boundary is small and fixed, so encoding it by hand is a few hundred
// bytes of code rather than a dependency that will not build.
//
// Only the wire types these messages use are implemented: varint for
// numbers and length-delimited for strings, bytes, and nested messages.

// wire types, from the protobuf encoding spec.
const (
	wireVarint = 0
	wireBytes  = 2
)

// reader walks a protobuf message.
type reader struct {
	buf []byte
	pos int
}

// eof reports whether the whole message has been consumed.
func (r *reader) eof() bool { return r.pos >= len(r.buf) }

// varint reads a base-128 varint. ok is false on a truncated or
// unreasonably long encoding, which is how a malformed message from the
// host is refused rather than looped over.
func (r *reader) varint() (uint64, bool) {
	var v uint64
	var shift uint
	for {
		if r.pos >= len(r.buf) || shift > 63 {
			return 0, false
		}
		b := r.buf[r.pos]
		r.pos++
		v |= uint64(b&0x7f) << shift
		if b < 0x80 {
			return v, true
		}
		shift += 7
	}
}

// tag reads a field number and its wire type.
func (r *reader) tag() (field int, wire int, ok bool) {
	v, ok := r.varint()
	if !ok {
		return 0, 0, false
	}
	return int(v >> 3), int(v & 0x7), true
}

// bytes reads a length-delimited field.
func (r *reader) bytes() ([]byte, bool) {
	n, ok := r.varint()
	if !ok || r.pos+int(n) > len(r.buf) {
		return nil, false
	}
	out := r.buf[r.pos : r.pos+int(n)]
	r.pos += int(n)
	return out, true
}

// skip advances past a field the plugin does not care about. A message
// with fields this plugin does not know is normal: the host may be newer.
func (r *reader) skip(wire int) bool {
	switch wire {
	case wireVarint:
		_, ok := r.varint()
		return ok
	case wireBytes:
		_, ok := r.bytes()
		return ok
	case 5: // fixed32
		if r.pos+4 > len(r.buf) {
			return false
		}
		r.pos += 4
		return true
	case 1: // fixed64
		if r.pos+8 > len(r.buf) {
			return false
		}
		r.pos += 8
		return true
	default:
		return false
	}
}

// writer builds a protobuf message.
type writer struct {
	buf []byte
}

// putVarint appends a base-128 varint.
func (w *writer) putVarint(v uint64) {
	for v >= 0x80 {
		w.buf = append(w.buf, byte(v)|0x80)
		v >>= 7
	}
	w.buf = append(w.buf, byte(v))
}

// putTag appends a field number and wire type.
func (w *writer) putTag(field, wire int) {
	w.putVarint(uint64(field)<<3 | uint64(wire))
}

// putString appends a length-delimited string field.
func (w *writer) putString(field int, s string) {
	w.putTag(field, wireBytes)
	w.putVarint(uint64(len(s)))
	w.buf = append(w.buf, s...)
}

// putMessage appends a nested message field.
func (w *writer) putMessage(field int, body []byte) {
	w.putTag(field, wireBytes)
	w.putVarint(uint64(len(body)))
	w.buf = append(w.buf, body...)
}
