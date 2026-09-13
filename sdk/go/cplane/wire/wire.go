// Package wire provides the protobuf wire operations used by Go WASM plugins.
// It needs no reflection. Varint, bytes, fixed32 and fixed64 fields are accepted;
// deprecated protobuf groups are not supported. Decoder.Bytes borrows its input.
package wire

import "errors"

const (
	Varint  = 0
	Fixed64 = 1
	Bytes   = 2
	Fixed32 = 5
)

var ErrMalformed = errors.New("malformed protobuf message")

// Decoder walks fields, including unknown fields, without interpreting a schema.
// Read Field, Type, Uint and Bytes after Next succeeds, then check Err at the end.
type Decoder struct {
	Field int
	Type  int
	Uint  uint64
	Bytes []byte
	data  []byte
	pos   int
	err   error
}

func NewDecoder(data []byte) *Decoder { return &Decoder{data: data} }
func (d *Decoder) Err() error         { return d.err }

func (d *Decoder) varint() (uint64, bool) {
	var v uint64
	for shift := uint(0); shift < 64 && d.pos < len(d.data); shift += 7 {
		b := d.data[d.pos]
		d.pos++
		if shift == 63 && b > 1 {
			return 0, false
		}
		v |= uint64(b&0x7f) << shift
		if b < 0x80 {
			return v, true
		}
	}
	return 0, false
}

func (d *Decoder) Next() bool {
	if d.err != nil || d.pos == len(d.data) {
		return false
	}
	tag, ok := d.varint()
	if !ok || tag>>3 == 0 || tag>>3 > (1<<29)-1 {
		d.err = ErrMalformed
		return false
	}
	d.Field, d.Type = int(tag>>3), int(tag&7)
	d.Uint, d.Bytes = 0, nil
	var n uint64
	switch d.Type {
	case Varint:
		d.Uint, ok = d.varint()
		if !ok {
			d.err = ErrMalformed
		}
		return ok
	case Bytes:
		n, ok = d.varint()
	case Fixed32:
		n = 4
	case Fixed64:
		n = 8
	default:
		ok = false
	}
	if !ok || n > uint64(len(d.data)-d.pos) {
		d.err = ErrMalformed
		return false
	}
	d.Bytes = d.data[d.pos : d.pos+int(n)]
	d.pos += int(n)
	return true
}

// Encoder appends protobuf fields. Uint, String and Bytes omit zero values;
// Message writes even an empty embedded message.
type Encoder []byte

func (e *Encoder) varint(v uint64) {
	for v >= 0x80 {
		*e = append(*e, byte(v)|0x80)
		v >>= 7
	}
	*e = append(*e, byte(v))
}
func (e *Encoder) Uint(field int, value uint64) {
	if value == 0 {
		return
	}
	e.varint(uint64(field) << 3)
	e.varint(value)
}
func (e *Encoder) String(field int, value string) {
	if value == "" {
		return
	}
	e.varint(uint64(field)<<3 | Bytes)
	e.varint(uint64(len(value)))
	*e = append(*e, value...)
}
func (e *Encoder) Bytes(field int, value []byte) {
	if len(value) > 0 {
		e.Message(field, value)
	}
}
func (e *Encoder) Message(field int, value []byte) {
	e.varint(uint64(field)<<3 | Bytes)
	e.varint(uint64(len(value)))
	*e = append(*e, value...)
}
