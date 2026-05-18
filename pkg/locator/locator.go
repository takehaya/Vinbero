// Package locator implements Vinbero's SRv6 locator manager: a pool of
// IPv6 prefixes from which SID function values are allocated, with a
// function allocator and an in-memory binding table that records which
// SID was built from which (locator, function) pair so a Delete can
// return the function to the pool.
//
// Today Phase 1 implements RFC 8986 Classic SRv6. RFC 9800 uSID
// locators (Behavior == BehaviorUSID) are accepted at the config layer
// but BuildSID / ParseSID return ErrUnimplemented for them; the Phase 2
// extension of the GoBGP integration plan will fill in uSID encoding.
package locator

import (
	"errors"
	"fmt"
	"net/netip"
)

// Behavior selects the SID structure semantics. Classic and USID layouts
// are not interchangeable; each locator carries exactly one.
type Behavior uint8

const (
	BehaviorUnspecified Behavior = 0
	BehaviorClassic     Behavior = 1
	BehaviorUSID        Behavior = 2
)

func (b Behavior) String() string {
	switch b {
	case BehaviorClassic:
		return "classic"
	case BehaviorUSID:
		return "usid"
	default:
		return "unspecified"
	}
}

// Locator captures the per-PE SRv6 locator definition: the prefix it
// owns plus the bit layout used to slice SID values out of the
// remaining 128 - block - node bits.
type Locator struct {
	Name        string
	Prefix      netip.Prefix
	BlockLen    uint8
	NodeLen     uint8
	FunctionLen uint8
	ArgumentLen uint8
	Behavior    Behavior

	// FunctionAutoStart / FunctionAutoEnd bound the auto-allocator's
	// search range, inclusive. Manual allocations may pin any value
	// inside [0, 1<<FunctionLen) regardless of these bounds.
	FunctionAutoStart uint32
	FunctionAutoEnd   uint32
}

var (
	// ErrUnimplemented surfaces from BuildSID / ParseSID when the locator
	// uses a Behavior that the current build does not encode (today: USID).
	ErrUnimplemented = errors.New("locator: behavior not yet implemented")

	// ErrInvalidLocator signals a structural problem with the Locator
	// definition itself (sum of bit lengths != 128, etc.).
	ErrInvalidLocator = errors.New("locator: invalid definition")

	// ErrFunctionOutOfRange signals a function value that does not fit in
	// FunctionLen bits.
	ErrFunctionOutOfRange = errors.New("locator: function value out of range")
)

// maxFunctionLenBits caps how large a function field the bitmap allocator
// will materialize. function_len=24 backs a 2 MiB bitmap; beyond that the
// memory cost crosses into "needs sparse storage" territory and is
// intentionally rejected so an operator-side typo cannot accidentally
// commit hundreds of megabytes.
const maxFunctionLenBits = 24

// Validate checks structural invariants before the locator is registered.
// It does not check uniqueness or runtime conflicts -- the manager handles
// those.
func (l *Locator) Validate() error {
	if l.Name == "" {
		return fmt.Errorf("%w: name must be non-empty", ErrInvalidLocator)
	}
	if !l.Prefix.IsValid() || !l.Prefix.Addr().Is6() {
		return fmt.Errorf("%w: prefix must be a valid IPv6 prefix", ErrInvalidLocator)
	}
	total := uint16(l.BlockLen) + uint16(l.NodeLen) + uint16(l.FunctionLen) + uint16(l.ArgumentLen)
	if total != 128 {
		return fmt.Errorf("%w: bit lengths must sum to 128 (got %d)", ErrInvalidLocator, total)
	}
	if uint16(l.BlockLen)+uint16(l.NodeLen) != uint16(l.Prefix.Bits()) {
		return fmt.Errorf("%w: block_len + node_len (%d) must equal prefix bits (%d)",
			ErrInvalidLocator, l.BlockLen+l.NodeLen, l.Prefix.Bits())
	}
	if l.FunctionLen == 0 {
		return fmt.Errorf("%w: function_len must be > 0", ErrInvalidLocator)
	}
	if l.FunctionLen > maxFunctionLenBits {
		return fmt.Errorf("%w: function_len > %d is not supported (bitmap memory cost)",
			ErrInvalidLocator, maxFunctionLenBits)
	}
	max := uint32((uint64(1) << l.FunctionLen) - 1)
	if l.FunctionAutoStart > max {
		return fmt.Errorf("%w: function_auto_start (%d) exceeds function_len max (%d)",
			ErrInvalidLocator, l.FunctionAutoStart, max)
	}
	if l.FunctionAutoEnd > max {
		return fmt.Errorf("%w: function_auto_end (%d) exceeds function_len max (%d)",
			ErrInvalidLocator, l.FunctionAutoEnd, max)
	}
	if l.FunctionAutoEnd < l.FunctionAutoStart {
		return fmt.Errorf("%w: function_auto_end (%d) < function_auto_start (%d)",
			ErrInvalidLocator, l.FunctionAutoEnd, l.FunctionAutoStart)
	}
	switch l.Behavior {
	case BehaviorClassic, BehaviorUSID:
	default:
		return fmt.Errorf("%w: unsupported behavior %v", ErrInvalidLocator, l.Behavior)
	}
	return nil
}

// MaxFunction returns the largest value representable in FunctionLen bits.
func (l *Locator) MaxFunction() uint32 {
	return uint32((uint64(1) << l.FunctionLen) - 1)
}

// BuildSID returns the 128-bit SRv6 SID for (locator, function). The
// function bits sit immediately after locator-block + locator-node; the
// argument tail is left zero. uSID layout is deferred to Phase 2.
func (l *Locator) BuildSID(function uint32) (netip.Addr, error) {
	if l.Behavior != BehaviorClassic {
		return netip.Addr{}, fmt.Errorf("%w: behavior %v BuildSID", ErrUnimplemented, l.Behavior)
	}
	if function > l.MaxFunction() {
		return netip.Addr{}, fmt.Errorf("%w: function %d exceeds %d", ErrFunctionOutOfRange, function, l.MaxFunction())
	}
	addr := l.Prefix.Masked().Addr().As16()
	prefixBits := uint(l.BlockLen) + uint(l.NodeLen)
	writeBits(addr[:], prefixBits, uint(l.FunctionLen), uint64(function))
	out, ok := netip.AddrFromSlice(addr[:])
	if !ok {
		return netip.Addr{}, fmt.Errorf("locator: BuildSID failed to reconstruct address")
	}
	return out, nil
}

// ParseSID is the inverse of BuildSID for a sid that was minted by this
// locator. ok=false means the SID does not fall inside this locator's
// prefix and the caller should try a different locator. ParseSID does
// not consult the binding table.
func (l *Locator) ParseSID(sid netip.Addr) (function uint32, ok bool, err error) {
	if l.Behavior != BehaviorClassic {
		return 0, false, fmt.Errorf("%w: behavior %v ParseSID", ErrUnimplemented, l.Behavior)
	}
	if !sid.Is6() {
		return 0, false, nil
	}
	if !l.Prefix.Contains(sid) {
		return 0, false, nil
	}
	b16 := sid.As16()
	prefixBits := uint(l.BlockLen) + uint(l.NodeLen)
	v := readBits(b16[:], prefixBits, uint(l.FunctionLen))
	return uint32(v), true, nil
}

// writeBits stores value into buf starting at bit offset start, spanning
// width bits. Bits are written MSB-first to match IPv6's natural order.
func writeBits(buf []byte, start, width uint, value uint64) {
	for i := range width {
		bitVal := (value >> (width - 1 - i)) & 0x1
		bitIdx := start + i
		byteIdx := bitIdx / 8
		offset := 7 - bitIdx%8
		// Clear the target bit before setting, so partially-overwriting
		// a non-zero prefix slot does not OR stale data into the result.
		buf[byteIdx] &^= 1 << offset
		buf[byteIdx] |= byte(bitVal) << offset
	}
}

// readBits returns the width bits starting at bit offset start of buf,
// MSB-first.
func readBits(buf []byte, start, width uint) uint64 {
	var out uint64
	for i := range width {
		bitIdx := start + i
		byteIdx := bitIdx / 8
		offset := 7 - bitIdx%8
		bit := (buf[byteIdx] >> offset) & 0x1
		out = (out << 1) | uint64(bit)
	}
	return out
}
