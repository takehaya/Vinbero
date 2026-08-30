package locator

import (
	"errors"
	"fmt"
	"math/bits"
	"sync"
)

// ErrFunctionInUse is returned when the caller manually requests a
// function value that another binding already holds.
var ErrFunctionInUse = errors.New("locator: function value already in use")

// ErrPoolExhausted is returned when auto-allocation cannot find a free
// slot inside [FunctionAutoStart, FunctionAutoEnd].
var ErrPoolExhausted = errors.New("locator: auto-allocation pool exhausted")

// ErrFunctionOutsideAutoRange is returned when a manual function value
// falls outside the locator's function bit width. Within-range values
// outside [FunctionAutoStart, FunctionAutoEnd] are permitted -- the
// auto-range only bounds auto-allocation.
var ErrFunctionOutsideAutoRange = errors.New("locator: function value outside function_len range")

// FunctionAllocator hands out unique function values for a single
// locator. Implementations must be safe for concurrent use.
type FunctionAllocator interface {
	// Allocate returns a free function. When requested is non-nil the
	// allocator validates that specific value is free and reserves it
	// (manual mode). When requested is nil it auto-picks the lowest
	// free value inside [FunctionAutoStart, FunctionAutoEnd].
	Allocate(requested *uint32) (uint32, error)

	// Release returns function to the free pool. Releasing a value that
	// was never allocated is a silent no-op so callers can use Release
	// to roll back a partial Create without first checking state.
	Release(function uint32)

	// InUse reports whether function is currently allocated.
	InUse(function uint32) bool
}

// compile-time assertion that *bitmapAllocator satisfies the interface.
var _ FunctionAllocator = (*bitmapAllocator)(nil)

// bitmapAllocator is the default FunctionAllocator: an in-memory bitmap
// sized by the locator's FunctionLen (clamped at 32 bits to keep memory
// usage finite -- a 16-bit function fits 8 KiB, a 24-bit function 2 MiB,
// a 32-bit function 512 MiB).
type bitmapAllocator struct {
	mu          sync.Mutex
	bits        []uint64 // bit i set => function i in use
	max         uint32   // inclusive upper bound on storable function
	autoStart   uint32
	autoEnd     uint32
	autoNext    uint32 // hint for the next auto search; rolls forward to avoid scanning from 0 every time
	reserveZero bool   // uSID reserves CSID 0 as the container terminator
}

// NewBitmapAllocator returns an allocator preconfigured for loc. The
// caller must have already passed loc through Locator.Validate (Manager.Add
// does so before reaching here); the constructor itself does not
// re-validate to avoid double-running the same checks on every Add.
func NewBitmapAllocator(loc *Locator) FunctionAllocator {
	max := loc.MaxFunction()
	words := (uint64(max) + 64) / 64 // round up so the highest bit fits
	return &bitmapAllocator{
		bits:        make([]uint64, words),
		max:         max,
		autoStart:   loc.FunctionAutoStart,
		autoEnd:     loc.FunctionAutoEnd,
		autoNext:    loc.FunctionAutoStart,
		reserveZero: loc.Behavior == BehaviorUSID,
	}
}

func (a *bitmapAllocator) Allocate(requested *uint32) (uint32, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if requested != nil {
		f := *requested
		if a.reserveZero && f == 0 {
			return 0, fmt.Errorf("%w: uSID CSID 0 is the container terminator", ErrFunctionReserved)
		}
		if f > a.max {
			return 0, fmt.Errorf("%w: %d > %d", ErrFunctionOutsideAutoRange, f, a.max)
		}
		if a.isSetLocked(f) {
			return 0, fmt.Errorf("%w: function=%d", ErrFunctionInUse, f)
		}
		a.setLocked(f)
		return f, nil
	}
	// Auto: scan [autoNext, autoEnd] then [autoStart, autoNext-1] using
	// bits.TrailingZeros64 to skip 64 slots per word. A near-full pool
	// (FunctionLen=24, 99% occupied) walks ~256K words instead of ~16M
	// bits.
	if cand, ok := a.autoFindLocked(a.autoNext, a.autoEnd); ok {
		a.setLocked(cand)
		a.advanceAutoNextLocked(cand)
		return cand, nil
	}
	if a.autoNext > a.autoStart {
		if cand, ok := a.autoFindLocked(a.autoStart, a.autoNext-1); ok {
			a.setLocked(cand)
			a.advanceAutoNextLocked(cand)
			return cand, nil
		}
	}
	return 0, ErrPoolExhausted
}

// autoFindLocked returns the lowest free function in [from, to] (inclusive),
// or ok=false if every slot in the range is allocated. Word-aligned for
// O(slots/64) on the worst case.
func (a *bitmapAllocator) autoFindLocked(from, to uint32) (uint32, bool) {
	if from > to {
		return 0, false
	}
	fromWord := from / 64
	fromBit := from % 64
	toWord := to / 64
	toBit := to % 64
	for w := fromWord; w <= toWord; w++ {
		free := ^a.bits[w]
		if a.reserveZero && w == 0 {
			free &^= 1
		}
		if w == fromWord && fromBit > 0 {
			free &^= (uint64(1) << fromBit) - 1
		}
		if w == toWord && toBit < 63 {
			free &= (uint64(1) << (toBit + 1)) - 1
		}
		if free == 0 {
			continue
		}
		bitOffset := uint32(bits.TrailingZeros64(free))
		return w*64 + bitOffset, true
	}
	return 0, false
}

func (a *bitmapAllocator) advanceAutoNextLocked(cand uint32) {
	if cand == a.autoEnd {
		a.autoNext = a.autoStart
	} else {
		a.autoNext = cand + 1
	}
}

func (a *bitmapAllocator) Release(function uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if function > a.max {
		return
	}
	if !a.isSetLocked(function) {
		return
	}
	a.clearLocked(function)
	// Drop the auto-hint back to the freshly-freed slot so a subsequent
	// Allocate reuses it rather than walking the bitmap from autoNext.
	if function >= a.autoStart && function <= a.autoEnd && function < a.autoNext {
		a.autoNext = function
	}
}

func (a *bitmapAllocator) InUse(function uint32) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if function > a.max {
		return false
	}
	return a.isSetLocked(function)
}

func (a *bitmapAllocator) isSetLocked(function uint32) bool {
	word := function / 64
	bit := function % 64
	return a.bits[word]&(uint64(1)<<bit) != 0
}

func (a *bitmapAllocator) setLocked(function uint32) {
	word := function / 64
	bit := function % 64
	a.bits[word] |= uint64(1) << bit
}

func (a *bitmapAllocator) clearLocked(function uint32) {
	word := function / 64
	bit := function % 64
	a.bits[word] &^= uint64(1) << bit
}
