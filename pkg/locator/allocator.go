package locator

import (
	"errors"
	"fmt"
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

// bitmapAllocator is the default FunctionAllocator: an in-memory bitmap
// sized by the locator's FunctionLen (clamped at 32 bits to keep memory
// usage finite -- a 16-bit function fits 8 KiB, a 24-bit function 2 MiB,
// a 32-bit function 512 MiB).
type bitmapAllocator struct {
	mu        sync.Mutex
	bits      []uint64 // bit i set => function i in use
	max       uint32   // inclusive upper bound on storable function
	autoStart uint32
	autoEnd   uint32
	autoNext  uint32 // hint for the next auto search; rolls forward to avoid scanning from 0 every time
}

// NewBitmapAllocator returns an allocator preconfigured for loc.
func NewBitmapAllocator(loc *Locator) (FunctionAllocator, error) {
	if err := loc.Validate(); err != nil {
		return nil, err
	}
	max := loc.MaxFunction()
	words := (uint64(max) + 64) / 64 // round up so the highest bit fits
	return &bitmapAllocator{
		bits:      make([]uint64, words),
		max:       max,
		autoStart: loc.FunctionAutoStart,
		autoEnd:   loc.FunctionAutoEnd,
		autoNext:  loc.FunctionAutoStart,
	}, nil
}

func (a *bitmapAllocator) Allocate(requested *uint32) (uint32, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if requested != nil {
		f := *requested
		if f > a.max {
			return 0, fmt.Errorf("%w: %d > %d", ErrFunctionOutsideAutoRange, f, a.max)
		}
		if a.isSetLocked(f) {
			return 0, fmt.Errorf("%w: function=%d", ErrFunctionInUse, f)
		}
		a.setLocked(f)
		return f, nil
	}
	// Auto: linear probe forward from autoNext, wrapping once.
	start := a.autoNext
	for offset := uint64(0); offset <= uint64(a.autoEnd-a.autoStart); offset++ {
		cand := a.autoStart + uint32((uint64(start-a.autoStart)+offset)%(uint64(a.autoEnd-a.autoStart)+1))
		if !a.isSetLocked(cand) {
			a.setLocked(cand)
			// Advance the hint so the next auto-alloc does not retry this slot.
			if cand == a.autoEnd {
				a.autoNext = a.autoStart
			} else {
				a.autoNext = cand + 1
			}
			return cand, nil
		}
	}
	return 0, ErrPoolExhausted
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
