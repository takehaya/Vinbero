package locator

import (
	"errors"
	"testing"
)

func TestAllocator_AutoIncremental(t *testing.T) {
	loc := makeClassic48(t)
	a := NewBitmapAllocator(&loc)
	want := []uint32{0x10, 0x11, 0x12}
	for _, w := range want {
		got, err := a.Allocate(nil)
		if err != nil {
			t.Fatalf("Allocate: %v", err)
		}
		if got != w {
			t.Errorf("auto: got %#x want %#x", got, w)
		}
	}
}

func TestAllocator_ManualThenAutoSkips(t *testing.T) {
	loc := makeClassic48(t)
	a := NewBitmapAllocator(&loc)

	manual := uint32(0x20)
	got, err := a.Allocate(&manual)
	if err != nil {
		t.Fatalf("manual: %v", err)
	}
	if got != manual {
		t.Errorf("manual: got %#x want %#x", got, manual)
	}

	// Auto picks the next available value -- not the one we just pinned.
	got, err = a.Allocate(nil)
	if err != nil {
		t.Fatalf("auto: %v", err)
	}
	if got == manual {
		t.Errorf("auto reused manual value %#x", manual)
	}
}

func TestAllocator_ConflictRejected(t *testing.T) {
	loc := makeClassic48(t)
	a := NewBitmapAllocator(&loc)
	v := uint32(0x42)
	if _, err := a.Allocate(&v); err != nil {
		t.Fatalf("first manual: %v", err)
	}
	if _, err := a.Allocate(&v); !errors.Is(err, ErrFunctionInUse) {
		t.Errorf("second manual: got %v, want ErrFunctionInUse", err)
	}
}

func TestAllocator_ReleaseLetsReuse(t *testing.T) {
	loc := makeClassic48(t)
	a := NewBitmapAllocator(&loc)
	v := uint32(0x123)
	if _, err := a.Allocate(&v); err != nil {
		t.Fatalf("alloc: %v", err)
	}
	a.Release(v)
	if a.InUse(v) {
		t.Errorf("InUse after Release")
	}
	got, err := a.Allocate(&v)
	if err != nil || got != v {
		t.Errorf("reuse after release: got %#x err=%v", got, err)
	}
}

func TestAllocator_AutoExhaustion(t *testing.T) {
	loc := makeClassic48(t)
	loc.FunctionAutoStart = 0
	loc.FunctionAutoEnd = 1
	a := NewBitmapAllocator(&loc)
	if _, err := a.Allocate(nil); err != nil {
		t.Fatalf("alloc 1: %v", err)
	}
	if _, err := a.Allocate(nil); err != nil {
		t.Fatalf("alloc 2: %v", err)
	}
	if _, err := a.Allocate(nil); !errors.Is(err, ErrPoolExhausted) {
		t.Errorf("alloc 3: got %v, want ErrPoolExhausted", err)
	}
}

func TestAllocator_ReleaseUnallocatedIsNoOp(t *testing.T) {
	loc := makeClassic48(t)
	a := NewBitmapAllocator(&loc)
	a.Release(0x55) // never allocated; must not panic
	if a.InUse(0x55) {
		t.Errorf("InUse after spurious release")
	}
}

func TestAllocator_ManualOutsideFunctionLenRejected(t *testing.T) {
	loc := makeClassic48(t)
	a := NewBitmapAllocator(&loc)
	tooBig := uint32(0x10000) // function_len=16
	if _, err := a.Allocate(&tooBig); !errors.Is(err, ErrFunctionOutsideAutoRange) {
		t.Errorf("oversize manual: got %v, want ErrFunctionOutsideAutoRange", err)
	}
}

// TestAllocator_SingleSlotExhaustion pins the edge case where the auto
// range has exactly one slot. The word-scan path must succeed once and
// fail the second time without an infinite loop.
func TestAllocator_SingleSlotExhaustion(t *testing.T) {
	loc := makeClassic48(t)
	loc.FunctionAutoStart = 0x80
	loc.FunctionAutoEnd = 0x80
	a := NewBitmapAllocator(&loc)
	got, err := a.Allocate(nil)
	if err != nil {
		t.Fatalf("first alloc: %v", err)
	}
	if got != 0x80 {
		t.Errorf("first alloc: got %#x, want 0x80", got)
	}
	if _, err := a.Allocate(nil); !errors.Is(err, ErrPoolExhausted) {
		t.Errorf("second alloc: got %v, want ErrPoolExhausted", err)
	}
}

// TestAllocator_WordBoundaryWalk verifies the word-scan optimization walks
// across uint64 word boundaries correctly: fill the entire first word,
// then auto-allocate -- the result must land in the next word, not loop
// forever on the busy one.
func TestAllocator_WordBoundaryWalk(t *testing.T) {
	loc := makeClassic48(t)
	loc.FunctionAutoStart = 0
	loc.FunctionAutoEnd = 200
	a := NewBitmapAllocator(&loc)
	// Pre-allocate manually so positions 0..63 are taken.
	for i := range uint32(64) {
		v := i
		if _, err := a.Allocate(&v); err != nil {
			t.Fatalf("pre-alloc %d: %v", i, err)
		}
	}
	got, err := a.Allocate(nil)
	if err != nil {
		t.Fatalf("auto after word fill: %v", err)
	}
	if got != 64 {
		t.Errorf("auto after word fill: got %d, want 64", got)
	}
}
