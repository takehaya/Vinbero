package locator

import (
	"errors"
	"testing"
)

func TestAllocator_AutoIncremental(t *testing.T) {
	loc := makeClassic48(t)
	a, err := NewBitmapAllocator(&loc)
	if err != nil {
		t.Fatalf("NewBitmapAllocator: %v", err)
	}
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
	a, _ := NewBitmapAllocator(&loc)

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
	a, _ := NewBitmapAllocator(&loc)
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
	a, _ := NewBitmapAllocator(&loc)
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
	a, _ := NewBitmapAllocator(&loc)
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
	a, _ := NewBitmapAllocator(&loc)
	a.Release(0x55) // never allocated; must not panic
	if a.InUse(0x55) {
		t.Errorf("InUse after spurious release")
	}
}

func TestAllocator_ManualOutsideFunctionLenRejected(t *testing.T) {
	loc := makeClassic48(t)
	a, _ := NewBitmapAllocator(&loc)
	tooBig := uint32(0x10000) // function_len=16
	if _, err := a.Allocate(&tooBig); !errors.Is(err, ErrFunctionOutsideAutoRange) {
		t.Errorf("oversize manual: got %v, want ErrFunctionOutsideAutoRange", err)
	}
}
