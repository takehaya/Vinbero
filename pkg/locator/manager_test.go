package locator

import (
	"errors"
	"net/netip"
	"testing"
)

func TestManager_AddListGet(t *testing.T) {
	m := NewManager()
	loc := makeClassic48(t)
	if err := m.Add(&loc); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, ok := m.Get("LOC1")
	if !ok {
		t.Fatalf("Get missing")
	}
	if got.Name != "LOC1" || got.Prefix.String() != "fd00:1:1::/48" {
		t.Errorf("Get returned %+v", got)
	}
	if all := m.List(); len(all) != 1 {
		t.Errorf("List returned %d, want 1", len(all))
	}
}

func TestManager_AddDuplicateRejected(t *testing.T) {
	m := NewManager()
	loc := makeClassic48(t)
	if err := m.Add(&loc); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	if err := m.Add(&loc); !errors.Is(err, ErrLocatorExists) {
		t.Errorf("duplicate Add: got %v, want ErrLocatorExists", err)
	}
}

// FindByContaining must resolve nested locator prefixes by longest match in
// either registration order, not by map iteration order: a SID under the
// /64 belongs to the /64's layout even though the /48 also contains it.
func TestManager_FindByContaining_LongestMatch(t *testing.T) {
	wide := makeClassic48(t) // LOC1 fd00:1:1::/48
	narrow := Locator{
		Name: "LOC2", Prefix: netip.MustParsePrefix("fd00:1:1:1::/64"),
		BlockLen: 48, NodeLen: 16, FunctionLen: 16, ArgumentLen: 48,
		Behavior:          BehaviorClassic,
		FunctionAutoStart: 0x10, FunctionAutoEnd: 0xFFFE,
	}
	sid := netip.MustParseAddr("fd00:1:1:1::100")
	for _, order := range [][]Locator{{wide, narrow}, {narrow, wide}} {
		m := NewManager()
		for i := range order {
			if err := m.Add(&order[i]); err != nil {
				t.Fatalf("Add(%s): %v", order[i].Name, err)
			}
		}
		got, ok := m.FindByContaining(sid)
		if !ok || got.Name != "LOC2" {
			t.Errorf("FindByContaining(%s) = (%+v, %v), want the /64 LOC2", sid, got, ok)
		}
	}
	m := NewManager()
	if err := m.Add(&wide); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, ok := m.FindByContaining(netip.MustParseAddr("fd00:2::1")); ok {
		t.Error("FindByContaining outside every locator must be ok=false")
	}
}

func TestManager_DeleteUnknown(t *testing.T) {
	m := NewManager()
	if err := m.Delete("nope", false); !errors.Is(err, ErrLocatorNotFound) {
		t.Errorf("delete unknown: got %v, want ErrLocatorNotFound", err)
	}
}

func TestManager_AllocReleaseRoundTrip(t *testing.T) {
	m := NewManager()
	loc := makeClassic48(t)
	if err := m.Add(&loc); err != nil {
		t.Fatalf("Add: %v", err)
	}
	sid, binding, err := m.AllocateSID("LOC1", nil)
	if err != nil {
		t.Fatalf("AllocateSID: %v", err)
	}
	if !sid.IsValid() || !sid.Is6() {
		t.Errorf("AllocateSID returned invalid sid %s", sid)
	}
	if binding.LocatorName != "LOC1" {
		t.Errorf("binding name = %q, want LOC1", binding.LocatorName)
	}
	if got, ok := m.BindingOf(sid); !ok || got != binding {
		t.Errorf("BindingOf: ok=%v got=%+v want %+v", ok, got, binding)
	}

	m.ReleaseSID(sid)
	if _, ok := m.BindingOf(sid); ok {
		t.Errorf("BindingOf after Release: still present")
	}
}

func TestManager_DeleteRejectsInUseUnlessForce(t *testing.T) {
	m := NewManager()
	loc := makeClassic48(t)
	if err := m.Add(&loc); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, _, err := m.AllocateSID("LOC1", nil); err != nil {
		t.Fatalf("alloc: %v", err)
	}
	if err := m.Delete("LOC1", false); !errors.Is(err, ErrLocatorInUse) {
		t.Errorf("Delete in-use: got %v, want ErrLocatorInUse", err)
	}
	if err := m.Delete("LOC1", true); err != nil {
		t.Errorf("force Delete: %v", err)
	}
}

func TestManager_ManualFunction(t *testing.T) {
	m := NewManager()
	loc := makeClassic48(t)
	if err := m.Add(&loc); err != nil {
		t.Fatalf("Add: %v", err)
	}
	want := uint32(0x42)
	sid, binding, err := m.AllocateSID("LOC1", &want)
	if err != nil {
		t.Fatalf("AllocateSID manual: %v", err)
	}
	if binding.Function != want {
		t.Errorf("manual: got function=%#x want %#x", binding.Function, want)
	}
	expectedSID := netip.MustParseAddr("fd00:1:1:42::")
	if sid != expectedSID {
		t.Errorf("manual sid: got %s, want %s", sid, expectedSID)
	}
}

func TestManager_ReleaseUnknownIsNoOp(t *testing.T) {
	m := NewManager()
	m.ReleaseSID(netip.MustParseAddr("fd00:dead::1")) // must not panic
}

// TestManager_DuplicatePrefixRejected pins the contract that two
// locators cannot share a prefix even under different names -- the
// resulting SID byte representations would collide.
func TestManager_DuplicatePrefixRejected(t *testing.T) {
	m := NewManager()
	loc := makeClassic48(t)
	if err := m.Add(&loc); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	dup := loc
	dup.Name = "LOC2"
	if err := m.Add(&dup); !errors.Is(err, ErrLocatorPrefixInUse) {
		t.Errorf("duplicate prefix: got %v, want ErrLocatorPrefixInUse", err)
	}
}

// TestValidate_FunctionLenAboveCap pins the bitmap memory cap: function_len
// values that would back a >2 MiB bitmap are rejected so an operator typo
// cannot silently commit hundreds of megabytes.
func TestValidate_FunctionLenAboveCap(t *testing.T) {
	loc := makeClassic48(t)
	loc.FunctionLen = maxFunctionLenBits + 1
	loc.ArgumentLen = uint8(128 - uint16(loc.BlockLen) - uint16(loc.NodeLen) - uint16(loc.FunctionLen))
	if err := loc.Validate(); !errors.Is(err, ErrInvalidLocator) {
		t.Errorf("function_len above cap: got %v, want ErrInvalidLocator", err)
	}
}

// TestValidate_AutoStartAboveMax catches a typo where function_auto_start
// exceeds the function_len max. Previously this was only caught when
// function_auto_end < function_auto_start, which depended on what
// function_auto_end happened to be.
func TestValidate_AutoStartAboveMax(t *testing.T) {
	loc := makeClassic48(t)
	loc.FunctionAutoStart = 0xFFFF + 1
	loc.FunctionAutoEnd = 0xFFFF + 1
	if err := loc.Validate(); !errors.Is(err, ErrInvalidLocator) {
		t.Errorf("auto_start above max: got %v, want ErrInvalidLocator", err)
	}
}

// TestBindingTable_RecordRejectsDuplicate guards against a double-Record
// silently overwriting the original binding: if it did, ReleaseSID would
// later return the function to whichever allocator the second Record
// pointed at, possibly the wrong one.
func TestBindingTable_RecordRejectsDuplicate(t *testing.T) {
	bt := NewBindingTable()
	sid := netip.MustParseAddr("fd00:1:1::1")
	if err := bt.Record(sid, Binding{LocatorName: "LOC1", Function: 1}); err != nil {
		t.Fatalf("first Record: %v", err)
	}
	if err := bt.Record(sid, Binding{LocatorName: "LOC2", Function: 2}); !errors.Is(err, ErrBindingExists) {
		t.Errorf("duplicate Record: got %v, want ErrBindingExists", err)
	}
	// Original binding must remain intact.
	got, ok := bt.Lookup(sid)
	if !ok || got.LocatorName != "LOC1" || got.Function != 1 {
		t.Errorf("Lookup after rejected duplicate: got %+v, want LOC1/1", got)
	}
}
