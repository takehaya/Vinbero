package locator

import (
	"errors"
	"sync"
	"testing"
)

func TestSIDReservationsPrecedeLocatorRegistration(t *testing.T) {
	loc := makeClassic48(t)
	r := SIDReservation{Key: "plugin/name", Locator: loc, Function: loc.FunctionAutoStart}
	m := NewManager()
	if err := m.RestoreSIDReservations([]SIDReservation{r}); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Get(loc.Name); ok {
		t.Fatal("reservation created a locator")
	}
	if err := m.Delete(loc.Name, false); !errors.Is(err, ErrLocatorNotFound) {
		t.Fatalf("pending locator delete: %v", err)
	}
	if _, _, err := m.AllocateReservedSID(r.Key, loc.Name); !errors.Is(err, ErrLocatorNotFound) {
		t.Fatalf("pending reservation: %v", err)
	}
	alias := loc
	alias.Name = "alias"
	if err := m.Add(&alias); !errors.Is(err, ErrLocatorPrefixInUse) {
		t.Fatalf("alias stole pending prefix: %v", err)
	}
	changed := loc
	changed.BlockLen--
	changed.NodeLen++
	if err := m.Add(&changed); err == nil {
		t.Fatal("accepted changed SID structure")
	}
	// Allocation-range changes do not change the address format.
	loc.FunctionAutoStart++
	if err := m.Add(&loc); err != nil {
		t.Fatal(err)
	}
	sid, _, err := m.AllocateReservedSID(r.Key, loc.Name)
	if err != nil {
		t.Fatal(err)
	}
	m.ReleaseSID(sid)
	if _, _, err := m.AllocateSID(loc.Name, &r.Function); !errors.Is(err, ErrFunctionInUse) {
		t.Fatalf("ordinary release dropped reservation: %v", err)
	}
	if err := m.Delete(loc.Name, false); !errors.Is(err, ErrLocatorInUse) {
		t.Fatalf("delete reserved locator: %v", err)
	}
	// Forced rollback removes the live locator, retaining its pending holds.
	if err := m.Delete(loc.Name, true); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.BindingOf(sid); !ok {
		t.Fatal("forced deletion forgot durable reservation")
	}
	if err := m.Add(&loc); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.AllocateSID(loc.Name, &r.Function); !errors.Is(err, ErrFunctionInUse) {
		t.Fatalf("re-add lost reservation: %v", err)
	}
	m.ReleaseReservedSID(r.Key)
	if _, _, err := m.AllocateSID(loc.Name, &r.Function); err != nil {
		t.Fatalf("explicit release did not return function: %v", err)
	}
}

func TestSIDReservationBatchRollsBackOnlyNewReservations(t *testing.T) {
	for _, registered := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "registered"}[registered], func(t *testing.T) {
			loc := makeClassic48(t)
			m := NewManager()
			if registered {
				if err := m.Add(&loc); err != nil {
					t.Fatal(err)
				}
			}
			a := SIDReservation{Key: "a", Locator: loc, Function: loc.FunctionAutoStart}
			b := a
			b.Key = "b"
			b.Function++
			bad := a
			bad.Key = "collision"
			if err := m.RestoreSIDReservations([]SIDReservation{a}); err != nil {
				t.Fatal(err)
			}
			if err := m.RestoreSIDReservations([]SIDReservation{a, b, bad}); err == nil {
				t.Fatal("accepted duplicate address")
			}
			if !registered {
				if err := m.Add(&loc); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := m.AllocateSID(loc.Name, &a.Function); !errors.Is(err, ErrFunctionInUse) {
				t.Fatalf("rollback dropped existing reservation: %v", err)
			}
			if _, _, err := m.AllocateSID(loc.Name, &b.Function); err != nil {
				t.Fatalf("rollback leaked new reservation: %v", err)
			}
		})
	}
}

func TestSIDReservationsShareAllocationLock(t *testing.T) {
	m := NewManager()
	loc := makeClassic48(t)
	if err := m.Add(&loc); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				if i%2 == 0 {
					sid, _, err := m.AllocateSID(loc.Name, nil)
					if err != nil {
						t.Error(err)
						return
					}
					m.ReleaseSID(sid)
				} else {
					// Each goroutine holds a distinct caller identity.
					key := string(rune('a' + i))
					sid, _, err := m.AllocateReservedSID(key, loc.Name)
					if err != nil {
						t.Error(err)
						return
					}
					m.ReleaseSID(sid)
					if _, ok := m.BindingOf(sid); !ok {
						t.Error("reservation disappeared")
					}
					m.ReleaseReservedSID(key)
				}
			}
		}()
	}
	wg.Wait()
	if got := m.bindings.ListByLocator(loc.Name); len(got) != 0 {
		t.Fatalf("leaked bindings: %v", got)
	}
}
