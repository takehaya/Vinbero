package wasm

import (
	"errors"
	"time"

	"github.com/takehaya/vinbero/pkg/cplane"
)

// monotonicSince is the nanoseconds elapsed since an instance started.
//
// time.Since is monotonic on every platform Go supports (it reads the
// wall clock's monotonic companion), so the value never goes backwards
// across an NTP step. The epoch is per instance and deliberately
// unspecified: a plugin may only compare two readings.
func monotonicSince(started time.Time) int64 {
	return int64(time.Since(started))
}

// isDenied reports whether an error is a policy refusal the guest can act
// on -- today, a key another owner holds -- rather than a host-side
// failure it can do nothing about.
func isDenied(err error) bool {
	return errors.Is(err, cplane.ErrLeaseHeld)
}
