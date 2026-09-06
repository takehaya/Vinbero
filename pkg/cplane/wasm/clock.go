package wasm

import (
	"errors"
	"time"
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

// denier is implemented by an error that means "policy said no" rather
// than "the host failed".
//
// The distinction is tested through an interface rather than against a
// specific error value so this package stays free of the capability layer
// it serves: the runtime moves bytes and enforces budgets, and knowing
// which package defines lease conflicts is not its business.
type denier interface {
	Denied() bool
}

// isDenied reports whether an error is a policy refusal the guest can act
// on -- a key another owner holds, say -- rather than a host-side failure
// it can do nothing about.
func isDenied(err error) bool {
	var d denier
	return errors.As(err, &d) && d.Denied()
}
