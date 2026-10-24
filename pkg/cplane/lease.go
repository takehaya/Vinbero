// Package cplane implements the control-plane plugin host. Resource ownership
// and headend reconciliation live in shared host packages.
package cplane

import "github.com/takehaya/vinbero/pkg/ownership"

// Compatibility names for callers of the original plugin-scoped API.
type LeaseKind = ownership.LeaseKind
type LeaseError = ownership.LeaseError
type Leases = ownership.Leases

const (
	LeaseHeadendV4 = ownership.LeaseHeadendV4
	LeaseHeadendV6 = ownership.LeaseHeadendV6
	LeaseAdvertise = ownership.LeaseAdvertise
)

var ErrLeaseHeld = ownership.ErrLeaseHeld

func NewLeases() *Leases { return ownership.NewLeases() }
