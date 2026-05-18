// Package bgp is Vinbero's BGP control-plane integration. It defines a
// BGPd-agnostic interface surface so the daemon can embed GoBGP today
// (pkg/bgp/gobgp) and, if needed later, swap in an out-of-process BGP
// speaker without touching the call sites.
//
// The surface is split into four roles per the GoBGP integration plan
// (docs/plan/gobgp-integration.md §2.2):
//
//   - Session            -- peer / global lifecycle, no data path
//   - RouteAdvertiser    -- push local state out as BGP routes
//   - RouteSubscriber    -- receive BGP routes into Vinbero
//   - SRPolicyController -- SR Policy specific receive / advertise
//
// Phase 1c implements Session only (peer establishment). The other
// three interfaces are defined here so Phase 1d / 1e can fill them in
// without reshaping the package.
package bgp

import (
	"context"
	"errors"
	"fmt"
)

// Session lifecycle errors. Exposed as sentinels so callers can branch
// with errors.Is rather than string-matching.
var (
	ErrSessionNotStarted     = errors.New("bgp: session not started")
	ErrSessionAlreadyStarted = errors.New("bgp: session already started")
)

// Family identifies an AFI/SAFI pair in operator-friendly form. The
// gobgp adapter maps these to api.Family values.
type Family string

const (
	FamilyVPNv4        Family = "vpnv4"
	FamilyVPNv6        Family = "vpnv6"
	FamilyIPv6Unicast  Family = "ipv6_unicast"
	FamilySRPolicyIPv6 Family = "sr_policy_ipv6"
)

// String renders the family for logs and error messages.
func (f Family) String() string { return string(f) }

// Valid reports whether f is one of the recognized families.
func (f Family) Valid() bool {
	switch f {
	case FamilyVPNv4, FamilyVPNv6, FamilyIPv6Unicast, FamilySRPolicyIPv6:
		return true
	default:
		return false
	}
}

// ParseFamily validates an operator-supplied family string (as written
// in vinbero.yml) and returns the typed Family.
func ParseFamily(s string) (Family, error) {
	f := Family(s)
	if !f.Valid() {
		return "", fmt.Errorf("unknown BGP family %q (want vpnv4|vpnv6|ipv6_unicast|sr_policy_ipv6)", s)
	}
	return f, nil
}

// GlobalConfig is the BGP speaker's own identity.
type GlobalConfig struct {
	LocalASN uint32
	RouterID string
	// ListenPort is the TCP port the speaker binds. -1 disables the
	// listener entirely (in-process / passive-only operation), which is
	// the default for Vinbero so it can coexist with a host BGP daemon.
	ListenPort int32
}

// PeerConfig describes a single BGP neighbor.
type PeerConfig struct {
	Neighbor     string
	PeerASN      uint32
	HoldTimeSec  uint32
	KeepaliveSec uint32
	Families     []Family
}

// PeerState is a read-only snapshot of a neighbor's session.
type PeerState struct {
	Neighbor     string
	PeerASN      uint32
	SessionState string // "idle" / "connect" / "active" / "opensent" / "openconfirm" / "established"
}

// Session owns peer and global lifecycle. It carries no data-path
// responsibility -- route exchange lives in the other three interfaces.
type Session interface {
	Start(ctx context.Context, cfg GlobalConfig) error
	Stop(ctx context.Context) error
	AddPeer(ctx context.Context, p PeerConfig) error
	DeletePeer(ctx context.Context, neighbor string) error
	Peers(ctx context.Context) ([]PeerState, error)
}

// RouteKey identifies a previously-advertised route for withdrawal.
type RouteKey struct {
	Family Family
	Prefix string
	RD     string // route distinguisher; empty for non-VPN families
}

// VPNRoute is an L3VPN (VPNv4 / VPNv6) route carrying an SRv6 service
// SID. Fields are intentionally minimal for Phase 1c; Phase 1d/1e fill
// in the SID structure and extended-community detail.
type VPNRoute struct {
	Family   Family
	Prefix   string
	RD       string
	RTs      []string
	SRv6SID  string
	NextHop  string
}

// UnicastRoute is a plain IPv6 unicast route.
type UnicastRoute struct {
	Prefix  string
	NextHop string
}

// RouteAdvertiser pushes Vinbero's local state out to BGP peers.
// Implemented in Phase 1e.
type RouteAdvertiser interface {
	Advertise(ctx context.Context, r VPNRoute) error
	AdvertiseUnicast(ctx context.Context, r UnicastRoute) error
	Withdraw(ctx context.Context, key RouteKey) error
}

// RouteEvent is a single received BGP route update delivered to a
// RouteHandler. IsWithdraw distinguishes a withdrawal from an
// advertisement.
type RouteEvent struct {
	Family     Family
	VPN        *VPNRoute
	Unicast    *UnicastRoute
	IsWithdraw bool
}

// RouteHandler consumes received BGP routes. It is invoked from a
// GoBGP-internal goroutine; implementations must not block.
type RouteHandler func(ev RouteEvent)

// RouteSubscriber delivers received BGP routes to Vinbero. Implemented
// in Phase 1d.
type RouteSubscriber interface {
	Subscribe(filter Family, handler RouteHandler) (cancel func(), err error)
}

// SRPolicy is a received or to-be-advertised BGP SR Policy. Detail is
// filled in by Phase 1e.
type SRPolicy struct {
	Endpoint    string
	Color       uint32
	SegmentList []string
}

// SRPolicyController handles the SR Policy address family. Implemented
// in Phase 1e.
type SRPolicyController interface {
	OnPolicy(handler func(SRPolicy))
	PushPolicy(ctx context.Context, p SRPolicy) error
}
