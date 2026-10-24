// Package customcontroller implements the shared custom SRv6 behavior example.
package customcontroller

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"

	"github.com/takehaya/vinbero/sdk/go/cplane"
)

const localSIDName = "self"

// Controller owns the route view and pending declarations for one serial instance.
type Controller struct {
	client       *cplane.Client
	config       configuration
	routes       cplane.RouteView
	log          func(cplane.LogLevel, string)
	allocatedSID string

	localSIDPending, advertisePending                             bool
	headendUnavailable, localSIDUnavailable, advertiseUnavailable bool
}

// New preserves the example's opaque wire configuration and initial cleanup.
func New(data []byte, client *cplane.Client, log func(cplane.LogLevel, string)) (*Controller, error) {
	config, err := decodeConfig(data)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, fmt.Errorf("custom behavior requires a declaration client")
	}
	if log == nil {
		log = func(cplane.LogLevel, string) {}
	}
	c := &Controller{client: client, config: config, log: log,
		localSIDPending: true, advertisePending: !config.advertises()}
	c.routes.Accept = c.acceptsRoute
	c.reconcile()
	return c, nil
}

// Tick retries declarations, including a local SID whose notification was lost.
func (c *Controller) Tick(int64) { c.reconcile() }

func (c *Controller) Update(events []cplane.Event) []cplane.EventResult {
	c.routes.Update(events)
	for _, ev := range events {
		if ev.Kind == cplane.EventRoute && !ev.Route.Withdraw && c.acceptsRoute(ev.Route) {
			c.log(cplane.LogInfo, "steering "+ev.Route.Prefix)
		}
		if c.config.allocates() && !c.localSIDUnavailable && ev.Kind == cplane.EventLocalSID && ev.LocalSID.Name == localSIDName && ev.LocalSID.SID != "" {
			c.allocatedSID = ev.LocalSID.SID
			c.localSIDPending = false
			c.advertisePending = c.config.advertises() && !c.advertiseUnavailable
		}
	}
	c.reconcile()
	return nil
}

func (c *Controller) acceptsRoute(r cplane.Route) bool {
	if r.Family != "vpnv4" || r.EndpointBehavior != c.config.behavior || r.SRv6SID == "" {
		return false
	}
	prefix, err := netip.ParsePrefix(r.Prefix)
	if err != nil || !prefix.Addr().Is4() {
		return false
	}
	// With no configured filter, retain the original unrestricted receiver.
	// Narrow host scopes must supply the same ranges in field 9.
	if len(c.config.headendPrefixes) == 0 {
		return true
	}
	for _, allowed := range c.config.headendPrefixes {
		if prefix.Bits() >= allowed.Bits() && allowed.Contains(prefix.Masked().Addr()) {
			return true
		}
	}
	return false
}

// Pending declarations survive a refusal and are retried on ticks, including
// when no new BGP update arrives. A BGP replay suspends headend declarations
// across event batches and ticks until its end marker.
func (c *Controller) reconcile() {
	if c.advertisePending && !c.config.advertises() {
		c.advertisePending = !c.optionalCleanup(c.client.ApplyAdvertise(nil))
	}
	if c.localSIDPending && (c.config.allocates() || !c.advertisePending) {
		var desired []cplane.LocalSID
		if c.config.allocates() {
			desired = []cplane.LocalSID{{
				Name: localSIDName, Locator: c.config.locator, Slot: c.config.slot,
				DecapVRF: c.config.decapVRF,
			}}
		}
		err := c.client.ApplyLocalSIDs(desired)
		if len(desired) == 0 {
			c.localSIDPending = !c.optionalCleanup(err)
		} else if errors.Is(err, cplane.ErrBeginRefused) {
			c.localSIDPending, c.localSIDUnavailable = false, true
			c.log(cplane.LogInfo, "local SID unavailable; running without local SID writes")
		} else if err != nil {
			c.log(cplane.LogWarn, err.Error())
		}
		// A successful declaration can lose its allocation notification when
		// the host queue is full. Retry until the matching SID event arrives.
	}
	if c.advertisePending && c.config.advertises() && c.allocatedSID != "" {
		err := c.client.ApplyAdvertise([]cplane.AdvertisedRoute{{
			Family: "vpnv4", VRF: c.config.vrf, Prefix: c.config.prefix,
			SRv6SID: c.allocatedSID, EndpointBehavior: c.config.behavior, NextHop: c.config.nextHop,
		}})
		if err == nil {
			c.advertisePending = false
		} else if errors.Is(err, cplane.ErrBeginRefused) {
			c.advertisePending, c.advertiseUnavailable = false, true
			c.log(cplane.LogInfo, "advertise unavailable; running without advertisements")
		} else {
			c.log(cplane.LogWarn, err.Error())
		}
	}
	if c.routes.Pending() && !c.headendUnavailable {
		if err := c.client.ApplyHeadendV4(c.headendEntries()); err != nil {
			if errors.Is(err, cplane.ErrBeginRefused) {
				c.headendUnavailable = true
				c.log(cplane.LogInfo, "headend unavailable; running without headend writes")
			} else {
				c.log(cplane.LogWarn, err.Error())
			}
		} else {
			c.routes.Applied()
			c.log(cplane.LogInfo, "declared headend")
		}
	}
}

// One forwarding entry per prefix. Keep all input paths, then choose one
// deterministically by RD, peer and ADD-PATH ID. This example does not implement
// BGP best-path selection; another plugin can choose its own policy here.
func (c *Controller) headendEntries() []cplane.HeadendEntry {
	type candidate struct {
		key cplane.PathKey
		sid string
	}
	chosen := map[string]candidate{}
	c.routes.Range(func(key cplane.PathKey, route cplane.Route) {
		old, found := chosen[key.Prefix]
		if !found || lessPath(key, old.key) {
			chosen[key.Prefix] = candidate{key, route.SRv6SID}
		}
	})
	prefixes := make([]string, 0, len(chosen))
	for prefix := range chosen {
		prefixes = append(prefixes, prefix)
	}
	sort.Strings(prefixes)
	entries := make([]cplane.HeadendEntry, 0, len(prefixes))
	for _, prefix := range prefixes {
		entries = append(entries, cplane.HeadendEntry{TriggerPrefix: prefix, Segments: []string{chosen[prefix].sid}})
	}
	return entries
}

// The example has no overlapping open transactions. In ABI 1 an optional kind
// that cannot begin is unavailable (e.g. a headend-only receiver has no sender
// capabilities). Once cleanup can begin, every failed commit stays retryable.
func (c *Controller) optionalCleanup(err error) bool {
	if err == nil || errors.Is(err, cplane.ErrBeginRefused) {
		return true
	}
	c.log(cplane.LogWarn, err.Error())
	return false
}

func lessPath(a, b cplane.PathKey) bool {
	if a.RD != b.RD {
		return a.RD < b.RD
	}
	if a.Peer != b.Peer {
		return a.Peer < b.Peer
	}
	return a.PathID < b.PathID
}
