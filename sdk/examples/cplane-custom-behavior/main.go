// Command cplane-custom-behavior steers VPNv4 routes carrying an operator's
// SRv6 behavior, and optionally allocates and advertises its own local SID.
package main

import (
	"errors"
	"sort"

	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/guest"
)

const localSIDName = "self"

var client = cplane.Client{Host: guest.Host{}}
var config = configuration{behavior: 0xFE01}
var routes = cplane.RouteView{Accept: acceptsRoute}
var allocatedSID string
var localSIDPending, advertisePending bool
var headendUnavailable bool

func init() {
	guest.Register(guest.Handlers{
		Configure: configure,
		Events:    handleEvents,
		Tick:      func(int64) { reconcile() },
	})
}

func configure(data []byte) error {
	var err error
	config, err = decodeConfig(data)
	if err != nil {
		return err
	}
	// Owner state survives same-name replacement. Disabled kinds must declare
	// empty sets so the previous instance's resources are retracted.
	localSIDPending = true
	advertisePending = !config.advertises()
	reconcile()
	return nil
}

func handleEvents(events []cplane.Event) []cplane.EventResult {
	routes.Update(events)
	for _, ev := range events {
		if ev.Kind == cplane.EventRoute && !ev.Route.Withdraw && acceptsRoute(ev.Route) {
			guest.Log(cplane.LogInfo, "steering "+ev.Route.Prefix)
		}
		if config.allocates() && ev.Kind == cplane.EventLocalSID && ev.LocalSID.Name == localSIDName && ev.LocalSID.SID != "" {
			allocatedSID = ev.LocalSID.SID
			advertisePending = config.advertises()
		}
	}
	reconcile()
	return nil
}

func acceptsRoute(r cplane.Route) bool {
	return r.Family == "vpnv4" && r.EndpointBehavior == config.behavior && r.SRv6SID != ""
}

// Pending declarations survive a refusal and are retried on ticks, including
// when no new BGP update arrives. A BGP replay suspends headend declarations
// across event batches and ticks until its end marker.
func reconcile() {
	if advertisePending && !config.advertises() {
		advertisePending = !optionalCleanup(client.ApplyAdvertise(nil))
	}
	if localSIDPending && (config.allocates() || !advertisePending) {
		var desired []cplane.LocalSID
		if config.allocates() {
			desired = []cplane.LocalSID{{
				Name: localSIDName, Locator: config.locator, Slot: config.slot,
				DecapVRF: config.decapVRF,
			}}
		}
		err := client.ApplyLocalSIDs(desired)
		if len(desired) == 0 {
			localSIDPending = !optionalCleanup(err)
		} else if err == nil {
			localSIDPending = false
		} else {
			guest.Log(cplane.LogWarn, err.Error())
		}
	}
	if advertisePending && config.advertises() && allocatedSID != "" {
		err := client.ApplyAdvertise([]cplane.AdvertisedRoute{{
			Family: "vpnv4", VRF: config.vrf, Prefix: config.prefix,
			SRv6SID: allocatedSID, EndpointBehavior: config.behavior, NextHop: config.nextHop,
		}})
		if err == nil {
			advertisePending = false
		} else {
			guest.Log(cplane.LogWarn, err.Error())
		}
	}
	if routes.Pending() && !headendUnavailable {
		if err := client.ApplyHeadendV4(headendEntries()); err != nil {
			if errors.Is(err, cplane.ErrBeginRefused) {
				headendUnavailable = true
				guest.Log(cplane.LogInfo, "headend unavailable; running without headend writes")
			} else {
				guest.Log(cplane.LogWarn, err.Error())
			}
		} else {
			routes.Applied()
			guest.Log(cplane.LogInfo, "declared headend")
		}
	}
}

// One forwarding entry per prefix. Keep all input paths, then choose one
// deterministically by RD, peer and ADD-PATH ID. This example does not implement
// BGP best-path selection; another plugin can choose its own policy here.
func headendEntries() []cplane.HeadendEntry {
	type candidate struct {
		key cplane.PathKey
		sid string
	}
	chosen := map[string]candidate{}
	routes.Range(func(key cplane.PathKey, route cplane.Route) {
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
func optionalCleanup(err error) bool {
	if err == nil || errors.Is(err, cplane.ErrBeginRefused) {
		return true
	}
	guest.Log(cplane.LogWarn, err.Error())
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

func main() {}
