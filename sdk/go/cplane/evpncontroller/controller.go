// Package evpncontroller implements an optional IMET-gated static MAC policy.
// IMET presence is a policy prerequisite, not proof of reachability or an EVPN
// standard requirement. Only the existing single-homed, tag-zero profile is used.
package evpncontroller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"reflect"

	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/evpn"
	"github.com/takehaya/vinbero/sdk/go/cplane/resolve"
	"github.com/takehaya/vinbero/sdk/go/cplane/routes"
)

type operatorConfig struct {
	Context     string `json:"context"`
	Source      string `json:"source"`
	ObserveOnly *bool  `json:"observe_only"`
}

// CompositionClient receives the complete desired set for one controller.
type CompositionClient interface {
	ApplyComposition(cplane.Composition) error
}

// Controller owns one serially driven route view and retry revision.
type Controller struct {
	engine          *resolve.Engine
	plan            *resolve.Plan[evpn.RT2, evpn.RT3]
	source          netip.Addr
	observeOnly     bool
	client          CompositionClient
	log             func(cplane.LogLevel, string)
	handledRevision uint64
}

type peerKey struct {
	Remote netip.Addr
	Tag    uint32
}

// New configures the policy. Observation is the default; writing needs a client.
func New(input cplane.InputConfig, client CompositionClient, log func(cplane.LogLevel, string)) (*Controller, error) {
	var config operatorConfig
	decoder := json.NewDecoder(bytes.NewReader(input.Payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("operator config: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("operator config: expected one JSON object")
	}
	source, err := netip.ParseAddr(config.Source)
	if err != nil || !source.Is6() || source.Is4In6() || !source.IsGlobalUnicast() || source.Zone() != "" {
		return nil, fmt.Errorf("source must be a usable IPv6 address")
	}
	if config.Context == "" {
		return nil, fmt.Errorf("context is required")
	}
	view, err := routes.NewView(input, routes.Limits{})
	if err != nil {
		return nil, err
	}
	engine, err := resolve.NewEngine(view, resolve.Limits{})
	if err != nil {
		return nil, err
	}
	// RD identifies the NLRI, not the remote peer shared by the two route types.
	left := resolve.Field[evpn.RT2, peerKey]{Name: "RT2 peer", Get: func(r evpn.RT2) resolve.Value[peerKey] { return resolve.Known(peerKey{r.Remote, r.EthernetTag}) }}
	right := resolve.Field[evpn.RT3, peerKey]{Name: "RT3 peer", Get: func(r evpn.RT3) resolve.Value[peerKey] { return resolve.Known(peerKey{r.Remote, r.EthernetTag}) }}
	plan, err := resolve.Register(engine, resolve.Rule[evpn.RT2, evpn.RT3]{Name: "imet-gated-mac", Context: config.Context,
		Left: evpn.RT2Selector(), Right: evpn.RT3Selector(), Match: resolve.Equal(resolve.Left(left), resolve.Right(right)), Choose: resolve.Unique})
	if err != nil {
		return nil, err
	}
	observe := config.ObserveOnly == nil || *config.ObserveOnly
	if !observe && client == nil {
		return nil, fmt.Errorf("write mode requires a composition client")
	}
	if log == nil {
		log = func(cplane.LogLevel, string) {}
	}
	return &Controller{engine: engine, plan: plan, source: source, observeOnly: observe, client: client, log: log}, nil
}

// Update applies the batch and reconciles only a complete authorized view.
func (c *Controller) Update(events []cplane.Event) []cplane.EventResult {
	results := c.engine.Update(events)
	c.reconcile()
	return results
}

// Tick retries the latest ready revision after a failed apply.
func (c *Controller) Tick(_ int64) { c.reconcile() }

func (c *Controller) reconcile() {
	status := c.engine.Status()
	if !status.Ready || status.Revision == c.handledRevision {
		return
	}
	for _, issue := range status.Issues {
		c.log(cplane.LogWarn, fmt.Sprintf("%s: %s: %s", issue.Rule, issue.Code, issue.Reason))
	}
	set := cplane.Composition{Revision: status.Revision}
	c.plan.Range(func(pair resolve.Pair[evpn.RT2, evpn.RT3]) {
		// Validate the IMET service profile without installing a BUM flood peer.
		if _, err := evpn.BuildFlood(pair.Right, pair.Context, c.source); err != nil {
			c.log(cplane.LogWarn, "IMET: "+err.Error())
			return
		}
		entry, err := evpn.BuildStaticMAC(pair.Left, pair.Context, c.source)
		if err != nil {
			c.log(cplane.LogWarn, "MAC: "+err.Error())
			return
		}
		set.EVPN = append(set.EVPN, entry)
	})
	// Different RT2 NLRIs can claim one MAC. Keep conflicts sticky across every
	// claimant, coalesce identical outputs, and never pick a conflicting first row.
	first := map[string]int{}
	conflicts := map[string]bool{}
	for i, entry := range set.EVPN {
		if at, exists := first[entry.MAC]; exists {
			if !reflect.DeepEqual(set.EVPN[at], entry) {
				conflicts[entry.MAC] = true
			}
		} else {
			first[entry.MAC] = i
		}
	}
	out := set.EVPN[:0]
	for i, entry := range set.EVPN {
		if first[entry.MAC] != i {
			continue
		}
		if conflicts[entry.MAC] {
			c.log(cplane.LogWarn, "ambiguous MAC: "+entry.MAC)
			continue
		}
		out = append(out, entry)
	}
	set.EVPN = out
	// One authorized context maps a remote source to one unicast reverse peer.
	// Remove every conflicting peer after MAC filtering so its invalid set
	// cannot prevent independent MAC withdrawals from reaching the host.
	remoteFirst := map[string]int{}
	remoteConflicts := map[string]bool{}
	for i, entry := range set.EVPN {
		if at, exists := remoteFirst[entry.RemoteSrc]; exists {
			if !reflect.DeepEqual(set.EVPN[at].Segments, entry.Segments) {
				remoteConflicts[entry.RemoteSrc] = true
			}
		} else {
			remoteFirst[entry.RemoteSrc] = i
		}
	}
	out = set.EVPN[:0]
	for _, entry := range set.EVPN {
		if remoteConflicts[entry.RemoteSrc] {
			c.log(cplane.LogWarn, "ambiguous remote peer: "+entry.RemoteSrc)
			continue
		}
		out = append(out, entry)
	}
	set.EVPN = out
	if !c.observeOnly {
		if err := c.client.ApplyComposition(set); err != nil {
			c.log(cplane.LogWarn, fmt.Sprintf("revision %d apply failed: %v", set.Revision, err))
			return
		}
	}
	c.handledRevision = status.Revision
	c.log(cplane.LogInfo, fmt.Sprintf("revision %d observe_only=%t static_macs=%d", set.Revision, c.observeOnly, len(set.EVPN)))
}
