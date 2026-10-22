// Package mupcontroller implements the shared GTP4 MUP route-composition controller.
package mupcontroller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"reflect"
	"slices"

	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/mup"
	"github.com/takehaya/vinbero/sdk/go/cplane/resolve"
	"github.com/takehaya/vinbero/sdk/go/cplane/routes"
)

type operatorConfig struct {
	Context     string `json:"context"`
	Source      string `json:"source"`
	ArgsOffset  *uint8 `json:"args_offset"`
	ObserveOnly *bool  `json:"observe_only"`
}

// CompositionClient receives complete desired forwarding sets.
type CompositionClient interface {
	ApplyComposition(cplane.Composition) error
}

// Controller keeps the route view and retry state for one serially driven instance.
type Controller struct {
	engine      *resolve.Engine
	down        *resolve.Plan[mup.ST1, mup.ISD]
	up          *resolve.Plan[mup.ST2, mup.DSD]
	downContext mup.DownlinkContext
	observeOnly bool
	client      CompositionClient
	log         func(cplane.LogLevel, string)
	// Only successful writes (or previews) advance this revision. Failed writes
	// are rebuilt from the current ready view on the next event or tick.
	handledRevision uint64
}

// New configures one controller. A nil client permits observation only.
func New(input cplane.InputConfig, client CompositionClient, log func(cplane.LogLevel, string)) (*Controller, error) {
	var config operatorConfig
	d := json.NewDecoder(bytes.NewReader(input.Payload))
	d.DisallowUnknownFields()
	if err := d.Decode(&config); err != nil {
		return nil, fmt.Errorf("operator config: %w", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("operator config: expected one JSON object")
	}
	source, err := netip.ParseAddr(config.Source)
	if err != nil || !source.Is6() || source.Is4In6() || source.IsUnspecified() || source.IsMulticast() || source.Zone() != "" {
		return nil, fmt.Errorf("source must be a usable IPv6 outer source address")
	}
	if config.Context == "" || config.ArgsOffset == nil || *config.ArgsOffset > 7 {
		return nil, fmt.Errorf("context and explicit args_offset (0..7) are required")
	}
	v, err := routes.NewView(input, routes.Limits{})
	if err != nil {
		return nil, err
	}
	engine, err := resolve.NewEngine(v, resolve.Limits{})
	if err != nil {
		return nil, err
	}
	rank := resolve.LongestPrefix(resolve.Right(mup.ISDPrefix))
	down, err := resolve.Register(engine, resolve.Rule[mup.ST1, mup.ISD]{
		Name: "downlink", Context: config.Context,
		Left: mup.ST1Selector(), Right: mup.ISDSelector(),
		Match: resolve.Contains(resolve.Right(mup.ISDPrefix), resolve.Left(mup.ST1Endpoint)),
		Rank:  &rank, Choose: resolve.Unique,
	})
	if err != nil {
		return nil, err
	}
	up, err := resolve.Register(engine, resolve.Rule[mup.ST2, mup.DSD]{
		Name: "uplink", Context: config.Context,
		Left: mup.ST2Selector(), Right: mup.DSDSelector(),
		Match:  resolve.Equal(resolve.Left(mup.ST2DirectSegment), resolve.Right(mup.DSDDirectSegment)),
		Choose: resolve.Unique,
	})
	if err != nil {
		return nil, err
	}
	observeOnly := config.ObserveOnly == nil || *config.ObserveOnly
	if !observeOnly && client == nil {
		return nil, fmt.Errorf("write mode requires a composition client")
	}
	if log == nil {
		log = func(cplane.LogLevel, string) {}
	}
	return &Controller{engine: engine, down: down, up: up,
		downContext: mup.DownlinkContext{Source: source, ArgsOffset: *config.ArgsOffset},
		observeOnly: observeOnly, client: client, log: log}, nil
}

// Update applies a batch and reconciles the latest complete route view.
func (c *Controller) Update(events []cplane.Event) []cplane.EventResult {
	results := c.engine.Update(events)
	c.reconcile()
	return results
}

// Tick retries a pending revision when no route event arrives.
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
	for _, pair := range c.down.Results() {
		entry, err := mup.BuildDownlink(pair, c.downContext)
		if err != nil {
			c.log(cplane.LogWarn, "downlink: "+err.Error())
			continue
		}
		set.Headends = append(set.Headends, entry)
	}
	for _, pair := range c.up.Results() {
		entry, err := mup.BuildUplink(pair, c.downContext.Source)
		if err != nil {
			c.log(cplane.LogWarn, "uplink: "+err.Error())
			continue
		}
		set.Uplinks = append(set.Uplinks, entry)
	}
	// Every uplink also claims its endpoint /32 in the headend map. Record
	// all raw claims before reducing either list so ambiguity stays sticky.
	gates := map[string]bool{}
	for _, u := range set.Uplinks {
		gates[u.Endpoint+"/32"] = true
	}
	conflicts := map[string]bool{}
	for _, h := range set.Headends {
		k := h.Entry.TriggerPrefix
		if gates[k] && !conflicts[k] {
			conflicts[k] = true
			c.log(cplane.LogWarn, "ambiguous forwarding key: "+k)
		}
	}
	set.Headends = slices.DeleteFunc(set.Headends, func(h cplane.ForwardingHeadend) bool {
		return conflicts[h.Entry.TriggerPrefix]
	})
	set.Uplinks = slices.DeleteFunc(set.Uplinks, func(u cplane.MUPUplink) bool {
		return conflicts[u.Endpoint+"/32"]
	})
	set.Headends = unambiguousOutputs(set.Headends, func(h cplane.ForwardingHeadend) string {
		return h.Entry.TriggerPrefix
	}, c.log)
	// This controller has one context, hence one host-resolved MUP instance.
	set.Uplinks = unambiguousOutputs(set.Uplinks, func(u cplane.MUPUplink) string {
		return fmt.Sprintf("%s/%d/%d", u.Endpoint, u.TEID, u.TEIDBits)
	}, c.log)
	if !c.observeOnly {
		if err := c.client.ApplyComposition(set); err != nil {
			c.log(cplane.LogWarn, fmt.Sprintf("revision %d apply failed: %v", set.Revision, err))
			return
		}
	}
	c.handledRevision = status.Revision
	c.log(cplane.LogInfo, fmt.Sprintf("revision %d observe_only=%t headends=%d uplinks=%d", set.Revision, c.observeOnly, len(set.Headends), len(set.Uplinks)))
}

// Different NLRIs can build the same forwarding key. Preserve result order,
// coalesce identical outputs and omit every value for a conflicting key.
func unambiguousOutputs[T any](entries []T, key func(T) string, log func(cplane.LogLevel, string)) []T {
	first := map[string]int{}
	conflicts := map[string]bool{}
	for i, entry := range entries {
		k := key(entry)
		if at, ok := first[k]; ok {
			if !conflicts[k] && !reflect.DeepEqual(entries[at], entry) {
				conflicts[k] = true
				log(cplane.LogWarn, "ambiguous forwarding key: "+k)
			}
		} else {
			first[k] = i
		}
	}
	out := entries[:0]
	for i, entry := range entries {
		k := key(entry)
		if !conflicts[k] && first[k] == i {
			out = append(out, entry)
		}
	}
	return out
}
