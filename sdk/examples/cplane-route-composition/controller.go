package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"

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

type compositionClient interface {
	ApplyComposition(cplane.Composition) error
}

type controller struct {
	engine      *resolve.Engine
	down        *resolve.Plan[mup.ST1, mup.ISD]
	up          *resolve.Plan[mup.ST2, mup.DSD]
	downContext mup.DownlinkContext
	observeOnly bool
	client      compositionClient
	log         func(cplane.LogLevel, string)
	// Only successful writes (or previews) advance this revision. Failed writes
	// are rebuilt from the current ready view on the next event or tick.
	handledRevision uint64
}

func newController(input cplane.InputConfig, client compositionClient, log func(cplane.LogLevel, string)) (*controller, error) {
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
	return &controller{engine: engine, down: down, up: up,
		downContext: mup.DownlinkContext{Source: source, ArgsOffset: *config.ArgsOffset},
		observeOnly: observeOnly, client: client, log: log}, nil
}

func (c *controller) update(events []cplane.Event) []cplane.EventResult {
	results := c.engine.Update(events)
	c.reconcile()
	return results
}

func (c *controller) reconcile() {
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
	if !c.observeOnly {
		if err := c.client.ApplyComposition(set); err != nil {
			c.log(cplane.LogWarn, fmt.Sprintf("revision %d apply failed: %v", set.Revision, err))
			return
		}
	}
	c.handledRevision = status.Revision
	c.log(cplane.LogInfo, fmt.Sprintf("revision %d observe_only=%t headends=%d uplinks=%d", set.Revision, c.observeOnly, len(set.Headends), len(set.Uplinks)))
}
