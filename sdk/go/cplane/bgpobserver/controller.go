// Package bgpobserver implements the shared read-only GoBGP route observer.
package bgpobserver

import (
	"fmt"

	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/gobgppath"
)

// Controller logs decoded routes and quarantines malformed BGP paths.
type Controller struct{ log func(cplane.LogLevel, string) }

// New requires full BGP input, without interpreting the opaque configuration.
func New(features uint64, log func(cplane.LogLevel, string)) (*Controller, error) {
	if features&cplane.FeatureBGPPath == 0 {
		return nil, fmt.Errorf("full BGP input is required")
	}
	if log == nil {
		log = func(cplane.LogLevel, string) {}
	}
	return &Controller{log: log}, nil
}

func (c *Controller) Update(events []cplane.Event) []cplane.EventResult {
	var results []cplane.EventResult
	for _, ev := range events {
		if ev.Kind != cplane.EventRoute {
			continue
		}
		path, err := gobgppath.Decode(ev.Route)
		if err != nil {
			results = append(results, cplane.EventResult{
				Sequence: ev.Sequence, Disposition: cplane.Quarantine, Reason: err.Error(),
			})
			continue
		}
		c.log(cplane.LogInfo, fmt.Sprintf("BGP family=%d/%d peer=%s path_id=%d withdraw=%t nlri=%s attributes=%d",
			path.Key.AFI, path.Key.SAFI, path.Key.Peer, path.Key.PathID,
			path.Withdraw, path.NLRI.String(), len(path.Attributes)))
	}
	return results
}

func (*Controller) Tick(int64) {}
