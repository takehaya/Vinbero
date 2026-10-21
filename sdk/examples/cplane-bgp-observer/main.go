package main

import (
	"fmt"

	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/gobgppath"
	"github.com/takehaya/vinbero/sdk/go/cplane/guest"
)

func init() {
	guest.Register(guest.Handlers{
		Configure: func([]byte) error {
			if guest.InputFeatures()&cplane.FeatureBGPPath == 0 {
				return fmt.Errorf("full BGP input is required")
			}
			return nil
		},
		Events: func(events []cplane.Event) []cplane.EventResult {
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
				guest.Log(cplane.LogInfo, fmt.Sprintf("BGP family=%d/%d peer=%s path_id=%d withdraw=%t nlri=%s attributes=%d",
					path.Key.AFI, path.Key.SAFI, path.Key.Peer, path.Key.PathID,
					path.Withdraw, path.NLRI.String(), len(path.Attributes)))
			}
			return results
		},
	})
}

func main() {}
