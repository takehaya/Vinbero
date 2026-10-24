package main

import (
	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/guest"
)

func init() {
	guest.Register(guest.Handlers{
		Configure: func(data []byte) error { guest.Log(cplane.LogInfo, string(data)); return nil },
		Events: func(events []cplane.Event) []cplane.EventResult {
			var results []cplane.EventResult
			for _, ev := range events {
				guest.Log(cplane.LogInfo, ev.Route.Prefix)
				results = append(results, cplane.EventResult{
					Sequence: ev.Sequence, Disposition: cplane.Quarantine, Reason: "observation only",
				})
			}
			return results
		},
		Tick: func(now int64) {
			if guest.NowMonotonic() != now {
				panic("clock mismatch")
			}
		},
	})
}

func main() {}
