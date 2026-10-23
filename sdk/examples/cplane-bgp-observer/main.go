package main

import (
	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/bgpobserver"
	"github.com/takehaya/vinbero/sdk/go/cplane/guest"
)

func init() {
	var current *bgpobserver.Controller
	guest.Register(guest.Handlers{
		Configure: func([]byte) error {
			next, err := bgpobserver.New(guest.InputFeatures(), guest.Log)
			if err == nil {
				current = next
			}
			return err
		},
		Events: func(events []cplane.Event) []cplane.EventResult { return current.Update(events) },
		Tick:   func(now int64) { current.Tick(now) },
	})
}

func main() {}
