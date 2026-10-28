// Command cplane-custom-cdplane-behavior connects the JSON adapter to the WASM ABI.
package main

import (
	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/cdplanecontroller"
	"github.com/takehaya/vinbero/sdk/go/cplane/customcontroller"
	"github.com/takehaya/vinbero/sdk/go/cplane/guest"
)

func init() {
	var current *customcontroller.Controller
	client := &cplane.Client{Host: guest.Host{}}
	guest.Register(guest.Handlers{
		Configure: func(data []byte) error {
			next, err := cdplanecontroller.New(data, client, guest.Log)
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
