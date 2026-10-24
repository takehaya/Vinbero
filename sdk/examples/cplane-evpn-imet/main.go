//go:build (wasip1 && wasm) || (tinygo && wasm_unknown)

package main

import (
	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/evpncontroller"
	"github.com/takehaya/vinbero/sdk/go/cplane/guest"
)

func init() {
	var current *evpncontroller.Controller
	guest.Register(guest.Handlers{
		Configure: func(data []byte) error {
			input, err := cplane.DecodeInputConfig(data, guest.InputFeatures())
			if err != nil {
				return err
			}
			next, err := evpncontroller.New(input, &cplane.Client{Host: guest.Host{}}, guest.Log)
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
