//go:build (wasip1 && wasm) || (tinygo && wasm_unknown)

package main

import (
	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/guest"
)

func init() {
	var current *controller
	client := outputClient()
	guest.Register(guest.Handlers{
		Configure: func(data []byte) error {
			input, err := cplane.DecodeInputConfig(data, guest.InputFeatures())
			if err != nil {
				return err
			}
			next, err := newController(input, client, guest.Log)
			if err == nil {
				current = next
			}
			return err
		},
		Events: func(events []cplane.Event) []cplane.EventResult { return current.update(events) },
		Tick:   func(int64) { current.reconcile() },
	})
}

func main() {}
