//go:build !composition_write

package main

import "github.com/takehaya/vinbero/sdk/go/cplane/mupcontroller"

// A read-only artifact does not reference guest.Host, so its WASM imports do
// not include apply_*. Configuration cannot promote this build to writing.
func outputClient() mupcontroller.CompositionClient { return nil }
