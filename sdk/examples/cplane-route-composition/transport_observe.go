//go:build !composition_write

package main

// A read-only artifact does not reference guest.Host, so its WASM imports do
// not include apply_*. Configuration cannot promote this build to writing.
func outputClient() compositionClient { return nil }
