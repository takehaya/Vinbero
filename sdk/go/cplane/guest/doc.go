// Package guest connects a Go WASM plugin to vinberod. Register callbacks
// from init; the host initializes the reactor before invoking them.
// WASM functions are built with standard Go for wasip1/wasm or optionally
// TinyGo for wasm-unknown. Native tests use cplane.Host and cplaneharness.
package guest
