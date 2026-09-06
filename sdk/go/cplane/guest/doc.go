// Package guest connects a TinyGo WASM plugin to vinberod. Register callbacks
// from a package initializer; the host invokes them through ABI version 1.
// WASM functions are built only with TinyGo for the wasm target. Native tests
// can exercise package cplane directly or run a compiled module in cplaneharness.
package guest
