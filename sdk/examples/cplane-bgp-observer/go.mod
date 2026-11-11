module github.com/takehaya/vinbero/sdk/examples/cplane-bgp-observer

go 1.25.5

require github.com/takehaya/vinbero v0.0.0

require github.com/osrg/gobgp/v4 v4.11.0 // indirect

replace github.com/takehaya/vinbero => ../../..

// Dependency-module replacements are not inherited by this guest module.
replace github.com/osrg/gobgp/v4 => github.com/takehaya/gobgp/v4 v4.0.0-20261111065903-a0d320ba8166
