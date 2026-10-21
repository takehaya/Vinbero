module github.com/takehaya/vinbero/sdk/examples/cplane-bgp-observer

go 1.25.5

require github.com/takehaya/vinbero v0.0.0

require github.com/osrg/gobgp/v4 v4.5.0 // indirect

replace github.com/takehaya/vinbero => ../../..

// Dependency-module replacements are not inherited by this guest module.
replace github.com/osrg/gobgp/v4 => github.com/takehaya/gobgp/v4 v4.7.0-mup-draft01
