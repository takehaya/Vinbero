module github.com/takehaya/vinbero/sdk/examples/cplane-route-composition

go 1.25.5

require (
	github.com/osrg/gobgp/v4 v4.5.0
	github.com/takehaya/vinbero v0.0.0
)

replace github.com/takehaya/vinbero => ../../..

// Dependency-module replacements are not inherited by this guest module.
replace github.com/osrg/gobgp/v4 => github.com/takehaya/gobgp/v4 v4.7.0-mup-draft01
