//go:build composition_write && ((wasip1 && wasm) || (tinygo && wasm_unknown))

package main

import (
	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/guest"
	"github.com/takehaya/vinbero/sdk/go/cplane/mupcontroller"
)

func outputClient() mupcontroller.CompositionClient { return &cplane.Client{Host: guest.Host{}} }
