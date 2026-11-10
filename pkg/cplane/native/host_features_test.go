package native

import (
	"testing"

	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	"github.com/takehaya/vinbero/sdk/go/cplane"
)

// The native host reports the same bitmap as the WASM host, and the SDK
// client sees the headend VRF bit through it.
func TestNativeHostReportsHeadendVRF(t *testing.T) {
	var h cplane.Host = &host{}
	fh, ok := h.(cplane.FeatureHost)
	if !ok {
		t.Fatal("the native host reports no features")
	}
	if fh.Features() != wasm.HostFeatures || fh.Features()&cplane.FeatureHeadendVRF == 0 {
		t.Errorf("features = %#x, want %#x with the headend VRF bit", fh.Features(), wasm.HostFeatures)
	}
}
