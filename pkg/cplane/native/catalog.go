// Package native runs statically linked, trusted control-plane controllers in
// the daemon process. It does not isolate memory or forcibly terminate calls.
package native

import (
	"crypto/sha256"
	"fmt"

	buildidentity "github.com/takehaya/vinbero"

	"github.com/takehaya/vinbero/pkg/cplane/wasm"
)

const (
	CustomBehavior         = "custom-behavior"
	BGPObserver            = "bgp-observer"
	MUPComposition         = "mup-composition"
	MUPCompositionObserver = "mup-composition-observer"
	ImplementationVersion  = "1"
)

// Descriptor identifies a compiled implementation; it does not grant authority.
type Descriptor struct {
	ID       string
	Version  string
	Identity string
	Write    bool
}

// Lookup reads catalog metadata without constructing or configuring a controller.
func Lookup(id string) (Descriptor, bool) {
	identity := fmt.Sprintf("%x", sha256.Sum256([]byte(id+"\x00"+ImplementationVersion+"\x00"+buildidentity.Source)))
	switch id {
	case MUPComposition, CustomBehavior:
		return Descriptor{ID: id, Version: ImplementationVersion, Identity: identity, Write: true}, true
	case MUPCompositionObserver, BGPObserver:
		return Descriptor{ID: id, Version: ImplementationVersion, Identity: identity}, true
	default:
		return Descriptor{}, false
	}
}

// ValidateIdentity rejects unavailable implementations without executing them.
func ValidateIdentity(id, version string) error {
	d, ok := Lookup(id)
	if !ok || version != d.Version {
		return fmt.Errorf("%w: native implementation %q version %q unavailable", wasm.ErrAdmission, id, version)
	}
	return nil
}
