package cplane

import (
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
)

// EncodeGrants renders what a registration granted as the PluginGrants
// message a plugin reads through vinbero.grants or the native adapter.
//
// The message is advisory input to the plugin. Nothing here is consulted
// when a declaration is checked: PluginOps, the Guard and the claim registry
// enforce the same registration independently, so a guest that misreads its
// grants can only have declarations refused.
func EncodeGrants(caps wasm.Capabilities, families []bgp.Family, behaviors []uint16, scope Scope) ([]byte, error) {
	msg := &v1.PluginGrants{
		Version:         1,
		Capabilities:    caps.Names(),
		Locators:        append([]string(nil), scope.Locators...),
		Vrfs:            append([]string(nil), scope.VRFs...),
		HeadendPrefixes: scope.HeadendPrefixStrings(),
		HeadendV4Slots:  append([]uint32(nil), scope.HeadendV4Slots...),
		HeadendV6Slots:  append([]uint32(nil), scope.HeadendV6Slots...),
		EndpointSlots:   append([]uint32(nil), scope.EndpointSlots...),
	}
	// A registration may repeat a family or behavior; the plugin sees each
	// once, so a repeated claim still counts as a single claimed behavior.
	for _, f := range families {
		msg.Families = append(msg.Families, string(f))
	}
	slices.Sort(msg.Families)
	msg.Families = slices.Compact(msg.Families)
	for _, b := range behaviors {
		msg.Behaviors = append(msg.Behaviors, uint32(b))
	}
	slices.Sort(msg.Behaviors)
	msg.Behaviors = slices.Compact(msg.Behaviors)
	out, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("cplane: encode grants: %w", err)
	}
	return out, nil
}
