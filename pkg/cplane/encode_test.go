package cplane

import (
	"net/netip"
	"testing"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

// The mode indexes the headend PROG_ARRAY, so one with nothing behind it
// is an entry that looks installed and tail-calls into an empty slot: the
// packet is dropped and nothing says why.
func TestHeadendModeMustHaveSomethingBehindIt(t *testing.T) {
	src := netip.MustParseAddr("fd00:1::1")
	entry := func(mode uint32) *v1.PluginHeadendEntry {
		return &v1.PluginHeadendEntry{
			TriggerPrefix: "10.0.0.0/24",
			Segments:      []string{"fd00:2::1"},
			Mode:          mode,
		}
	}

	// A behavior vinbero implements is fine, and so is a plugin slot.
	for _, mode := range []uint32{
		0, // the plugin-facing default
		uint32(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_RED),
		16, // the first headend plugin slot
		31, // the last
	} {
		if _, _, err := DecodeHeadendEntry(entry(mode), src); err != nil {
			t.Errorf("mode %d was refused: %v", mode, err)
		}
	}

	// Neither a behavior nor a plugin slot.
	for _, mode := range []uint32{11, 15, 32, 200} {
		if _, _, err := DecodeHeadendEntry(entry(mode), src); err == nil {
			t.Errorf("mode %d was accepted; nothing is dispatched from it", mode)
		}
	}
}
