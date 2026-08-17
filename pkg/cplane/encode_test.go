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
		if _, _, err := DecodeHeadendEntry(entry(mode), AFv4, src); err != nil {
			t.Errorf("mode %d was refused: %v", mode, err)
		}
	}

	// Neither a behavior nor a plugin slot.
	for _, mode := range []uint32{11, 15, 32, 200} {
		if _, _, err := DecodeHeadendEntry(entry(mode), AFv4, src); err == nil {
			t.Errorf("mode %d was accepted; nothing is dispatched from it", mode)
		}
	}
}

// The headend maps are LPM tries: they store the masked network and report
// it back that way. A declaration spelled with host bits set has to become
// the same key the map will report, or the owner's next declaration does
// not recognize the entry it just wrote -- it prunes it, writes it again,
// and never releases the lease.
func TestTriggerPrefixIsMasked(t *testing.T) {
	prefix, _, err := DecodeHeadendEntry(&v1.PluginHeadendEntry{
		TriggerPrefix: "10.0.0.7/24",
		Segments:      []string{"fd00:2::1"},
	}, AFv4, netip.MustParseAddr("fd00:1::1"))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if prefix != "10.0.0.0/24" {
		t.Fatalf("trigger prefix = %q, want the masked network", prefix)
	}
}

// The transaction's kind picks the map, so a prefix of the other family is
// an entry that cannot be written. The reconcile prunes before it writes,
// so accepting it empties the owner's whole set in that family and then
// fails -- identically on every declaration, so nothing recovers it.
func TestTriggerPrefixMustMatchTheDeclaredFamily(t *testing.T) {
	src := netip.MustParseAddr("fd00:1::1")
	v6InV4 := &v1.PluginHeadendEntry{
		TriggerPrefix: "2001:db8::/32",
		Segments:      []string{"fd00:2::1"},
	}
	if _, _, err := DecodeHeadendEntry(v6InV4, AFv4, src); err == nil {
		t.Error("an IPv6 prefix was accepted into an IPv4 declaration")
	}
	v4InV6 := &v1.PluginHeadendEntry{
		TriggerPrefix: "10.0.0.0/24",
		Segments:      []string{"fd00:2::1"},
	}
	if _, _, err := DecodeHeadendEntry(v4InV6, AFv6, src); err == nil {
		t.Error("an IPv4 prefix was accepted into an IPv6 declaration")
	}
	// And each is fine in its own family.
	if _, _, err := DecodeHeadendEntry(v4InV6, AFv4, src); err != nil {
		t.Errorf("an IPv4 prefix was refused in an IPv4 declaration: %v", err)
	}
	if _, _, err := DecodeHeadendEntry(v6InV4, AFv6, src); err != nil {
		t.Errorf("an IPv6 prefix was refused in an IPv6 declaration: %v", err)
	}
}
