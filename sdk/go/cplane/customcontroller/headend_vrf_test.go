package customcontroller

import (
	"testing"

	"github.com/takehaya/vinbero/sdk/go/cplane"
)

// The headend entries of received routes are declared in the configured
// headend VRF, and in the global VRF without one.
func TestHeadendEntriesCarryTheHeadendVRF(t *testing.T) {
	for _, vrf := range []string{"", "vpn-a"} {
		c := &Controller{config: Config{Behavior: 0xfe01, HeadendVRF: vrf}}
		c.routes.Accept = c.acceptsRoute
		c.routes.Update([]cplane.Event{{Kind: cplane.EventRoute, Route: cplane.Route{
			Family: "vpnv4", Peer: "2001:db8::2", RD: "65000:1", Prefix: "10.2.0.0/24",
			EndpointBehavior: 0xfe01, SRv6SID: "fd00:2::1",
		}}})
		entries := c.headendEntries()
		if len(entries) != 1 || entries[0].VRF != vrf || entries[0].TriggerPrefix != "10.2.0.0/24" {
			t.Errorf("headend VRF %q: entries = %+v", vrf, entries)
		}
	}
}
