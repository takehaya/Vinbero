package main

import (
	"fmt"
	"strings"

	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/guest"
)

func init() {
	guest.Register(guest.Handlers{
		Configure: func([]byte) error {
			g, err := guest.Grants()
			if err != nil {
				return err
			}
			prefixes := make([]string, 0, len(g.HeadendPrefixes))
			for _, p := range g.HeadendPrefixes {
				prefixes = append(prefixes, p.String())
			}
			guest.Log(cplane.LogInfo, fmt.Sprintf("caps=%s families=%s behaviors=%v locators=%d vrfs=%s prefixes=%s v4=%v v6=%v endpoint=%v",
				strings.Join(g.Capabilities, ","), strings.Join(g.Families, ","), g.Behaviors, len(g.Locators),
				strings.Join(g.VRFs, ","), strings.Join(prefixes, ","), g.HeadendV4Slots, g.HeadendV6Slots, g.EndpointSlots))
			return nil
		},
	})
}

func main() {}
