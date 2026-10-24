package bgpobserver

import (
	"github.com/takehaya/vinbero/sdk/go/cplane"
	"testing"
)

func TestRequiresFullBGPInput(t *testing.T) {
	if _, err := New(0, nil); err == nil {
		t.Fatal("missing BGPPath feature accepted")
	}
	c, err := New(cplane.FeatureBGPPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Tick(123)
	if got := c.Update([]cplane.Event{{Kind: cplane.EventEndOfReplay}}); len(got) != 0 {
		t.Fatal("non-route event quarantined")
	}
}
