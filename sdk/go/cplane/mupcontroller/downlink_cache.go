package mupcontroller

import (
	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/mup"
	"github.com/takehaya/vinbero/sdk/go/cplane/resolve"
)

// This memoizes only the pure builder, after fresh resolution on every update.
// A changed result position is a miss; dependency and ambiguity checks stay live.
// The controller's downlink configuration is fixed for its lifetime.
type downlinkProjection struct {
	left    mup.ST1
	right   mup.ISD
	context string
	value   cplane.ForwardingHeadend
	sid     string
	valid   bool
}

func (c *Controller) buildDownlink(i int, pair resolve.Pair[mup.ST1, mup.ISD]) (cplane.ForwardingHeadend, error) {
	slot := &c.downCache[i]
	if slot.valid && slot.left == pair.Left && slot.right == pair.Right && slot.context == pair.Context {
		value := slot.value
		value.Entry.Segments = []string{slot.sid}
		return value, nil
	}
	*slot = downlinkProjection{}
	value, err := mup.BuildDownlink(pair, c.downContext)
	if err == nil && len(value.Entry.Segments) == 1 {
		*slot = downlinkProjection{left: pair.Left, right: pair.Right, context: pair.Context,
			value: value, sid: value.Entry.Segments[0], valid: true}
		// The client owns its output slices, including on the first cache miss.
		slot.value.Entry.Segments = nil
	}
	return value, err
}
