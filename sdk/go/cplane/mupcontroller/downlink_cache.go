package mupcontroller

import (
	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/mup"
	"github.com/takehaya/vinbero/sdk/go/cplane/resolve"
)

// This memoizes only the pure builder, after fresh resolution on every update.
// A changed result position is a miss; dependency and ambiguity checks stay live.
//
// The key is every input of mup.BuildDownlink: the pair's Left, Right and
// Context, plus the operator's downlink context. All are plain comparable
// values, so == is an exact match. Revision and the path lists are not
// keys because the builder never reads them.
//
// The downlink context is fixed for a controller's lifetime today (a config
// change builds a new controller with an empty cache), so keying on it never
// changes a hit. It is keyed anyway so that applying configuration in place
// cannot silently return a headend built from a stale source or ArgsOffset.
type downlinkProjection struct {
	left    mup.ST1
	right   mup.ISD
	context string
	config  mup.DownlinkContext
	value   cplane.ForwardingHeadend
	sid     string
	valid   bool
}

func (c *Controller) buildDownlink(i int, pair resolve.Pair[mup.ST1, mup.ISD]) (cplane.ForwardingHeadend, error) {
	slot := &c.downCache[i]
	if slot.valid && slot.left == pair.Left && slot.right == pair.Right && slot.context == pair.Context && slot.config == c.downContext {
		value := slot.value
		value.Entry.Segments = []string{slot.sid}
		return value, nil
	}
	*slot = downlinkProjection{}
	value, err := mup.BuildDownlink(pair, c.downContext)
	if err == nil && len(value.Entry.Segments) == 1 {
		*slot = downlinkProjection{left: pair.Left, right: pair.Right, context: pair.Context, config: c.downContext,
			value: value, sid: value.Entry.Segments[0], valid: true}
		// The client owns its output slices, including on the first cache miss.
		slot.value.Entry.Segments = nil
	}
	return value, err
}
