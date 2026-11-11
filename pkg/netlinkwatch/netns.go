package netlinkwatch

import (
	"runtime"

	"github.com/vishvananda/netns"
)

// enterNetns locks the calling goroutine to its thread and moves the thread
// to ns unless it is there already, so the netlink calls made on it (a
// resubscribe, a dump) act on ns. The thread is never unlocked: it ends with
// the goroutine.
func enterNetns(ns netns.NsHandle) error {
	runtime.LockOSThread()
	cur, err := netns.Get()
	if err != nil {
		return err
	}
	defer func() { _ = cur.Close() }()
	if cur.Equal(ns) {
		return nil
	}
	return netns.Set(ns)
}

// drain reads ch until it is closed, which lets a subscription's reader that
// blocks on a full channel see its closed socket and end.
func drain[T any](ch <-chan T) {
	for range ch {
	}
}
