//go:build bench

package main

import (
	"context"
	"fmt"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/api/vinbero/v1/vinberov1connect"
	"github.com/takehaya/vinbero/pkg/bgp"
)

// Preserve callback order without blocking GoBGP's delivery goroutine. A
// backlog overflow or failed write invalidates the measurement, rather than
// silently dropping an update and reporting a shorter convergence time.
type relayWorker struct {
	queue  chan bgp.RouteEvent
	failed chan error
	done   chan struct{}
	cancel context.CancelFunc
}

func newRelayWorker(ctx context.Context, depth int, apply func(context.Context, bgp.RouteEvent) error) *relayWorker {
	ctx, cancel := context.WithCancel(ctx)
	w := &relayWorker{queue: make(chan bgp.RouteEvent, depth), failed: make(chan error, 1), done: make(chan struct{}), cancel: cancel}
	go func() {
		defer close(w.done)
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-w.queue:
				callCtx, release := context.WithTimeout(ctx, 5*time.Second)
				err := apply(callCtx, ev)
				release()
				if err != nil {
					w.fail(err)
					return
				}
			}
		}
	}()
	return w
}

func (w *relayWorker) submit(ev bgp.RouteEvent) {
	if ev.VPN == nil {
		return
	}
	// Only immutable route strings are used by the RPC worker. Copy the route
	// value so its pointer need not remain owned by the callback.
	route := *ev.VPN
	ev.VPN = &route
	select {
	case w.queue <- ev:
	default:
		w.fail(fmt.Errorf("relay queue is full"))
	}
}

func (w *relayWorker) fail(err error) {
	select {
	case w.failed <- err:
	default:
	}
	w.cancel()
}

func (w *relayWorker) close() {
	w.cancel()
	<-w.done
}

func applyRoute(ctx context.Context, client vinberov1connect.Headendv4ServiceClient, source string, ev bgp.RouteEvent) error {
	r := ev.VPN
	var operationErrors []*v1.OperationError
	if ev.IsWithdraw {
		resp, err := client.Headendv4Delete(ctx, connect.NewRequest(&v1.Headendv4DeleteRequest{TriggerPrefixes: []string{r.Prefix}}))
		if err != nil {
			return fmt.Errorf("withdraw %s: %w", r.Prefix, err)
		}
		operationErrors = resp.Msg.Errors
	} else {
		resp, err := client.Headendv4Create(ctx, connect.NewRequest(&v1.Headendv4CreateRequest{Headendv4S: []*v1.Headendv4{{
			TriggerPrefix: r.Prefix,
			Mode:          v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS,
			SrcAddr:       source, DstAddr: r.SRv6SID, Segments: []string{r.SRv6SID},
		}}}))
		if err != nil {
			return fmt.Errorf("install %s: %w", r.Prefix, err)
		}
		operationErrors = resp.Msg.Errors
	}
	if len(operationErrors) != 0 {
		return fmt.Errorf("reflect %s: %v", r.Prefix, operationErrors)
	}
	return nil
}
