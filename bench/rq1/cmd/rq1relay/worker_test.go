//go:build bench

package main

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/api/vinbero/v1/vinberov1connect"
	"github.com/takehaya/vinbero/pkg/bgp"
)

func event(prefix string) bgp.RouteEvent {
	return bgp.RouteEvent{VPN: &bgp.VPNRoute{Prefix: prefix, SRv6SID: "fd00::1"}}
}

func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(time.Second):
		t.Fatal("worker did not make progress")
		var zero T
		return zero
	}
}

func TestRelayWorkerPreservesOrderWithoutBlockingCallback(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	applied := make(chan string, 3)
	w := newRelayWorker(context.Background(), 2, func(ctx context.Context, ev bgp.RouteEvent) error {
		if ev.VPN.Prefix == "first" {
			started <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		applied <- ev.VPN.Prefix
		return nil
	})
	defer w.close()
	w.submit(event("first"))
	receive(t, started)
	submitted := make(chan struct{})
	go func() { w.submit(event("second")); w.submit(event("third")); close(submitted) }()
	receive(t, submitted) // still waiting on the first RPC
	close(release)
	for _, want := range []string{"first", "second", "third"} {
		if got := receive(t, applied); got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}

func TestRelayWorkerRejectsOverflowAndWriteFailure(t *testing.T) {
	started := make(chan struct{}, 1)
	w := newRelayWorker(context.Background(), 1, func(ctx context.Context, _ bgp.RouteEvent) error {
		started <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	})
	w.submit(event("first"))
	receive(t, started)
	w.submit(event("queued"))
	w.submit(event("overflow"))
	if err := receive(t, w.failed); err == nil {
		t.Fatal("overflow was ignored")
	}
	w.close()
	want := errors.New("write failed")
	w = newRelayWorker(context.Background(), 1, func(context.Context, bgp.RouteEvent) error { return want })
	defer w.close()
	w.submit(event("prefix"))
	if err := receive(t, w.failed); !errors.Is(err, want) {
		t.Fatalf("write failure: %v", err)
	}
}

type rejectedWrites struct {
	vinberov1connect.UnimplementedHeadendv4ServiceHandler
}

func (rejectedWrites) Headendv4Create(context.Context, *connect.Request[v1.Headendv4CreateRequest]) (*connect.Response[v1.Headendv4CreateResponse], error) {
	return connect.NewResponse(&v1.Headendv4CreateResponse{Errors: []*v1.OperationError{{Reason: "owner conflict"}}}), nil
}

func (rejectedWrites) Headendv4Delete(context.Context, *connect.Request[v1.Headendv4DeleteRequest]) (*connect.Response[v1.Headendv4DeleteResponse], error) {
	return connect.NewResponse(&v1.Headendv4DeleteResponse{Errors: []*v1.OperationError{{Reason: "delete refused"}}}), nil
}

func TestRelayRejectsOperationErrorsInSuccessfulRPC(t *testing.T) {
	_, handler := vinberov1connect.NewHeadendv4ServiceHandler(rejectedWrites{})
	srv := httptest.NewServer(handler)
	defer srv.Close()
	client := vinberov1connect.NewHeadendv4ServiceClient(srv.Client(), srv.URL)
	for _, withdraw := range []bool{false, true} {
		ev := event("10.0.2.0/24")
		ev.IsWithdraw = withdraw
		if err := applyRoute(context.Background(), client, "fd00:100::", ev); err == nil {
			t.Fatalf("withdraw=%v: ignored operation error", withdraw)
		}
	}
}
