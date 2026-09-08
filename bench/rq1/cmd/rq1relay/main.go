//go:build bench

// Command rq1relay is the third arm of RQ1: a BGP speaker that runs outside the
// forwarding node and pushes what it learns in over RPC.
//
// The other two arms bound the question from either side. One has the speaker
// inside the process that owns the table, so a learned route becomes data plane
// state without crossing anything. The other skips the protocol entirely and
// measures the crossing on its own. This one is the combination a deployment
// actually ships when the speaker is a separate daemon: the protocol runs, and
// then its result crosses a process boundary.
//
// The speaker is Vinbero's own session package, the same one the in-process arm
// uses, so the two differ in where the speaker runs rather than in what it is.
// The translation from a VPN route to a headend entry is done here because that
// is the point of the design: the forwarding node exposes a table, and whoever
// holds the speaker decides what goes in it.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"go.uber.org/zap"
	"golang.org/x/net/http2"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/api/vinbero/v1/vinberov1connect"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bgp/gobgp"
)

func main() {
	fs := flag.NewFlagSet("rq1relay", flag.ExitOnError)
	neighbor := fs.String("neighbor", "", "address of the churn source")
	localASN := fs.Uint("local-asn", 65100, "our AS number")
	peerASN := fs.Uint("peer-asn", 65100, "the neighbor's AS number")
	routerID := fs.String("router-id", "10.255.0.1", "our BGP router id")
	listenPort := fs.Int("listen-port", 179, "TCP port to bind; -1 disables the listener")
	passive := fs.Bool("passive", true, "wait for the neighbor to dial in")
	rpcAddr := fs.String("rpc", "127.0.0.1:18081", "address of the forwarding node's RPC")
	encapSrc := fs.String("encap-src", "fd00:100::", "outer source address written into the entry")
	hold := fs.Duration("hold", 0, "how long to stay up; 0 waits for a signal")
	_ = fs.Parse(os.Args[1:])

	if *neighbor == "" {
		fatal("rq1relay needs -neighbor")
	}

	ctx := context.Background()
	client := vinberov1connect.NewHeadendv4ServiceClient(
		&http.Client{
			Transport: &http2.Transport{
				AllowHTTP: true,
				DialTLSContext: func(ctx context.Context, network, a string, _ *tls.Config) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, network, a)
				},
			},
		},
		"http://"+*rpcAddr,
	)

	// Establish the connection before any route can arrive, so the first
	// update does not pay for the handshake. A speaker that has been up for
	// a while would have a warm session too.
	if _, err := client.Headendv4List(ctx, connect.NewRequest(&v1.Headendv4ListRequest{})); err != nil {
		fatal("reach the forwarding node: %v", err)
	}

	session := gobgp.NewSession(zap.NewNop())
	if err := session.Start(ctx, bgp.GlobalConfig{
		LocalASN:   uint32(*localASN),
		RouterID:   *routerID,
		ListenPort: int32(*listenPort),
	}); err != nil {
		fatal("start speaker: %v", err)
	}
	defer func() { _ = session.Stop(ctx) }()

	cancel, err := session.Subscribe(bgp.FamilyVPNv4, func(ev bgp.RouteEvent) {
		if ev.VPN == nil {
			return
		}
		r := *ev.VPN
		if ev.IsWithdraw {
			req := &v1.Headendv4DeleteRequest{TriggerPrefixes: []string{r.Prefix}}
			if _, err := client.Headendv4Delete(ctx, connect.NewRequest(req)); err != nil {
				fmt.Fprintf(os.Stderr, "rq1relay: withdraw %s: %v\n", r.Prefix, err)
			}
			return
		}
		req := &v1.Headendv4CreateRequest{
			Headendv4S: []*v1.Headendv4{
				{
					TriggerPrefix: r.Prefix,
					Mode:          v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS,
					SrcAddr:       *encapSrc,
					DstAddr:       r.SRv6SID,
					Segments:      []string{r.SRv6SID},
				},
			},
		}
		if _, err := client.Headendv4Create(ctx, connect.NewRequest(req)); err != nil {
			fmt.Fprintf(os.Stderr, "rq1relay: install %s: %v\n", r.Prefix, err)
		}
	})
	if err != nil {
		fatal("subscribe: %v", err)
	}
	defer cancel()

	if err := session.AddPeer(ctx, bgp.PeerConfig{
		Neighbor:        *neighbor,
		PeerASN:         uint32(*peerASN),
		HoldTimeSec:     30,
		KeepaliveSec:    10,
		Families:        []bgp.Family{bgp.FamilyVPNv4},
		Passive:         *passive,
		ConnectRetrySec: 2,
	}); err != nil {
		fatal("add peer: %v", err)
	}

	fmt.Fprintln(os.Stderr, "ready")

	if *hold > 0 {
		time.Sleep(*hold)
		return
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "rq1relay: "+format+"\n", args...)
	os.Exit(1)
}
