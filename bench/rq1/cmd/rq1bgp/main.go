//go:build bench

// Command rq1bgp is the churn source for the BGP arm of RQ1.
//
// Until now the measurement moved a headend entry directly, which isolates the
// boundary being studied but skips the protocol that feeds it. This command
// peers with the node under test and moves the route by advertising it, so the
// measured path is the one the thesis actually claims: a BGP UPDATE arrives,
// the reflection path turns it into data plane state, and traffic follows.
//
// The speaker is Vinbero's own gobgp session rather than a separate BGP
// implementation. That is deliberate: the control the experiment needs is that
// every arm runs the same speaker, and reusing the same package makes that true
// by construction instead of by configuration.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bgp/gobgp"
)

func main() {
	fs := flag.NewFlagSet("rq1bgp", flag.ExitOnError)
	neighbor := fs.String("neighbor", "", "address of the node under test")
	localASN := fs.Uint("local-asn", 65100, "our AS number")
	peerASN := fs.Uint("peer-asn", 65100, "the neighbor's AS number")
	routerID := fs.String("router-id", "10.255.0.2", "our BGP router id")
	listenPort := fs.Int("listen-port", -1, "TCP port to bind; -1 disables the listener")
	prefix := fs.String("prefix", "10.0.2.0/24", "VPN prefix to advertise")
	rd := fs.String("rd", "65100:100", "route distinguisher")
	rts := fs.String("rts", "65100:100", "route target")
	nextHop := fs.String("next-hop", "", "BGP next hop")
	initialSID := fs.String("initial-sid", "", "service SID advertised first")
	changeTo := fs.String("change-to", "", "service SID advertised at the change instant")
	changeAt := fs.Int64("change-at", 0, "unix nanoseconds at which to advertise the second SID")
	changeFile := fs.String("change-file", "", "wait for a file containing the change timestamp, after initial forwarding is ready")
	readyTimeout := fs.Duration("ready-timeout", time.Minute, "maximum wait for -change-file")
	behavior := fs.Uint("behavior", 0, "SRv6 endpoint behavior; 0 uses the standard family default")
	settle := fs.Duration("settle", 8*time.Second, "how long to let the session settle before the change")
	hold := fs.Duration("hold", 6*time.Second, "how long to stay up after the change")
	_ = fs.Parse(os.Args[1:])

	if *neighbor == "" || *nextHop == "" || *initialSID == "" {
		fatal("rq1bgp needs -neighbor, -next-hop and -initial-sid")
	}
	if *behavior > 65535 || (*changeFile != "" && (*changeAt != 0 || *changeTo == "" || *readyTimeout <= 0)) {
		fatal("invalid behavior or change-file options")
	}

	ctx := context.Background()
	logger := zap.NewNop()
	session := gobgp.NewSession(logger)

	if err := session.Start(ctx, bgp.GlobalConfig{
		LocalASN:   uint32(*localASN),
		RouterID:   *routerID,
		ListenPort: int32(*listenPort),
	}); err != nil {
		fatal("start speaker: %v", err)
	}
	defer func() { _ = session.Stop(ctx) }()

	// A short connect retry keeps a first attempt that lands before the peer
	// is listening from costing the default two minutes.
	if err := session.AddPeer(ctx, bgp.PeerConfig{
		Neighbor:        *neighbor,
		PeerASN:         uint32(*peerASN),
		HoldTimeSec:     30,
		KeepaliveSec:    10,
		Families:        []bgp.Family{bgp.FamilyVPNv4},
		ConnectRetrySec: 2,
	}); err != nil {
		fatal("add peer: %v", err)
	}

	route := func(sid string) bgp.VPNRoute {
		return bgp.VPNRoute{
			Family:           bgp.FamilyVPNv4,
			Prefix:           *prefix,
			RD:               *rd,
			RTs:              []string{*rts},
			SRv6SID:          sid,
			NextHop:          *nextHop,
			EndpointBehavior: uint16(*behavior),
		}
	}

	if err := session.Advertise(ctx, route(*initialSID)); err != nil {
		fatal("advertise initial: %v", err)
	}

	// Let the session establish and the first route settle into the data
	// plane before anything is timed.
	if *changeFile == "" {
		time.Sleep(*settle)
	} else {
		var err error
		*changeAt, err = awaitChange(*changeFile, *readyTimeout)
		if err != nil {
			fatal("wait for measurement readiness: %v", err)
		}
	}
	fmt.Fprintln(os.Stderr, "ready")

	if *changeTo != "" {
		next := route(*changeTo)
		if *changeAt > 0 {
			for time.Now().UnixNano() < *changeAt {
				remaining := *changeAt - time.Now().UnixNano()
				if remaining > int64(time.Millisecond) {
					time.Sleep(time.Duration(remaining / 2))
				}
			}
		}
		// Stamp before handing the route to the speaker. Everything after
		// this point, including the speaker's own encoding and the TCP
		// write, is part of what the reflection path costs.
		stamp := time.Now().UnixNano()
		if err := session.Advertise(ctx, next); err != nil {
			fatal("advertise change: %v", err)
		}
		fmt.Printf("change_ns=%d\n", stamp)
	}

	time.Sleep(*hold)
}

// The driver publishes the timestamp with rename only after verifying the
// initial map and starting both receivers. A slow startup cannot consume the
// measurement window or silently turn initial convergence into update latency.
func awaitChange(path string, timeout time.Duration) (int64, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			ns, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
			if err != nil || ns <= time.Now().UnixNano() {
				return 0, fmt.Errorf("change timestamp must be in the future")
			}
			return ns, nil
		}
		if !os.IsNotExist(err) {
			return 0, err
		}
		time.Sleep(10 * time.Millisecond)
	}
	return 0, fmt.Errorf("timed out waiting for %s", path)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "rq1bgp: "+format+"\n", args...)
	os.Exit(1)
}
