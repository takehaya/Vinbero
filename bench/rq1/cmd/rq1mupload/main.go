//go:build bench

// rq1mupload offers bounded MUP updates to a real BGP peer. API call times are
// source-side bounds, not receiver enqueue or application timestamps.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bgp/gobgp"
	"go.uber.org/zap"
)

type config struct {
	neighbor, nextHop, base, startFile, stopFile, log, expected string
	sessions, rate, burst                                       int
	duration, hold, readyTimeout                                time.Duration
}

type event struct {
	Kind       string `json:"kind"`
	RouteType  string `json:"route_type"`
	Initial    bool   `json:"initial,omitempty"`
	Tag        int    `json:"tag"`
	Index      int    `json:"index"`
	Version    int    `json:"version"`
	Prefix     string `json:"prefix"`
	TEID       uint32 `json:"teid,omitempty"`
	SID        string `json:"sid,omitempty"`
	PlannedNS  int64  `json:"planned_ns"`
	DecisionNS int64  `json:"decision_ns"`
	StartNS    int64  `json:"start_ns"`
	EndNS      int64  `json:"end_ns"`
	Error      string `json:"err"`
}

type sessionState struct {
	Prefix  string `json:"prefix"`
	TEID    uint32 `json:"teid"`
	Version int    `json:"successful_updates"`
}

// Only the update goroutine changes Sessions; only the sentinel goroutine
// changes Sentinel. A join precedes reading either for the final oracle.
type expectedState struct {
	Complete        bool           `json:"complete"`
	Error           string         `json:"error"`
	StartNS         int64          `json:"start_ns"`
	EndNS           int64          `json:"end_ns"`
	Rate            int            `json:"rate"`
	Burst           int            `json:"burst"`
	DurationNS      int64          `json:"duration_ns"`
	Sessions        []sessionState `json:"sessions"`
	SentinelSID     string         `json:"sentinel_sid"`
	SentinelVersion int            `json:"sentinel_successful_updates"`
}

type recorder struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func (r *recorder) write(e event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.enc.Encode(e) // Direct file writes: no user-space buffer to flush.
}

func prefixes(base string, count int) ([]sessionState, error) {
	addr, err := netip.ParseAddr(base)
	if err != nil || !addr.Is4() || count < 1 {
		return nil, fmt.Errorf("base-address must be IPv4 and count positive")
	}
	result := make([]sessionState, count)
	for i := range result {
		if !addr.IsValid() || !addr.Is4() {
			return nil, fmt.Errorf("IPv4 address range overflows at session %d", i)
		}
		result[i] = sessionState{Prefix: netip.PrefixFrom(addr, 32).String(), TEID: uint32(256 + i)}
		addr = addr.Next()
	}
	return result, nil
}

func nextTEID(index, successfulUpdates int) uint32 {
	if successfulUpdates%2 == 0 {
		return uint32(1048576 + index)
	}
	return uint32(2097152 + index)
}

// A late slot is skipped, including equality at the next slot's boundary.
// Advancing the loop index never replays the missed slot as a catch-up burst.
func slot(start time.Time, index, rate int, duration time.Duration, now time.Time) (time.Time, bool) {
	planned := start.Add(time.Duration(index) * time.Second / time.Duration(rate))
	deadline := start.Add(time.Duration(index+1) * time.Second / time.Duration(rate))
	if end := start.Add(duration); deadline.After(end) {
		deadline = end
	}
	return planned, !now.Before(deadline)
}

func waitUntil(ctx context.Context, at time.Time) error {
	timer := time.NewTimer(time.Until(at))
	defer timer.Stop()
	select {
	case <-timer.C:
		return ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func awaitStart(ctx context.Context, path string, timeout time.Duration) (time.Time, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(path)
		if err == nil {
			ns, e := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
			at := time.Unix(0, ns)
			if e != nil || !at.After(time.Now()) {
				return time.Time{}, fmt.Errorf("start-file must contain future Unix nanoseconds")
			}
			return at, nil
		}
		if !os.IsNotExist(err) {
			return time.Time{}, err
		}
		if err := waitUntil(ctx, time.Now().Add(10*time.Millisecond)); err != nil {
			return time.Time{}, err
		}
	}
	return time.Time{}, fmt.Errorf("start-file readiness deadline expired")
}

func saveExpected(path string, state *expectedState) error {
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path+".tmp", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(append(raw, '\n'))
	syncErr, closeErr := f.Sync(), f.Close()
	if err = errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

// The MUP BGP key excludes TEID. GoBGP's path comparison also excludes
// MP_REACH_NLRI, so a changing test-only RT makes each TEID replacement visible.
// The controller is still authorized and matched by the unchanged primary RT.
func st1Route(prefix string, teid uint32, version int, nextHop string) bgp.MUPRoute {
	rts := []string{"65000:7"}
	if version > 0 {
		rts = append(rts, fmt.Sprintf("65000:%d", 1000+(version-1)%2))
	}
	return bgp.MUPRoute{Type: bgp.MUPRouteTypeT1ST, RD: "65000:7", RTs: rts, Prefix: prefix,
		TEID: teid, TEIDLen: 32, QFI: 9, Endpoint: "172.16.0.1", NextHop: nextHop}
}

func sentinelRoute(sid, nextHop string) bgp.VPNRoute {
	return bgp.VPNRoute{Family: bgp.FamilyVPNv4, Prefix: "10.250.0.1/32", RD: "65100:100",
		RTs: []string{"65100:100"}, SRv6SID: sid, NextHop: nextHop, EndpointBehavior: 65025}
}

func run(ctx context.Context, c config) (retErr error) {
	if c.sessions != 64 && c.sessions != 512 {
		return fmt.Errorf("sessions must be 64 or 512")
	}
	if (c.rate != 10 && c.rate != 50 && c.rate != 200) && c.burst != 512 || c.rate != 0 && c.burst != 0 || c.burst != 0 && c.burst != 512 {
		return fmt.Errorf("select rate 10/50/200 or burst 512, exclusively")
	}
	if c.duration < time.Second || c.duration > time.Minute || c.hold <= 0 || c.readyTimeout <= 0 {
		return fmt.Errorf("duration must be 1s..60s; hold and ready-timeout must be positive")
	}
	if c.neighbor == "" || c.nextHop == "" || c.startFile == "" || c.log == "" || c.expected == "" {
		return fmt.Errorf("neighbor, next-hop, start-file, log and expected are required")
	}
	paths := make(map[string]bool)
	for _, path := range []string{c.startFile, c.stopFile, c.log, c.expected, c.expected + ".tmp"} {
		if path == "" {
			continue
		}
		abs, err := filepath.Abs(path)
		if err != nil || paths[abs] {
			return fmt.Errorf("control and output paths must be distinct: %s", path)
		}
		paths[abs] = true
	}
	for _, path := range []string{c.expected, c.expected + ".tmp", c.stopFile} {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			return fmt.Errorf("output/stop path must not exist: %s", path)
		}
	}
	routes, err := prefixes(c.base, c.sessions)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(c.log, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	record := &recorder{enc: json.NewEncoder(file)}
	state := expectedState{Sessions: routes, Rate: c.rate, Burst: c.burst, DurationNS: int64(c.duration)}
	saved := false
	defer func() {
		if !saved {
			state.Error = fmt.Sprint(retErr)
			state.EndNS = time.Now().UnixNano()
			retErr = errors.Join(retErr, saveExpected(c.expected, &state))
		}
		retErr = errors.Join(retErr, file.Sync())
	}()
	speaker := gobgp.NewSession(zap.NewNop())
	if err := speaker.Start(ctx, bgp.GlobalConfig{LocalASN: 65100, RouterID: "10.255.0.2", ListenPort: -1}); err != nil {
		return err
	}
	defer speaker.Stop(context.Background())
	if err := speaker.AddPeer(ctx, bgp.PeerConfig{Neighbor: c.neighbor, PeerASN: 65100,
		Families: []bgp.Family{bgp.FamilyMUPIPv4, bgp.FamilyVPNv4}, HoldTimeSec: 30, KeepaliveSec: 10, ConnectRetrySec: 2}); err != nil {
		return err
	}
	st1 := func(prefix string, teid uint32, version int) error {
		return speaker.PushMUPT1ST(ctx, st1Route(prefix, teid, version, c.nextHop))
	}
	vpn := func(sid string) error {
		return speaker.Advertise(ctx, sentinelRoute(sid, c.nextHop))
	}
	call := func(e event, fn func() error) error {
		e.StartNS = time.Now().UnixNano()
		err := fn()
		e.EndNS = time.Now().UnixNano()
		if err != nil {
			e.Error = err.Error()
		}
		return errors.Join(err, record.write(e))
	}
	for i, r := range routes {
		if err := call(event{Kind: "initial", Initial: true, RouteType: "st1", Index: i, Prefix: r.Prefix, TEID: r.TEID, DecisionNS: time.Now().UnixNano()}, func() error { return st1(r.Prefix, r.TEID, 0) }); err != nil {
			return err
		}
	}
	if err := call(event{Kind: "initial", Initial: true, RouteType: "isd", Index: -1, Prefix: "172.16.0.0/24", SID: "fd00:a:0:100::", DecisionNS: time.Now().UnixNano()}, func() error {
		return speaker.PushMUPISD(ctx, bgp.MUPRoute{Type: bgp.MUPRouteTypeISD, RD: "65000:7", RTs: []string{"65000:7"}, Prefix: "172.16.0.0/24",
			SRv6SID: "fd00:a:0:100::", NextHop: c.nextHop, SIDStructure: bgp.SIDStructure{LocatorBlockLen: 32, LocatorNodeLen: 16, FunctionLen: 8, ArgumentLen: 72}})
	}); err != nil {
		return err
	}
	if err := call(event{Kind: "sentinel", Initial: true, RouteType: "vpn", Index: -1, Prefix: "10.250.0.1/32", SID: "fd00:a::100", DecisionNS: time.Now().UnixNano()}, func() error { return vpn("fd00:a::100") }); err != nil {
		return err
	}
	state.SentinelSID = "fd00:a::100"
	fmt.Fprintln(os.Stderr, "ready: initial advertisements submitted; driver must gate receiver maps")
	start, err := awaitStart(ctx, c.startFile, c.readyTimeout)
	if err != nil {
		return err
	}
	state.StartNS = start.UnixNano()
	active := c.duration
	if c.burst != 0 {
		active = 3 * time.Second
	}
	state.DurationNS = int64(active)
	// Independent schedules prevent a blocked MUP advertise from serializing
	// sentinel emission in the instrument itself. Both still share one BGP peer.
	sentinelDone := make(chan error, 1)
	go func() {
		var errs error
		for i := 0; time.Duration(i)*time.Second < active; i++ {
			planned, _ := slot(start, i, 1, active, start)
			if err := waitUntil(ctx, planned); err != nil {
				sentinelDone <- errors.Join(errs, err)
				return
			}
			now := time.Now()
			_, late := slot(start, i, 1, active, now)
			sid := "fd00:b::100"
			if state.SentinelVersion%2 == 1 {
				sid = "fd00:a::100"
			}
			e := event{Kind: "sentinel", RouteType: "vpn", Tag: i + 1, Index: -1, Version: state.SentinelVersion + 1, Prefix: "10.250.0.1/32", SID: sid, PlannedNS: planned.UnixNano(), DecisionNS: now.UnixNano()}
			if late {
				e.Kind = "skipped"
				errs = errors.Join(errs, record.write(e))
				continue
			}
			if err := call(e, func() error { return vpn(sid) }); err != nil {
				errs = errors.Join(errs, err)
			} else {
				state.SentinelSID, state.SentinelVersion = sid, state.SentinelVersion+1
			}
		}
		sentinelDone <- errs
	}()
	slots := c.burst
	if c.rate > 0 {
		slots = int((int64(c.duration)*int64(c.rate) + int64(time.Second) - 1) / int64(time.Second))
	}
	var loadErr error
	for i := 0; i < slots; i++ {
		planned := start
		if c.rate > 0 {
			planned, _ = slot(start, i, c.rate, active, start)
		}
		if err := waitUntil(ctx, planned); err != nil {
			loadErr = errors.Join(loadErr, err)
			break
		}
		now := time.Now()
		index := i % len(routes)
		r := &routes[index]
		teid := nextTEID(index, r.Version)
		e := event{Kind: "update", RouteType: "st1", Tag: i + 1, Index: index, Version: r.Version + 1, Prefix: r.Prefix, TEID: teid, PlannedNS: planned.UnixNano(), DecisionNS: now.UnixNano()}
		if c.rate > 0 {
			if _, late := slot(start, i, c.rate, active, now); late {
				e.Kind = "skipped"
				loadErr = errors.Join(loadErr, record.write(e))
				continue
			}
		}
		if err := call(e, func() error { return st1(r.Prefix, teid, r.Version+1) }); err != nil {
			loadErr = errors.Join(loadErr, err)
		} else {
			r.TEID, r.Version = teid, r.Version+1
		}
	}
	loadErr = errors.Join(loadErr, <-sentinelDone, waitUntil(ctx, start.Add(active)))
	state.EndNS, state.Complete = time.Now().UnixNano(), loadErr == nil
	if loadErr != nil {
		state.Error = loadErr.Error()
	}
	if err := saveExpected(c.expected, &state); err != nil {
		return errors.Join(loadErr, err)
	}
	saved = true
	fmt.Fprintln(os.Stderr, "load_complete: expected state saved; BGP session held")
	deadline := time.Now().Add(c.hold)
	for time.Now().Before(deadline) {
		if c.stopFile != "" {
			if _, err := os.Stat(c.stopFile); err == nil {
				return loadErr
			} else if !os.IsNotExist(err) {
				return errors.Join(loadErr, err)
			}
		}
		if err := waitUntil(ctx, time.Now().Add(20*time.Millisecond)); err != nil {
			return errors.Join(loadErr, err)
		}
	}
	if c.stopFile != "" {
		return errors.Join(loadErr, fmt.Errorf("stop-file hold deadline expired"))
	}
	return loadErr
}

func main() {
	var c config
	flag.StringVar(&c.neighbor, "neighbor", "", "receiver BGP peer address (AS 65100)")
	flag.StringVar(&c.nextHop, "next-hop", "", "speaker next-hop address")
	flag.StringVar(&c.base, "base-address", "10.0.2.2", "first IPv4 session address; following /32s are consecutive")
	flag.IntVar(&c.sessions, "sessions", 64, "64 or 512 initial ST1 sessions")
	flag.IntVar(&c.rate, "rate", 0, "10, 50 or 200 ST1 updates/s; excludes burst")
	flag.IntVar(&c.burst, "burst", 0, "512 immediate ST1 updates; excludes rate; sentinel remains active for 3s")
	flag.DurationVar(&c.duration, "duration", 10*time.Second, "rate load duration, 1s..60s")
	flag.StringVar(&c.startFile, "start-file", "", "driver atomically publishes future Unix nanoseconds after readiness")
	flag.DurationVar(&c.readyTimeout, "ready-timeout", 2*time.Minute, "maximum wait for start-file")
	flag.StringVar(&c.stopFile, "stop-file", "", "driver creates this file after drain/state checks; must not already exist")
	flag.DurationVar(&c.hold, "hold", 120*time.Second, "maximum session hold after expected state is saved")
	flag.StringVar(&c.log, "log", "", "new JSONL event log")
	flag.StringVar(&c.expected, "expected", "", "new atomic JSON of final speaker-accepted state, not receiver state")
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, c); err != nil {
		fmt.Fprintln(os.Stderr, "rq1mupload:", err)
		os.Exit(1)
	}
}
