package apply

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"go.uber.org/zap"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bgp/demux"
	"github.com/takehaya/vinbero/pkg/bgp/gobgp"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// Loopback port the Vinbero PE of the session test below listens on. It must
// not collide with the ports other packages' tests listen on.
const attrPE2ListenPort = 10196

// The uDT4 SID FRR advertises with `format usid-f3216`: the wire carries the
// block+node only, the function uSID (0x0001) travels in the high 16 bits of
// the 20-bit VPN label (label 16), and the SID Structure is 32/16/16/0 with
// transposition length 16 at offset 48.
const (
	frrWireSID       = "fd00:200:2::"
	frrFullSID       = "fd00:200:2:1::"
	frrFuncLabel     = 1 << (20 - 16) // function 1 in the top 16 label bits
	implicitNullLbl  = 3              // MPLS implicit null: top 16 bits are 0
	frrUDT4Behavior  = 0x003F         // End.DT4 with NEXT-C-SID
	frrUSIDNextHop   = "2001:db8:ff::2"
	attrUpdateWaitTO = 20 * time.Second
)

// programmedEntry is the trigger entry of one prefix after an applied event.
type programmedEntry struct {
	prefix string
	sid    string // "" when the prefix has no entry
	mode   uint8
}

// frrVPNUpdate is an UPDATE for one VPNv4 route the way FRR's usid-f3216
// export builds it, carrying label as the VPN label. withStructure false
// leaves out the SID Structure Sub-Sub-TLV, so no transposition is signalled.
func frrVPNUpdate(t *testing.T, prefix string, label uint32, withStructure bool) *gobgppkt.BGPMessage {
	t.Helper()
	rd := gobgppkt.NewRouteDistinguisherTwoOctetAS(65200, 200)
	nlri, err := gobgppkt.NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix(prefix), *gobgppkt.NewMPLSLabelStack(label), rd)
	if err != nil {
		t.Fatalf("build VPNv4 NLRI: %v", err)
	}
	var subs []gobgppkt.PrefixSIDTLVInterface
	if withStructure {
		subs = append(subs, gobgppkt.NewSRv6SIDStructureSubSubTLV(32, 16, 16, 0, 16, 48))
	}
	info := gobgppkt.NewSRv6InformationSubTLV(netip.MustParseAddr(frrWireSID), gobgppkt.SRBehavior(frrUDT4Behavior), subs...)
	psid := gobgppkt.NewPathAttributePrefixSID(gobgppkt.NewSRv6ServiceTLV(gobgppkt.TLVTypeSRv6L3Service, info))
	rt := gobgppkt.NewTwoOctetAsSpecificExtended(gobgppkt.EC_SUBTYPE_ROUTE_TARGET, 65000, 200, true)
	mpReach, err := gobgppkt.NewPathAttributeMpReachNLRI(
		gobgppkt.RF_IPv4_VPN, []gobgppkt.PathNLRI{{NLRI: nlri}}, netip.MustParseAddr(frrUSIDNextHop))
	if err != nil {
		t.Fatalf("build MP_REACH_NLRI: %v", err)
	}
	return gobgppkt.NewBGPUpdateMessage(nil, []gobgppkt.PathAttributeInterface{
		gobgppkt.NewPathAttributeOrigin(0),
		gobgppkt.NewPathAttributeAsPath(nil),
		gobgppkt.NewPathAttributeLocalPref(100),
		gobgppkt.NewPathAttributeExtendedCommunities([]gobgppkt.ExtendedCommunityInterface{rt}),
		psid,
		mpReach,
	}, nil)
}

// startAttrUpdatePipeline runs the daemon's receive path end to end over a
// real iBGP session: Vinbero's gobgp.Session subscribes through the demux and
// the built-in Applier writes into a fake data plane. The remote PE is a raw
// BGP speaker (rawSpeaker), so each UPDATE reaches the wire exactly as built.
// Every applied event reports the trigger entry of its prefix on the returned
// channel; the entry is read on the handler's goroutine, so the fake is never
// touched concurrently.
func startAttrUpdatePipeline(t *testing.T) (*rawSpeaker, <-chan programmedEntry) {
	t.Helper()
	ctx := context.Background()

	fh := newFakeHeadend()
	a := NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65100, zap.NewNop())
	programmed := make(chan programmedEntry, 256)

	pe2 := gobgp.NewSession(zap.NewNop())
	if err := pe2.Start(ctx, bgp.GlobalConfig{LocalASN: 65100, RouterID: "10.255.0.1", ListenPort: attrPE2ListenPort}); err != nil {
		t.Fatalf("PE2 Start: %v", err)
	}
	t.Cleanup(func() { _ = pe2.Stop(ctx) })
	if err := pe2.AddPeer(ctx, bgp.PeerConfig{
		Neighbor: "127.0.0.1", PeerASN: 65100,
		HoldTimeSec: 90, KeepaliveSec: 30, Passive: true,
		Families: []bgp.Family{bgp.FamilyVPNv4},
	}); err != nil {
		t.Fatalf("PE2 AddPeer: %v", err)
	}

	d := demux.New(pe2, pe2, zap.NewNop())
	d.SetVPNImportResolver(a.ImportVRFs)
	if _, err := d.RegisterBuiltin("applier", nil, func(ev bgp.RouteEvent) {
		a.Apply(ev)
		if ev.VPN == nil {
			return
		}
		got := programmedEntry{prefix: ev.VPN.Prefix}
		if e, ok := fh.v4created[ev.VPN.Prefix]; ok {
			got.sid = netip.AddrFrom16(e.DstAddr).String()
			got.mode = e.Mode
		}
		select {
		case programmed <- got:
		default:
			t.Errorf("programmed-entry channel full; dropped %+v", got)
		}
	}); err != nil {
		t.Fatalf("register applier: %v", err)
	}
	if err := d.Start(); err != nil {
		t.Fatalf("demux Start: %v", err)
	}
	t.Cleanup(d.Stop)

	pe1 := dialRawSpeaker(t, fmt.Sprintf("127.0.0.1:%d", attrPE2ListenPort))
	deadline := time.Now().Add(attrUpdateWaitTO)
	for {
		peers, err := pe2.Peers(ctx)
		if err == nil && len(peers) == 1 && peers[0].SessionState == "established" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("BGP session not ESTABLISHED within %s (peers %+v, err %v)", attrUpdateWaitTO, peers, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return pe1, programmed
}

// rawSpeaker is the remote PE: a minimal BGP speaker that writes UPDATEs as
// given. A gobgp speaker cannot stand in for FRR here: its best-path change
// check compares path attributes only (table.Path.Equal), so it never sends
// an UPDATE whose only change is the VPN label in the NLRI. FRR does.
type rawSpeaker struct {
	t    *testing.T
	conn net.Conn
	mu   sync.Mutex // serializes writes: UPDATEs and the keepalive loop
}

func dialRawSpeaker(t *testing.T, addr string) *rawSpeaker {
	t.Helper()
	var conn net.Conn
	var err error
	deadline := time.Now().Add(attrUpdateWaitTO)
	for {
		conn, err = net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial %s: %v", addr, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	s := &rawSpeaker{t: t, conn: conn}
	t.Cleanup(func() { _ = conn.Close() })

	caps := []gobgppkt.ParameterCapabilityInterface{
		gobgppkt.NewCapMultiProtocol(gobgppkt.RF_IPv4_VPN),
		gobgppkt.NewCapFourOctetASNumber(65100),
		// FRR's `capability extended-nexthop`: VPNv4 with an IPv6 next hop.
		gobgppkt.NewCapExtendedNexthop([]*gobgppkt.CapExtendedNexthopTuple{
			gobgppkt.NewCapExtendedNexthopTuple(gobgppkt.RF_IPv4_VPN, gobgppkt.AFI_IP6),
		}),
	}
	open, err := gobgppkt.NewBGPOpenMessage(65100, 90, netip.MustParseAddr("10.255.0.2"),
		[]gobgppkt.OptionParameterInterface{gobgppkt.NewOptionParameterCapability(caps)})
	if err != nil {
		t.Fatalf("build OPEN: %v", err)
	}
	s.send(open)
	s.send(gobgppkt.NewBGPKeepAliveMessage())
	// Drain what the receiver sends (its OPEN, KEEPALIVEs, End-of-RIB) so it
	// never blocks on a full socket, and keep the session alive.
	go func() {
		hdr := make([]byte, gobgppkt.BGP_HEADER_LENGTH)
		for {
			if _, err := io.ReadFull(conn, hdr); err != nil {
				return
			}
			n := int(binary.BigEndian.Uint16(hdr[16:18])) - gobgppkt.BGP_HEADER_LENGTH
			if n < 0 {
				return
			}
			if _, err := io.CopyN(io.Discard, conn, int64(n)); err != nil {
				return
			}
		}
	}()
	go func() {
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for range tick.C {
			if s.write(gobgppkt.NewBGPKeepAliveMessage()) != nil {
				return
			}
		}
	}()
	return s
}

func (s *rawSpeaker) write(m *gobgppkt.BGPMessage) error {
	b, err := m.Serialize()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.conn.Write(b)
	return err
}

func (s *rawSpeaker) send(m *gobgppkt.BGPMessage) {
	s.t.Helper()
	if err := s.write(m); err != nil {
		s.t.Fatalf("send BGP message: %v", err)
	}
}

// waitProgrammed waits for an applied event of prefix that leaves wantSID
// installed, and returns that entry.
func waitProgrammed(t *testing.T, ch <-chan programmedEntry, prefix, wantSID string) programmedEntry {
	t.Helper()
	timeout := time.After(attrUpdateWaitTO)
	var last *programmedEntry
	for {
		select {
		case got := <-ch:
			if got.prefix != prefix {
				continue
			}
			last = &got
			if got.sid == wantSID {
				return got
			}
		case <-timeout:
			t.Fatalf("%s: SID %q never installed (last applied event left %+v)", prefix, wantSID, last)
			return programmedEntry{}
		}
	}
}

// TestApplier_SessionVPNPrefixSIDOnlyUpdate drives the receive path with the
// UPDATE sequences an FRR usid-f3216 PE can send for one route, and checks the
// SID Vinbero installs after each. The second UPDATE of a pair repeats the RD
// and prefix and changes only the VPN label or the Prefix-SID attribute: it
// must replace what the first one installed, the way any implicit replace
// does, with nothing in GoBGP, the demux or the applier taking it for "no
// change".
func TestApplier_SessionVPNPrefixSIDOnlyUpdate(t *testing.T) {
	pe1, programmed := startAttrUpdatePipeline(t)
	red := uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_RED)

	type step struct {
		label         uint32
		withStructure bool
		want          string
	}
	cases := []struct {
		name   string
		prefix string
		steps  []step
	}{
		{
			// The steady state: the label carries the function and is folded back.
			name: "single transposed UPDATE", prefix: "10.2.0.0/24",
			steps: []step{{frrFuncLabel, true, frrFullSID}},
		},
		{
			// The structure signals transposition but the label's top 16 bits
			// are zero: the fold adds nothing and the bare block+node remains.
			name: "single UPDATE with implicit-null label", prefix: "10.3.0.0/24",
			steps: []step{{implicitNullLbl, true, frrWireSID}},
		},
		{
			// Only the label changes between the two UPDATEs.
			name: "label corrected by a later UPDATE", prefix: "10.4.0.0/24",
			steps: []step{{implicitNullLbl, true, frrWireSID}, {frrFuncLabel, true, frrFullSID}},
		},
		{
			// The newest UPDATE wins in the other direction too.
			name: "label lost by a later UPDATE", prefix: "10.5.0.0/24",
			steps: []step{{frrFuncLabel, true, frrFullSID}, {implicitNullLbl, true, frrWireSID}},
		},
		{
			// Only the Prefix-SID attribute changes: the first UPDATE has no
			// SID Structure, so its label is not folded; the second adds it.
			name: "SID Structure added by a later UPDATE", prefix: "10.6.0.0/24",
			steps: []step{{frrFuncLabel, false, frrWireSID}, {frrFuncLabel, true, frrFullSID}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for i, s := range tc.steps {
				pe1.send(frrVPNUpdate(t, tc.prefix, s.label, s.withStructure))
				got := waitProgrammed(t, programmed, tc.prefix, s.want)
				if s.withStructure && got.mode != red {
					t.Errorf("step %d: mode = %d, want H.Encaps.Red (%d) for a uSID structure", i, got.mode, red)
				}
			}
		})
	}
}
