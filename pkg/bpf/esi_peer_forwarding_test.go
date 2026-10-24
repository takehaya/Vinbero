package bpf

import (
	"net"
	"testing"

	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

func TestXDPProgEndDT2MMembership(t *testing.T) {
	esiA, esiB := [ESILen]byte{1}, [ESILen]byte{2}
	sender, _ := ParseIPv6("fd00:1::1")
	other, _ := ParseIPv6("fd00:1::2")
	local, _ := ParseIPv6("fd00:2::1")
	for _, noSRH := range []bool{false, true} {
		name := "SRH"
		if noSRH {
			name = "noSRH"
		}
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				name                              string
				memberESI                         [ESILen]byte
				memberSource                      [IPv6AddrLen]byte
				bd                                uint16
				missing, withdraw, detached, noES bool
				legacy, unicast                   bool
				want                              uint32
			}{
				{name: "same ES member", memberESI: esiA, memberSource: sender, bd: 100, want: XDP_DROP},
				{name: "other ES", memberESI: esiB, memberSource: sender, bd: 100, want: XDP_REDIRECT},
				{name: "other BD local ES", memberESI: esiA, memberSource: sender, bd: 101, want: XDP_REDIRECT},
				{name: "other source", memberESI: esiA, memberSource: other, bd: 100, want: XDP_REDIRECT},
				{name: "missing membership", bd: 100, missing: true, want: XDP_REDIRECT},
				{name: "withdrawn membership", memberESI: esiA, memberSource: sender, bd: 100, withdraw: true, want: XDP_REDIRECT},
				{name: "BD without local ES", memberESI: esiA, memberSource: sender, bd: 102, want: XDP_REDIRECT},
				{name: "ES detached", memberESI: esiA, memberSource: sender, bd: 100, detached: true, want: XDP_REDIRECT},
				{name: "ES unregistered", memberESI: esiA, memberSource: sender, bd: 100, noES: true, want: XDP_REDIRECT},
				{name: "legacy reverse ESI", bd: 100, missing: true, legacy: true, want: XDP_DROP},
				{name: "DT2U unaffected", memberESI: esiA, memberSource: sender, bd: 100, unicast: true, want: XDP_REDIRECT},
			} {
				t.Run(tc.name, func(t *testing.T) {
					h := newXDPTestHelperWithStats(t)
					action := actionEndDT2M
					if tc.unicast {
						action = actionEndDT2
					}
					h.createSidFunctionWithBD("fd00:1:100::10/128", action, tc.bd)
					for _, es := range [][ESILen]byte{esiA, esiB} {
						if tc.noES && es == esiA {
							continue
						}
						if err := h.mapOps.CreateEsi(es, NewEsiEntry(EsiConfig{LocalAttached: !tc.detached || es != esiA, LocalPeSrcAddr: local, DfPeSrcAddr: local})); err != nil {
							t.Fatal(err)
						}
					}
					for i, es := range [][ESILen]byte{esiA, esiB} {
						entry := &HeadendEntry{Mode: uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2), NumSegments: 1, SrcAddr: local, BdId: uint16(100 + i)}
						if err := h.mapOps.CreateHeadendL2(1, uint16(100+i), entry, es); err != nil {
							t.Fatal(err)
						}
					}
					if !tc.missing {
						if err := h.mapOps.CreateEsiPeer(tc.memberESI, tc.memberSource); err != nil {
							t.Fatal(err)
						}
					}
					if tc.withdraw {
						if err := h.mapOps.DeleteEsiPeer(tc.memberESI, tc.memberSource); err != nil {
							t.Fatal(err)
						}
					}
					if tc.legacy {
						entry := &HeadendEntry{Mode: uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2), NumSegments: 1, SrcAddr: local}
						if err := h.mapOps.CreateBdPeer(tc.bd, 0, entry, esiA, sender, true); err != nil {
							t.Fatal(err)
						}
					}
					// A local FDB destination proves the negative cases actually
					// reach DT2 forwarding, rather than bypassing endpoint dispatch.
					h.createFdbEntry(tc.bd, net.HardwareAddr{0, 0, 0, 0, 0, 2}, 1)
					var pkt []byte
					var err error
					if noSRH {
						pkt, err = buildL2EncapsulatedPacketNoSRH(net.IP(sender[:]), net.ParseIP("fd00:1:100::10"), 100, net.ParseIP("10.0.0.1"), net.ParseIP("192.0.2.100"), true)
					} else {
						pkt, err = buildL2EncapsulatedPacket(net.IP(sender[:]), net.ParseIP("fd00:1:100::10"), []net.IP{net.ParseIP("fd00:1:100::10")}, 0, 100, net.ParseIP("10.0.0.1"), net.ParseIP("192.0.2.100"), true)
					}
					if err != nil {
						t.Fatal(err)
					}
					ret, _ := h.run(pkt)
					if ret != tc.want {
						t.Fatalf("action=%d want=%d", ret, tc.want)
					}
					stats, err := h.mapOps.ReadStats()
					if err != nil {
						t.Fatal(err)
					}
					var found bool
					var wantCount uint64
					if tc.want == XDP_DROP {
						wantCount = 1
					}
					for _, stat := range stats {
						if stat.Name == "SPLIT_HORIZON_RX" {
							found = true
							if stat.Packets != wantCount {
								t.Fatalf("split-horizon RX count=%d want=%d", stat.Packets, wantCount)
							}
						}
					}
					if !found {
						t.Fatal("missing split-horizon RX counter")
					}
				})
			}
		})
	}
}
