package bpf

import (
	"bytes"
	"net"
	"testing"

	"github.com/cilium/ebpf"
)

// Loading a built-in into a plugin slot preserves a plugin SID's trusted
// discriminator, just as a plugin tail-call does. The aux bytes deliberately
// have a valid built-in layout so a missing discriminator changes the packet.
func TestXDPPluginAuxHandwrittenBuiltins(t *testing.T) {
	const pluginSlot = uint32(32)
	src := net.ParseIP("fd00:1:1::1")
	cases := []struct {
		name     string
		action   uint8
		program  func(*BpfObjects) *ebpf.Program
		sid      net.IP
		aux      *SidAuxEntry
		segments []net.IP
	}{
		{"EndX", actionEndX, func(o *BpfObjects) *ebpf.Program { return o.TailcallEndpointEndX }, net.ParseIP("fd00:1:100::10"), NewSidAuxNexthop([16]byte{}), []net.IP{net.ParseIP("fd00:2::1"), net.ParseIP("fd00:1:100::10")}},
		{"uN", actionEndUn, func(o *BpfObjects) *ebpf.Program { return o.TailcallEndpointEndUn }, net.ParseIP("fd00:aaaa:bbbb:cccc::"), NewSidAuxUsid([16]byte{}, 4), []net.IP{net.ParseIP("fd00:2::1"), net.ParseIP("fd00:aaaa:bbbb:cccc::")}},
		{"uT", actionEndUt, func(o *BpfObjects) *ebpf.Program { return o.TailcallEndpointEndUt }, net.ParseIP("fd00:aaaa:bbbb:cccc::"), NewSidAuxUsidVrf(1, 4), []net.IP{net.ParseIP("fd00:2::1"), net.ParseIP("fd00:aaaa:bbbb:cccc::")}},
		{"uA", actionEndUa, func(o *BpfObjects) *ebpf.Program { return o.TailcallEndpointEndUa }, net.ParseIP("fd00:aaaa:ffff:cccc:dddd::"), NewSidAuxUsid([16]byte{}, 4), []net.IP{net.ParseIP("fd00:2::1"), net.ParseIP("fd00:aaaa:ffff:cccc:dddd::")}},
		{"REPLACE", actionEndReplace, func(o *BpfObjects) *ebpf.Program { return o.TailcallEndpointEndReplace }, replDA(0x11112222, 2), NewSidAuxReplace([16]byte{}, 6, 4), []net.IP{mkContainer32(0, 0, 0, 0), mkContainer32(0x510500aa, 0x510500bb, 0x510500cc, 0x510500dd)}},
		{"X_REPLACE", actionEndXReplace, func(o *BpfObjects) *ebpf.Program { return o.TailcallEndpointEndX_replace }, replDA(0x11112222, 2), NewSidAuxReplace([16]byte{}, 6, 4), []net.IP{mkContainer32(0, 0, 0, 0), mkContainer32(0x510500aa, 0x510500bb, 0x510500cc, 0x510500dd)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkt, err := buildSRv6Packet(src, tc.sid, tc.segments, 1)
			if err != nil {
				t.Fatal(err)
			}
			t.Run("plugin", func(t *testing.T) {
				h := newXDPTestHelper(t)
				if err := h.objs.SidEndpointProgs.Update(pluginSlot, tc.program(h.objs), ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = h.objs.SidEndpointProgs.Delete(pluginSlot) })
				if err := h.mapOps.CreateSidFunction(tc.sid.String()+"/128", &SidFunctionEntry{Action: uint8(pluginSlot)}, tc.aux, OwnerRPC); err != nil {
					t.Fatal(err)
				}
				ret, out := h.run(pkt)
				if ret != XDP_DROP || !bytes.Equal(pkt, out) {
					t.Fatalf("plugin aux reached built-in: action=%d packet changed=%v", ret, !bytes.Equal(pkt, out))
				}
			})
			t.Run("builtin", func(t *testing.T) {
				h := newXDPTestHelper(t)
				if err := h.mapOps.CreateSidFunction(tc.sid.String()+"/128", &SidFunctionEntry{Action: tc.action}, tc.aux, OwnerRPC); err != nil {
					t.Fatal(err)
				}
				_, out := h.run(pkt)
				if bytes.Equal(pkt, out) {
					t.Fatal("legitimate built-in stopped consuming its aux")
				}
			})
		})
	}
}

func TestXDPPluginDXDecapGrant(t *testing.T) {
	const pluginSlot = uint32(32)
	for _, ipv6 := range []bool{false, true} {
		for _, srh := range []bool{false, true} {
			name := "DX4"
			if ipv6 {
				name = "DX6"
			}
			if srh {
				name += "/srh"
			} else {
				name += "/nosrh"
			}
			t.Run(name, func(t *testing.T) {
				h := newXDPTestHelper(t)
				program := h.objs.TailcallEndpointEndDx4
				action := actionEndDX4
				innerType := innerTypeIPv4
				innerSrc, innerDst := net.ParseIP("10.0.0.1").To4(), net.ParseIP("192.0.2.100").To4()
				if ipv6 {
					program = h.objs.TailcallEndpointEndDx6
					action = actionEndDX6
					innerType = innerTypeIPv6
					innerSrc = net.ParseIP("2001:db8:1::1")
					innerDst = net.ParseIP("2001:db8:2::1")
				}
				build := func(sid string) []byte {
					t.Helper()
					var pkt []byte
					var err error
					if srh {
						pkt, err = buildEncapsulatedPacket(net.ParseIP("fd00:1::1"), net.ParseIP(sid), []net.IP{net.ParseIP(sid)}, 0, innerSrc, innerDst, innerType)
					} else {
						pkt, err = buildEncapsulatedPacketNoSRH(net.ParseIP("fd00:1::1"), net.ParseIP(sid), innerSrc, innerDst, innerType)
					}
					if err != nil {
						t.Fatal(err)
					}
					return pkt
				}
				if err := h.objs.SidEndpointProgs.Update(pluginSlot, program, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = h.objs.SidEndpointProgs.Delete(pluginSlot) })
				const sid = "fd00:1:700::10"
				entry := &SidFunctionEntry{Action: uint8(pluginSlot)}
				// The attacker selects a different ifindex in raw aux; only the trusted
				// grant is allowed to select the plugin's inner routing domain.
				if err := h.mapOps.CreateSidFunction(sid+"/128", entry, NewSidAuxL3Vrf(9999), OwnerRPC); err != nil {
					t.Fatal(err)
				}
				pkt := build(sid)
				denied := func() {
					t.Helper()
					ret, out := h.run(pkt)
					if ret != XDP_DROP || !bytes.Equal(out, pkt) {
						t.Fatalf("ungranted decap: ret=%d length %d -> %d", ret, len(pkt), len(out))
					}
				}
				denied()
				h.grantPluginEndtVrf(uint32(entry.AuxIndex), 1)
				ret, out := h.run(pkt)
				if len(out) >= len(pkt) {
					t.Fatal("grant did not permit decapsulation")
				}
				h.createSidFunctionWithVRF("fd00:1:700::20/128", action, 1)
				builtinRet, builtinOut := h.run(build("fd00:1:700::20"))
				if ret != builtinRet || !bytes.Equal(out, builtinOut) {
					t.Fatalf("granted handoff differs from builtin: %d/%d", ret, builtinRet)
				}
				if err := h.mapOps.DeleteEndtVRFGrant(uint32(entry.AuxIndex)); err != nil {
					t.Fatal(err)
				}
				denied()
			})
		}
	}
}
