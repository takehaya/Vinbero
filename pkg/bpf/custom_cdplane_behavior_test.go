package bpf

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

const customCDPlaneProgram = "plugin_custom_cdplane_behavior"

func customCDPlaneSpec(t *testing.T) *ebpf.CollectionSpec {
	t.Helper()
	const object = "../../sdk/examples/plugin-custom-cdplane-behavior/plugin.o"
	spec, err := ebpf.LoadCollectionSpec(object)
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("build the packet fixture: make -C sdk/examples/plugin-custom-cdplane-behavior")
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidatePluginCollection(spec, customCDPlaneProgram, SharedReadOnlyMapNamesSet()); err != nil {
		t.Fatalf("production plugin validation: %v", err)
	}
	return spec
}

func TestCustomCDPlaneAuxLayout(t *testing.T) {
	spec := customCDPlaneSpec(t)
	var aux *btf.Struct
	if err := spec.Types.TypeByName(customCDPlaneProgram+"_aux", &aux); err != nil {
		t.Fatal(err)
	}
	if aux.Size != 32 || len(aux.Members) != 3 || aux.Members[0].Offset != 0 || aux.Members[2].Offset.Bytes() != 8 {
		t.Fatalf("unexpected aux layout: %+v", aux)
	}
	prefix, ok := aux.Members[2].Type.(*btf.Struct)
	if !ok || prefix.Size != 24 || prefix.Members[0].Offset != 0 || prefix.Members[2].Offset.Bytes() != 8 {
		t.Fatalf("unexpected IPv6 prefix layout: %+v", aux.Members[2].Type)
	}
}

func loadCustomCDPlane(t *testing.T, h *xdpTestHelper) *ebpf.Collection {
	t.Helper()
	spec := customCDPlaneSpec(t)
	replacements := map[string]*ebpf.Map{}
	for _, shared := range []map[string]*ebpf.Map{h.mapOps.GetSharedReadOnlyMaps(), h.mapOps.GetSharedReadWriteMaps()} {
		for name, m := range shared {
			if _, declared := spec.Maps[name]; declared {
				replacements[name] = m
			}
		}
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: replacements})
	if err != nil {
		t.Fatalf("load the real endpoint: %+v", err)
	}
	t.Cleanup(coll.Close)
	if err := h.objs.SidEndpointProgs.Update(uint32(32), coll.Programs[customCDPlaneProgram], ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.objs.SidEndpointProgs.Delete(uint32(32)) })
	return coll
}

func customCDPlaneAux(prefix string) []byte {
	p := netip.MustParsePrefix(prefix).Masked()
	raw := make([]byte, 32)
	raw[0], raw[8] = 1, byte(p.Bits())
	addr := p.Addr().As16()
	copy(raw[16:], addr[:])
	return raw
}

func customCDPlaneCounters(t *testing.T, coll *ebpf.Collection, allowed, denied uint64) {
	t.Helper()
	for key, want := range []uint64{allowed, denied} {
		var counts []uint64
		if err := coll.Maps["cdplane_policy"].Lookup(uint32(key), &counts); err != nil {
			t.Fatal(err)
		}
		var sum uint64
		for _, count := range counts {
			sum += count
		}
		if sum != want {
			t.Fatalf("policy counter %d = %d, want %d", key, sum, want)
		}
	}
}

func TestCustomCDPlanePackets(t *testing.T) {
	// Check for the optional built fixture before loading the host collection.
	customCDPlaneSpec(t)
	for _, srh := range []bool{false, true} {
		name := "nosrh"
		if srh {
			name = "srh"
		}
		for _, tc := range []struct {
			name, prefix, source string
			allow                bool
		}{
			{"exact", "2001:db8:ff::1/128", "2001:db8:ff::1", true},
			{"outside exact", "2001:db8:ff::1/128", "2001:db8:ff::2", false},
			{"subnet", "2001:db8:ff::/64", "2001:db8:ff::abcd", true},
			{"outside subnet", "2001:db8:ff::/64", "2001:db8:fe::1", false},
			{"partial byte", "2001:db8:ff:0:8000::/65", "2001:db8:ff:0:ffff::1", true},
			{"outside partial byte", "2001:db8:ff:0:8000::/65", "2001:db8:ff:0:7fff::1", false},
			{"any IPv6", "::/0", "2001:db8:ff::1", true},
		} {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				h := newXDPTestHelper(t)
				coll := loadCustomCDPlane(t, h)
				const sid = "fd00:1:700::10"
				entry := &SidFunctionEntry{Action: 32}
				if err := h.mapOps.CreateSidFunction(sid+"/128", entry, NewSidAuxPluginRaw(customCDPlaneAux(tc.prefix)), OwnerRPC); err != nil {
					t.Fatal(err)
				}
				h.grantPluginEndtVrf(uint32(entry.AuxIndex), 1)
				var pkt []byte
				var err error
				if srh {
					pkt, err = buildEncapsulatedPacket(net.ParseIP(tc.source), net.ParseIP(sid), []net.IP{net.ParseIP(sid)}, 0,
						net.ParseIP("10.0.0.1").To4(), net.ParseIP("192.0.2.100").To4(), innerTypeIPv4)
				} else {
					pkt, err = buildEncapsulatedPacketNoSRH(net.ParseIP(tc.source), net.ParseIP(sid),
						net.ParseIP("10.0.0.1").To4(), net.ParseIP("192.0.2.100").To4(), innerTypeIPv4)
				}
				if err != nil {
					t.Fatal(err)
				}
				ret, out := h.run(pkt)
				if tc.allow {
					if len(out) >= len(pkt) {
						t.Fatal("allowed packet never reached End.DT4 decapsulation")
					}
					customCDPlaneCounters(t, coll, 1, 0)
					// The same trusted VRF grant must produce the built-in outcome.
					if err := h.objs.SidEndpointProgs.Update(uint32(32), h.objs.TailcallEndpointEndDt4, ebpf.UpdateAny); err != nil {
						t.Fatal(err)
					}
					wantRet, wantOut := h.run(pkt)
					if ret != wantRet || !bytes.Equal(out, wantOut) {
						t.Fatal("allowed handoff differs from built-in End.DT4")
					}
				} else {
					if ret != XDP_DROP || !bytes.Equal(out, pkt) {
						t.Fatalf("rejected packet was modified: ret=%d", ret)
					}
					customCDPlaneCounters(t, coll, 0, 1)
				}
			})
		}
	}
}

func TestCustomCDPlaneRejectsInvalidInput(t *testing.T) {
	customCDPlaneSpec(t)
	for _, name := range []string{"missing aux", "zero version", "unknown version", "reserved", "prefix padding", "prefix too long", "truncated VLAN header", "truncated IPv6", "wrong IP version", "bad L3 offset", "no VRF grant", "missing End.DT4"} {
		t.Run(name, func(t *testing.T) {
			h := newXDPTestHelper(t)
			coll := loadCustomCDPlane(t, h)
			const sid = "fd00:1:700::10"
			raw := customCDPlaneAux("2001:db8:ff::1/128")
			switch name {
			case "zero version":
				raw[0] = 0
			case "unknown version":
				raw[0] = 2
			case "reserved":
				raw[7] = 1
			case "prefix padding":
				raw[15] = 1
			case "prefix too long":
				raw[8] = 129
			}
			var aux *SidAuxEntry
			if name != "missing aux" {
				aux = NewSidAuxPluginRaw(raw)
			}
			entry := &SidFunctionEntry{Action: 32}
			if err := h.mapOps.CreateSidFunction(sid+"/128", entry, aux, OwnerRPC); err != nil {
				t.Fatal(err)
			}
			if name != "missing aux" && name != "no VRF grant" {
				h.grantPluginEndtVrf(uint32(entry.AuxIndex), 1)
			}
			pkt, err := buildEncapsulatedPacketNoSRH(net.ParseIP("2001:db8:ff::1"), net.ParseIP(sid),
				net.ParseIP("10.0.0.1").To4(), net.ParseIP("192.0.2.100").To4(), innerTypeIPv4)
			if err != nil {
				t.Fatal(err)
			}
			l3 := uint16(14)
			switch name {
			case "truncated VLAN header":
				// A complete Ethernet header is the kernel test-run minimum.
				pkt, l3 = pkt[:14], 18
			case "truncated IPv6":
				pkt = pkt[:14+39]
			case "wrong IP version":
				pkt[14] = 0x40
			case "bad L3 offset":
				l3 = 15
			case "missing End.DT4":
				if err := h.objs.SidEndpointProgs.Delete(uint32(actionEndDT4)); err != nil {
					t.Fatal(err)
				}
			}
			// Direct entry also tests malformed packets that the main dispatcher
			// would reject before this program. Context is still host-owned.
			cpus, err := ebpf.PossibleCPU()
			if err != nil {
				t.Fatal(err)
			}
			contexts := make([]BpfTailcallCtx, cpus)
			for i := range contexts {
				contexts[i] = BpfTailcallCtx{L3Offset: l3, Slot: 32, SidEntry: *entry}
			}
			if err := h.objs.TailcallCtxMap.Update(uint32(0), contexts, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			ret, out, err := coll.Programs[customCDPlaneProgram].Test(pkt)
			if err != nil {
				t.Fatal(err)
			}
			if ret != XDP_DROP || !bytes.Equal(out, pkt) {
				t.Fatalf("invalid input escaped or decapsulated: ret=%d", ret)
			}
			if name == "no VRF grant" || name == "missing End.DT4" {
				customCDPlaneCounters(t, coll, 1, 0)
			} else {
				customCDPlaneCounters(t, coll, 0, 1)
			}
		})
	}
}
