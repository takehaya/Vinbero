package cplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/cplane/native"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
)

// TestEVPNControllerPacketLifecycle feeds packets through the production XDP
// collection after each settled Manager state. It does not attach an interface,
// establish a BGP session, or assert loss-free forwarding during replacement.
func TestEVPNControllerPacketLifecycle(t *testing.T) {
	if os.Getenv("VINBERO_CPLANE_EVPN_PACKET") != "1" {
		t.Skip("set VINBERO_CPLANE_EVPN_PACKET=1 with BPF privileges and VINBERO_CPLANE_EVPN_WASM")
	}
	evpnPacketLifecycle(t, false)
}

// TestEVPNControllerWireLifecycle verifies the same settled states with a real
// interface attachment and one transmitted packet per state. It does not test
// BGP transport, a remote decapsulation endpoint, or traffic during replacement.
func TestEVPNControllerWireLifecycle(t *testing.T) {
	if os.Getenv("VINBERO_CPLANE_EVPN_WIRE") != "1" {
		t.Skip("set VINBERO_CPLANE_EVPN_WIRE=1 with BPF/netns privileges and VINBERO_CPLANE_EVPN_WASM")
	}
	evpnPacketLifecycle(t, true)
}

func evpnPacketLifecycle(t *testing.T, onWire bool) {
	path := os.Getenv("VINBERO_CPLANE_EVPN_WASM")
	if path == "" {
		t.Fatal("VINBERO_CPLANE_EVPN_WASM must name the built EVPN module")
	}
	module, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("EVPN module SHA256 %x", sha256.Sum256(module))
	traces := []struct {
		name     string
		backends []string
	}{
		{"native", []string{BackendNative}},
		{"wasm", []string{BackendWASM}},
		{"native-wasm-native", []string{BackendNative, BackendWASM, BackendNative}},
		{"wasm-native-wasm", []string{BackendWASM, BackendNative, BackendWASM}},
	}
	for _, trace := range traces {
		t.Run(trace.name, func(t *testing.T) {
			// ReadCollection(nil,nil) creates fresh unpinned maps and fills tail calls.
			objects, err := bpf.ReadCollection(nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := objects.Close(); err != nil {
					t.Error(err)
				}
			})
			maps := bpf.NewMapOperations(objects)
			var wire *evpnPacketWire
			var ingress int
			var vlan uint16 = 100
			if onWire {
				wire = newEVPNPacketWire(t, objects.VinberoMain)
				ingress, vlan = wire.ingress, 0
			} else {
				lo, err := net.InterfaceByName("lo")
				if err != nil {
					t.Fatal(err)
				}
				ingress = lo.Index
			}
			// The AC only selects BD100. Its fallback SID must never serve as the
			// controller-created remote peer; a missing FDB goes to the kernel.
			ac := &bpf.HeadendEntry{Mode: uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2), BdId: 100, NumSegments: 1, SrcAddr: netip.MustParseAddr("fd00:feed::1").As16()}
			ac.Segments[0] = netip.MustParseAddr("fd00:bad::1").As16()
			if err := maps.CreateHeadendL2(uint32(ingress), vlan, ac, [bpf.ESILen]byte{}); err != nil {
				t.Fatal(err)
			}
			source := &compositionSource{newFakeSource()}
			rt2, rt3 := evpnPolicyFixture(t, false, "65000:7"), evpnPolicyFixture(t, true, "65000:7")
			source.setRib(rt2, rt3)
			manager, err := NewManager(ManagerConfig{AllowNative: true, Source: source, Headend: newFakeHeadendOps(), ForwardingMaps: maps, ResolveInputTarget: func(bgp.RouteEvent) (string, uint16, bool) { return "", 100, true }})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { manager.Close(context.Background()) })
			packetNumber := 0
			reg := Registration{Name: "packet-imet", Config: []byte(`{"context":"l2","source":"fd00:feed::1","observe_only":false}`), Capabilities: wasm.Capabilities{wasm.CapEVPN: {}}, Input: &v1.CplaneInputPolicy{Version: 1, Contexts: []*v1.CplaneInputContext{{Name: "l2", Grants: []*v1.CplaneInputGrant{{Families: []string{"evpn"}, RouteTargets: []string{"65000:7"}}}, DelegateEvpn: true, BridgeDomain: 100}}}}
			check := func(stage, backend string, present, registered bool) {
				t.Helper()
				if registered {
					if !manager.WaitIdle(reg.Name, 15*time.Second) {
						t.Fatal("worker did not drain")
					}
					state, ok := manager.StatsFor(reg.Name)
					if !ok {
						t.Fatal("missing plugin stats")
					}
					if state.Backend != backend || state.Dead || state.Restarts != 0 || !state.InputReady || state.InputFault != "" || state.OutputFailure != "" || state.CleanupPending || state.DesiredRevision == 0 || state.DesiredRevision != state.AppliedRevision {
						t.Fatalf("unhealthy %s: %+v", stage, state)
					}
				}
				fdb, err := maps.ListFdb()
				if err != nil {
					t.Fatal(err)
				}
				peers, err := maps.ListBdPeers()
				if err != nil {
					t.Fatal(err)
				}
				owners, err := maps.ListFdbOwners()
				if err != nil {
					t.Fatal(err)
				}
				peerOwners, err := maps.ListBdPeerOwners()
				if err != nil {
					t.Fatal(err)
				}
				key := bpf.FdbKey{BdId: 100, Mac: [6]byte{2, 0, 0, 0, 0, 1}}
				value := fdb[key]
				if present {
					if value == nil || value.IsStatic != 1 || value.IsRemote != 1 || value.BdId != 100 || owners[key] != bpf.OwnerPluginBundle(reg.Name) || len(owners) != 1 || len(peers) != 1 || len(peerOwners) != 1 {
						t.Fatalf("missing owned state %s: fdb=%v peers=%v owners=%v/%v", stage, fdb, peers, owners, peerOwners)
					}
					pk := bpf.BdPeerKey{BdId: 100, Index: value.PeerIndex}
					peer := peers[pk]
					if peer == nil || peerOwners[pk] != bpf.OwnerPluginBundle(reg.Name) || peer.NumSegments != 1 || peer.Segments[0] != netip.MustParseAddr("fd00:2::1").As16() || peer.SrcAddr != netip.MustParseAddr("fd00:feed::1").As16() || peer.FloodExclude != 1 {
						t.Fatalf("wrong peer %s: %+v", stage, peer)
					}
				} else if value != nil || len(owners) != 0 || len(peers) != 0 || len(peerOwners) != 0 {
					t.Fatalf("owned forwarding remained %s: %v/%v/%v/%v", stage, value, peers, owners, peerOwners)
				}
				packetNumber++
				frame := evpnPacketFrame(t, vlan, fmt.Sprintf("%s/%d/%s/%s", trace.name, packetNumber, stage, backend))
				if onWire {
					wire.check(t, frame, present)
					t.Logf("stage=%s backend=%s remote_present=%t wire_sent=1", stage, backend, present)
					return
				}
				// Local source-MAC learning may create an unowned FDB entry. It cannot
				// authorize the distinct destination MAC or create a remote peer.
				ctx := struct{ Data, DataEnd, DataMeta, IngressIfindex, RxQueueIndex, EgressIfindex uint32 }{DataEnd: uint32(len(frame)), IngressIfindex: uint32(ingress)}
				opts := ebpf.RunOptions{Data: append([]byte(nil), frame...), DataOut: make([]byte, 2048), Context: ctx, Repeat: 1}
				action, err := objects.VinberoMain.Run(&opts)
				if err != nil {
					t.Fatalf("BPF_PROG_TEST_RUN %s: %v", stage, err)
				}
				if present {
					// FIB resolution follows encapsulation. With no underlay route
					// owned by test-run, either DROP or REDIRECT may follow it.
					if action != bpf.XDP_DROP && action != bpf.XDP_REDIRECT {
						t.Fatalf("unexpected encap action %d", action)
					}
					evpnPacketEncapsulation(t, frame, opts.DataOut)
				} else {
					packet := opts.DataOut
					// Test-run may include the unknown-unicast BUM metadata before
					// Ethernet data. Validate it instead of treating it as wire bytes.
					if len(packet) == len(frame)+8 && binary.NativeEndian.Uint64(packet[:8]) == uint64(0x564e4255)<<32|uint64(vlan) {
						packet = packet[8:]
					}
					if action != bpf.XDP_PASS || !bytes.Equal(frame, packet) {
						t.Fatalf("withdrawn policy still transformed packet %s: action=%d bytes=%x", stage, action, opts.DataOut)
					}
				}
				t.Logf("stage=%s backend=%s remote_present=%t XDP_action=%d input_bytes=%d output_bytes=%d", stage, backend, present, action, len(frame), len(opts.DataOut))
			}
			for i, backend := range trace.backends {
				reg.Backend, reg.Module, reg.NativeID, reg.NativeVersion = backend, nil, "", ""
				if backend == BackendNative {
					reg.NativeID, reg.NativeVersion = native.EVPNIMET, native.ImplementationVersion
				} else {
					reg.Module = module
				}
				if err := manager.Register(context.Background(), reg); err != nil {
					t.Fatal(err)
				}
				check("registered", backend, true, true)
				if i == 0 {
					source.setRib(rt2)
					withdraw := rt3
					withdraw.IsWithdraw = true
					if !source.emit(reg.Name, withdraw) {
						t.Fatal("missing subscription for RT3 withdrawal")
					}
					check("RT3-withdrawn", backend, false, true)
					source.setRib(rt2, rt3)
					if !source.emit(reg.Name, rt3) {
						t.Fatal("missing subscription for RT3 re-advertisement")
					}
					check("RT3-restored", backend, true, true)
				}
			}
			// Withdrawal must still work after the roundtrip's last replay/instance.
			source.setRib(rt2)
			withdraw := rt3
			withdraw.IsWithdraw = true
			if !source.emit(reg.Name, withdraw) {
				t.Fatal("missing final withdrawal subscription")
			}
			backend := trace.backends[len(trace.backends)-1]
			check("final-RT3-withdrawn", backend, false, true)
			source.setRib(rt2, rt3)
			if !source.emit(reg.Name, rt3) {
				t.Fatal("missing final restore subscription")
			}
			check("final-RT3-restored", backend, true, true)
			if err := manager.Unregister(context.Background(), reg.Name); err != nil {
				t.Fatal(err)
			}
			check("unregistered", backend, false, false)
		})
	}
}

func evpnPacketFrame(t *testing.T, vlanID uint16, nonce string) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, EthernetType: layers.EthernetTypeIPv4}
	var headers []gopacket.SerializableLayer
	headers = append(headers, eth)
	if vlanID != 0 {
		eth.EthernetType = layers.EthernetTypeDot1Q
		headers = append(headers, &layers.Dot1Q{VLANIdentifier: vlanID, Type: layers.EthernetTypeIPv4})
	}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("192.0.2.1").To4(), DstIP: net.ParseIP("192.0.2.2").To4()}
	udp := &layers.UDP{SrcPort: 10000, DstPort: 20000}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	headers = append(headers, ip, udp, gopacket.Payload([]byte("EVPN controller packet lifecycle "+nonce)))
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, headers...); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func evpnPacketEncapsulation(t *testing.T, inner, outer []byte) {
	t.Helper()
	const ethernet, ipv6, srh = 14, 40, 24
	if len(outer) != ethernet+ipv6+srh+len(inner) {
		t.Fatalf("encap size %d want %d", len(outer), ethernet+ipv6+srh+len(inner))
	}
	ip := outer[ethernet : ethernet+ipv6]
	routing := outer[ethernet+ipv6 : ethernet+ipv6+srh]
	src, dst := netip.MustParseAddr("fd00:feed::1").As16(), netip.MustParseAddr("fd00:2::1").As16()
	if binary.BigEndian.Uint16(outer[12:14]) != 0x86dd || ip[0]>>4 != 6 || ip[6] != 43 || int(binary.BigEndian.Uint16(ip[4:6])) != srh+len(inner) || !bytes.Equal(ip[8:24], src[:]) || !bytes.Equal(ip[24:40], dst[:]) {
		t.Fatalf("wrong outer IPv6: %x", ip)
	}
	if routing[0] != 143 || routing[1] != 2 || routing[2] != 4 || routing[3] != 0 || routing[4] != 0 || !bytes.Equal(routing[8:24], dst[:]) {
		t.Fatalf("wrong single-SID Ethernet SRH: %x", routing)
	}
	if !bytes.Equal(outer[ethernet+ipv6+srh:], inner) {
		t.Fatal("encapsulation changed the inner Ethernet frame")
	}
}
