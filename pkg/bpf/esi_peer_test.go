package bpf

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
)

func TestEsiPeerMapContract(t *testing.T) {
	spec, err := LoadBpf()
	if err != nil {
		t.Fatal(err)
	}
	m := spec.Maps["esi_peer_map"]
	if m.Type != ebpf.Hash || m.KeySize != 32 || m.ValueSize != 1 || m.MaxEntries != 8192 || m.Flags != unix.BPF_F_RDONLY_PROG || m.Pinning != ebpf.PinNone {
		t.Fatalf("wrong ESI membership map: %+v", m)
	}
	if binary.Size(BpfEsiPeerKey{}) != 32 || binary.Size(EsiKey{}) != 16 || binary.Size(EsiEntry{}) != 40 || binary.Size(BdPeerReverseVal{}) != 16 {
		t.Fatal("ESI membership changed an existing map ABI")
	}
	for _, name := range pinnedControlMaps {
		if name == "esi_peer_map" {
			t.Fatal("RT4 membership must be rebuilt with the unpinned ES state")
		}
	}
	if _, ok := SharedReadOnlyMapNamesSet()["esi_peer_map"]; !ok {
		t.Fatal("membership map must be classified read-only for plugin validation")
	}
	if _, ok := integrityMapNames["esi_peer_map"]; !ok {
		t.Fatal("membership writes must not be warn-downgradable")
	}
}

func TestEsiPeerMapCRUD(t *testing.T) {
	h := newXDPTestHelper(t)
	esiA, esiB := [ESILen]byte{1}, [ESILen]byte{2}
	srcA, _ := ParseIPv6("fd00:1::1")
	srcB, _ := ParseIPv6("fd00:1::2")
	for _, key := range []BpfEsiPeerKey{{Esi: esiA, SrcAddr: srcA}, {Esi: esiA, SrcAddr: srcB}, {Esi: esiB, SrcAddr: srcA}} {
		for range 2 {
			if err := h.mapOps.CreateEsiPeer(key.Esi, key.SrcAddr); err != nil {
				t.Fatal(err)
			}
		}
	}
	for range 2 {
		if err := h.mapOps.DeleteEsiPeer(esiA, srcA); err != nil {
			t.Fatal(err)
		}
	}
	for _, key := range []BpfEsiPeerKey{{Esi: esiA, SrcAddr: srcA}, {Esi: esiA, SrcAddr: srcB}, {Esi: esiB, SrcAddr: srcA}} {
		var present uint8
		err := h.objs.EsiPeerMap.Lookup(key, &present)
		if key.Esi == esiA && key.SrcAddr == srcA {
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatalf("withdrawn membership remains: %v", err)
			}
		} else if err != nil || present != 1 {
			t.Fatalf("withdrawal affected another ES/source: %+v value=%d err=%v", key, present, err)
		}
	}
	if err := h.mapOps.CreateEsiPeer([ESILen]byte{}, srcA); err == nil {
		t.Error("zero ESI accepted")
	}
	for _, text := range []string{"::", "ff02::1", "::ffff:192.0.2.1"} {
		source := netip.MustParseAddr(text).As16()
		if err := h.mapOps.CreateEsiPeer(esiA, source); err == nil {
			t.Errorf("invalid source %s accepted", text)
		}
	}
}

// Check the kernel boundary too, even if the plugin RO validator were bypassed.
func TestEsiPeerMapRejectsBPFWrites(t *testing.T) {
	h := newXDPTestHelper(t)
	for _, write := range []bool{false, true} {
		ins := asm.Instructions{
			asm.Mov.Imm(asm.R3, 0),
			asm.StoreMem(asm.R10, -32, asm.R3, asm.DWord),
			asm.StoreMem(asm.R10, -24, asm.R3, asm.DWord),
			asm.StoreMem(asm.R10, -16, asm.R3, asm.DWord),
			asm.StoreMem(asm.R10, -8, asm.R3, asm.DWord),
			asm.LoadMapPtr(asm.R1, h.objs.EsiPeerMap.FD()),
			asm.Mov.Reg(asm.R2, asm.R10),
			asm.Add.Imm(asm.R2, -32),
			asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "exit"),
		}
		if write {
			ins = append(ins, asm.StoreImm(asm.R0, 0, 1, asm.Byte))
		} else {
			ins = append(ins, asm.LoadMem(asm.R2, asm.R0, 0, asm.Byte))
		}
		ins = append(ins, asm.Mov.Imm(asm.R0, int32(XDP_PASS)).WithSymbol("exit"), asm.Return())
		prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.XDP, License: "GPL", Instructions: ins})
		if prog != nil {
			if err := prog.Close(); err != nil {
				t.Fatal(err)
			}
		}
		if write && err == nil {
			t.Fatal("kernel accepted a BPF write to host-only membership")
		}
		if write {
			var verifier *ebpf.VerifierError
			if !errors.As(err, &verifier) {
				t.Fatalf("write denied for an unexpected reason: %v", err)
			}
			t.Logf("kernel denied membership write: %v", err)
		}
		if !write && err != nil {
			t.Fatalf("valid read-only program rejected: %v", err)
		}
	}
}
