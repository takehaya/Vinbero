package bpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/pkg/errors"
	"github.com/takehaya/vinbero/pkg/config"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS Bpf ../../src/xdp_prog.c -- -I ../../src -I /usr/include/x86_64-linux-gnu

func ReadCollection(constants map[string]any, cfg *config.Config) (*BpfObjects, error) {
	// Remove memory limit for BPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memory limit: %w", err)
	}

	objs := &BpfObjects{}
	spec, err := LoadBpf()
	if err != nil {
		return nil, fmt.Errorf("fail to load bpf spec: %w", err)
	}

	for name, value := range constants {
		varSpec, ok := spec.Variables[name]
		if !ok {
			return nil, fmt.Errorf("constant %s not found in spec", name)
		}
		if err := varSpec.Set(value); err != nil {
			return nil, err
		}
	}

	// Override map capacities from config
	if cfg != nil {
		entries := cfg.Setting.Entries
		mapSizes := map[string]int{
			"sid_function_map":   entries.SidFunction.Capacity,
			"sid_aux_map":        entries.SidFunction.Capacity,
			"headend_v4_map":     entries.Headendv4.Capacity,
			"headend_v6_map":     entries.Headendv6.Capacity,
			"headend_l2_map":     entries.HeadendL2.Capacity,
			"fdb_map":            entries.Fdb.Capacity,
			"bd_peer_map":        entries.BdPeer.Capacity,
			"bd_peer_reverse_map": entries.BdPeer.Capacity,
			"dx2v_map":            entries.VlanTable.Capacity,
		}
		for name, size := range mapSizes {
			if ms, ok := spec.Maps[name]; ok && size > 0 {
				ms.MaxEntries = uint32(size)
			}
		}
	}

	err = spec.LoadAndAssign(objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 64 * 1024 * 1024, LogLevel: ebpf.LogLevelInstruction},
	})
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			fmt.Printf("%+v\n", verr)
		}
		return nil, fmt.Errorf("fail to load and assign bpf objects: %w", err)
	}

	// Populate PROG_ARRAY maps with tail call targets
	if err := populateProgArrays(objs); err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("fail to populate prog arrays: %w", err)
	}

	return objs, nil
}

// populateProgArrays registers all tail call target programs into their
// respective PROG_ARRAY maps. Each index corresponds to the srv6_local_action
// or srv6_headend_behavior enum value.
func populateProgArrays(objs *BpfObjects) error {
	// Endpoint PROG_ARRAY (indexed by srv6_local_action enum)
	endpointProgs := map[uint32]*ebpf.Program{
		1:  objs.TailcallEndpointEnd,
		2:  objs.TailcallEndpointEndX,
		3:  objs.TailcallEndpointEndT,
		4:  objs.TailcallEndpointEndDx2,
		5:  objs.TailcallEndpointEndDx6,
		6:  objs.TailcallEndpointEndDx4,
		7:  objs.TailcallEndpointEndDt6,
		8:  objs.TailcallEndpointEndDt4,
		9:  objs.TailcallEndpointEndDt46,
		10: objs.TailcallEndpointEndB6,
		11: objs.TailcallEndpointEndB6Encaps,
		17: objs.TailcallEndpointEndDt2,
		22: objs.TailcallEndpointEndDx2v,
		18: objs.TailcallEndpointEndM_gtp6D,
		19: objs.TailcallEndpointEndM_gtp6D_di,
		20: objs.TailcallEndpointEndM_gtp6E,
		21: objs.TailcallEndpointEndM_gtp4E,
	}
	for idx, prog := range endpointProgs {
		if err := objs.SidEndpointProgs.Update(idx, prog, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("sid_endpoint_progs[%d]: %w", idx, err)
		}
	}

	// Headend v4 PROG_ARRAY (indexed by srv6_headend_behavior enum)
	headendV4Progs := map[uint32]*ebpf.Program{
		2: objs.TailcallHeadendV4H_encaps,
		4: objs.TailcallHeadendV4H_mGtp4D,
		5: objs.TailcallHeadendV4H_encapsRed,
	}
	for idx, prog := range headendV4Progs {
		if err := objs.HeadendV4Progs.Update(idx, prog, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("headend_v4_progs[%d]: %w", idx, err)
		}
	}

	// Headend v6 PROG_ARRAY (indexed by srv6_headend_behavior enum)
	headendV6Progs := map[uint32]*ebpf.Program{
		1: objs.TailcallHeadendV6H_insert,
		2: objs.TailcallHeadendV6H_encaps,
		5: objs.TailcallHeadendV6H_encapsRed,
		7: objs.TailcallHeadendV6H_insertRed,
	}
	for idx, prog := range headendV6Progs {
		if err := objs.HeadendV6Progs.Update(idx, prog, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("headend_v6_progs[%d]: %w", idx, err)
		}
	}

	return nil
}
