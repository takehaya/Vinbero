package bpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/pkg/errors"
	"github.com/takehaya/vinbero/pkg/config"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS Bpf ../../src/xdp_prog.c -- -I ../../src -I /usr/include/x86_64-linux-gnu

func ReadCollection(constants map[string]interface{}, cfg *config.Config) (*BpfObjects, error) {
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
		}
		for name, size := range mapSizes {
			if ms, ok := spec.Maps[name]; ok && size > 0 {
				ms.MaxEntries = uint32(size)
			}
		}
	}

	err = spec.LoadAndAssign(objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 1073741823, LogLevel: ebpf.LogLevelInstruction},
	})
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			fmt.Printf("%+v\n", verr)
		}
		return nil, fmt.Errorf("fail to load and assign bpf objects: %w", err)
	}

	return objs, nil
}
