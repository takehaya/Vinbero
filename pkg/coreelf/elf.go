package coreelf

import (
	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-12 -target bpf srv6 ../../src/srv6.c -- -I./../../include -I./../../src -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wnull-character -g -c -O2 -D__KERNEL__

func ReadCollection() (*srv6Objects, error) {
	spec, err := newSrv6Specs()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// TODO: BPF log level remove hardcoding. yaml in config
	obj, err := spec.Load(
		&ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogLevel: 2,
				LogSize:  102400 * 1024,
			},
		},
	)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return obj, nil
}
