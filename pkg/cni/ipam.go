package cni

import (
	"context"

	"github.com/containernetworking/cni/pkg/invoke"
	current "github.com/containernetworking/cni/pkg/types/100"
)

// execIPAM runs the IPAM plugin binary from CNI_PATH with the network
// configuration on stdin, as the CNI spec delegates IPAM.
type execIPAM struct{}

func (execIPAM) Add(ctx context.Context, ipamType string, conf []byte) (*current.Result, error) {
	r, err := invoke.DelegateAdd(ctx, ipamType, conf, nil)
	if err != nil {
		return nil, err
	}
	return current.NewResultFromResult(r)
}

func (execIPAM) Del(ctx context.Context, ipamType string, conf []byte) error {
	return invoke.DelegateDel(ctx, ipamType, conf, nil)
}

func (execIPAM) Check(ctx context.Context, ipamType string, conf []byte) error {
	return invoke.DelegateCheck(ctx, ipamType, conf, nil)
}
