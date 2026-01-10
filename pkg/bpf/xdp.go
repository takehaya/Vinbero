package bpf

import "structs"

// XdpMd is the XDP metadata structure for BPF_PROG_RUN.
// This structure must match the kernel's xdp_md structure.
type XdpMd struct {
	_              structs.HostLayout
	Data           uint32
	DataEnd        uint32
	DataMeta       uint32
	IngressIfindex uint32
	RxQueueIndex   uint32
	EgressIfindex  uint32
}

const (
	// XDP action codes
	XDP_ABORTED  = 0
	XDP_DROP     = 1
	XDP_PASS     = 2
	XDP_TX       = 3
	XDP_REDIRECT = 4
)
