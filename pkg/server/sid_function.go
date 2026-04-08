package server

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// SidFunctionServer implements the SidFunctionServiceHandler interface
type SidFunctionServer struct {
	mapOps *bpf.MapOperations
}

// NewSidFunctionServer creates a new SidFunctionServer
func NewSidFunctionServer(mapOps *bpf.MapOperations) *SidFunctionServer {
	return &SidFunctionServer{mapOps: mapOps}
}

// SidFunctionCreate creates SID function entries
func (s *SidFunctionServer) SidFunctionCreate(
	ctx context.Context,
	req *connect.Request[v1.SidFunctionCreateRequest],
) (*connect.Response[v1.SidFunctionCreateResponse], error) {
	resp := &v1.SidFunctionCreateResponse{
		Created: make([]*v1.SidFunction, 0),
		Errors:  make([]*v1.OperationError, 0),
	}

	for _, sidFunc := range req.Msg.SidFunctions {
		entry, err := s.protoToEntry(sidFunc)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: sidFunc.TriggerPrefix,
				Reason:        err.Error(),
			})
			continue
		}

		if err := s.mapOps.CreateSidFunction(sidFunc.TriggerPrefix, entry); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: sidFunc.TriggerPrefix,
				Reason:        err.Error(),
			})
			continue
		}

		// Create End.B6 policy entry if segments are specified
		if len(sidFunc.Segments) > 0 {
			policyEntry, err := s.buildPolicyEntry(sidFunc)
			if err != nil {
				// Rollback: remove the SID function entry
				_ = s.mapOps.DeleteSidFunction(sidFunc.TriggerPrefix)
				resp.Errors = append(resp.Errors, &v1.OperationError{
					TriggerPrefix: sidFunc.TriggerPrefix,
					Reason:        fmt.Sprintf("policy: %s", err.Error()),
				})
				continue
			}
			if err := s.mapOps.CreateEndB6Policy(sidFunc.TriggerPrefix, policyEntry); err != nil {
				_ = s.mapOps.DeleteSidFunction(sidFunc.TriggerPrefix)
				resp.Errors = append(resp.Errors, &v1.OperationError{
					TriggerPrefix: sidFunc.TriggerPrefix,
					Reason:        fmt.Sprintf("policy map: %s", err.Error()),
				})
				continue
			}
		}

		resp.Created = append(resp.Created, sidFunc)
	}

	return connect.NewResponse(resp), nil
}

// SidFunctionDelete deletes SID function entries
func (s *SidFunctionServer) SidFunctionDelete(
	ctx context.Context,
	req *connect.Request[v1.SidFunctionDeleteRequest],
) (*connect.Response[v1.SidFunctionDeleteResponse], error) {
	resp := &v1.SidFunctionDeleteResponse{
		DeletedTriggerPrefixes: make([]string, 0),
		Errors:                 make([]*v1.OperationError, 0),
	}

	for _, prefix := range req.Msg.TriggerPrefixes {
		if err := s.mapOps.DeleteSidFunction(prefix); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: prefix,
				Reason:        err.Error(),
			})
			continue
		}
		// Best-effort cleanup of End.B6 policy entry
		_ = s.mapOps.DeleteEndB6Policy(prefix)
		resp.DeletedTriggerPrefixes = append(resp.DeletedTriggerPrefixes, prefix)
	}

	return connect.NewResponse(resp), nil
}

// SidFunctionList lists all SID function entries
func (s *SidFunctionServer) SidFunctionList(
	ctx context.Context,
	req *connect.Request[v1.SidFunctionListRequest],
) (*connect.Response[v1.SidFunctionListResponse], error) {
	entries, err := s.mapOps.ListSidFunctions()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	resp := &v1.SidFunctionListResponse{
		SidFunctions: make([]*v1.SidFunction, 0, len(entries)),
	}

	for prefix, entry := range entries {
		sidFunc := s.entryToProto(prefix, entry)
		resp.SidFunctions = append(resp.SidFunctions, sidFunc)
	}

	return connect.NewResponse(resp), nil
}

// SidFunctionGet retrieves a specific SID function entry
func (s *SidFunctionServer) SidFunctionGet(
	ctx context.Context,
	req *connect.Request[v1.SidFunctionGetRequest],
) (*connect.Response[v1.SidFunctionGetResponse], error) {
	entry, err := s.mapOps.GetSidFunction(req.Msg.TriggerPrefix)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}

	resp := &v1.SidFunctionGetResponse{
		SidFunction: s.entryToProto(req.Msg.TriggerPrefix, entry),
	}

	return connect.NewResponse(resp), nil
}

// protoToEntry converts a protobuf SidFunction to a BPF map entry
func (s *SidFunctionServer) protoToEntry(sidFunc *v1.SidFunction) (*bpf.SidFunctionEntry, error) {
	srcAddr, err := bpf.ParseIPv6(sidFunc.SrcAddr)
	if err != nil {
		return nil, err
	}

	dstAddr, err := bpf.ParseIPv6(sidFunc.DstAddr)
	if err != nil {
		return nil, err
	}

	nexthop, err := bpf.ParseIPv6(sidFunc.Nexthop)
	if err != nil {
		return nil, err
	}

	gtpV4Src, err := bpf.ParseIPv4Optional(sidFunc.GtpV4SrcAddr)
	if err != nil {
		return nil, err
	}

	// Validate GTP-specific fields
	action := v1.Srv6LocalAction(sidFunc.Action)
	if action == v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_M_GTP4_E {
		if sidFunc.GtpV4SrcAddr == "" {
			return nil, fmt.Errorf("gtp_v4_src_addr is required for END_M_GTP4_E")
		}
	}
	if sidFunc.ArgsOffset > 15 {
		return nil, fmt.Errorf("args_offset must be 0-15, got %d", sidFunc.ArgsOffset)
	}

	entry := &bpf.SidFunctionEntry{
		Action:        uint8(sidFunc.Action),
		Flavor:        uint8(sidFunc.Flavor),
		SrcAddr:       srcAddr,
		DstAddr:       dstAddr,
		Nexthop:       nexthop,
		ArgSrcOffset:  uint8(sidFunc.ArgSrcOffset),
		ArgDstOffset:  uint8(sidFunc.ArgDstOffset),
		BdId:          uint16(sidFunc.BdId),
		ArgsOffset: uint8(sidFunc.ArgsOffset),
		GtpV4SrcAddr:  gtpV4Src,
	}

	// Resolve vrf_name → vrf_ifindex for End.DT4/DT6/DT46
	if sidFunc.VrfName != "" {
		vrfIfindex, err := resolveIfindex(sidFunc.VrfName)
		if err != nil {
			return nil, fmt.Errorf("vrf %q: %w", sidFunc.VrfName, err)
		}
		entry.VrfIfindex = vrfIfindex
	}

	// Resolve bridge_name → bridge_ifindex for End.DT2
	if sidFunc.BridgeName != "" {
		bridgeIfindex, err := resolveIfindex(sidFunc.BridgeName)
		if err != nil {
			return nil, fmt.Errorf("bridge %q: %w", sidFunc.BridgeName, err)
		}
		entry.BridgeIfindex = bridgeIfindex
	}

	return entry, nil
}

// entryToProto converts a BPF map entry to a protobuf SidFunction
func (s *SidFunctionServer) entryToProto(prefix string, entry *bpf.SidFunctionEntry) *v1.SidFunction {
	sf := &v1.SidFunction{
		Action:        v1.Srv6LocalAction(entry.Action),
		TriggerPrefix: prefix,
		SrcAddr:       bpf.FormatIPv6(entry.SrcAddr),
		DstAddr:       bpf.FormatIPv6(entry.DstAddr),
		Nexthop:       bpf.FormatIPv6(entry.Nexthop),
		Flavor:        v1.Srv6LocalFlavor(entry.Flavor),
		ArgSrcOffset:  uint32(entry.ArgSrcOffset),
		ArgDstOffset:  uint32(entry.ArgDstOffset),
		VrfName:       ifindexToName(entry.VrfIfindex),
		BdId:          uint32(entry.BdId),
		BridgeName:    ifindexToName(entry.BridgeIfindex),
		ArgsOffset: uint32(entry.ArgsOffset),
		GtpV4SrcAddr:  bpf.FormatIPv4Optional(entry.GtpV4SrcAddr),
	}

	// Include policy fields for End.B6/End.B6.Encaps from policy map
	if entry.Action == uint8(v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_B6) ||
		entry.Action == uint8(v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_B6_ENCAPS) {
		policy, err := s.mapOps.GetEndB6Policy(prefix)
		if err == nil && policy != nil {
			sf.Segments = bpf.FormatSegments(policy.Segments, policy.NumSegments)
			sf.HeadendMode = v1.Srv6HeadendBehavior(policy.Mode)
		}
	}

	return sf
}

// buildPolicyEntry creates a HeadendEntry for the End.B6 policy map
func (s *SidFunctionServer) buildPolicyEntry(sidFunc *v1.SidFunction) (*bpf.HeadendEntry, error) {
	srcAddr, err := bpf.ParseIPv6(sidFunc.SrcAddr)
	if err != nil {
		return nil, err
	}

	segments, numSegments, err := bpf.ParseSegments(sidFunc.Segments)
	if err != nil {
		return nil, err
	}

	return &bpf.HeadendEntry{
		Mode:        uint8(sidFunc.HeadendMode),
		NumSegments: numSegments,
		SrcAddr:     srcAddr,
		Segments:    segments,
	}, nil
}
