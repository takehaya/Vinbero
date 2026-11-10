package server

import (
	"context"
	"errors"
	"fmt"
	"github.com/vishvananda/netlink"
	"net"
	"sync"

	"connectrpc.com/connect"
	"github.com/cilium/ebpf"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// HeadendL2Server implements the HeadendL2ServiceHandler interface
type HeadendL2Server struct {
	mapOps *bpf.MapOperations
	// createEntry, deleteEntry and linkGone default to mapOps and the
	// kernel; tests replace them.
	createEntry func(ifindex uint32, vlan uint16, entry *bpf.HeadendEntry, esi [bpf.ESILen]byte) error
	deleteEntry func(ifindex uint32, vlan uint16) error
	linkGone    func(ifindex uint32) bool
	// closedVRF names the managed VRF whose closed table (it ends in the
	// unreachable default) the interface is enslaved to. Nil (the default
	// until SetClosedVRFCheck) refuses nothing.
	closedVRF func(ifindex uint32) (string, bool, error)
	// vrfMu is VrfServer's mutation lock, held from the check to the write
	// so a concurrent VrfCreate cannot close the port's table in between
	// (or enslave the port after its own check).
	vrfMu *sync.Mutex
}

// SetClosedVRFCheck installs the check HeadendL2Create refuses a port with,
// and the VRF mutation lock it runs under (VrfServer's).
func (s *HeadendL2Server) SetClosedVRFCheck(fn func(ifindex uint32) (string, bool, error), vrfMu *sync.Mutex) {
	s.closedVRF = fn
	s.vrfMu = vrfMu
}

// NewHeadendL2Server creates a new HeadendL2Server
func NewHeadendL2Server(mapOps *bpf.MapOperations) *HeadendL2Server {
	s := &HeadendL2Server{mapOps: mapOps, linkGone: ifindexGone}
	if mapOps != nil {
		s.createEntry = mapOps.CreateHeadendL2
		s.deleteEntry = mapOps.DeleteHeadendL2
	}
	return s
}

// ifindexGone reports whether no interface has this index. A lookup that
// fails for another reason is not an answer.
func ifindexGone(ifindex uint32) bool {
	_, err := netlink.LinkByIndex(int(ifindex))
	return errors.As(err, &netlink.LinkNotFoundError{})
}

// deleteTarget removes one entry. A name that resolves to nothing, or an
// interface with no such entry, is reported as v1.ReasonNotFound: a typo and a
// renamed interface are visible, and the link watcher removes the entries of
// a deleted interface, so a caller doing teardown treats it as already gone.
func (s *HeadendL2Server) deleteTarget(name string, vlan uint16) error {
	if err := validateIfname(name); err != nil {
		return err
	}
	link, err := netlink.LinkByName(name)
	if errors.As(err, &netlink.LinkNotFoundError{}) {
		return fmt.Errorf("%s: interface %q", v1.ReasonNotFound, name)
	}
	if err != nil {
		return fmt.Errorf("look up interface %q: %w", name, err)
	}
	err = s.deleteEntry(uint32(link.Attrs().Index), vlan)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("%s: interface %q has no entry for VLAN %d", v1.ReasonNotFound, name, vlan)
	}
	return err
}

// refuseVrfPort rejects an L2 circuit on a port enslaved to a managed VRF
// whose table ends in the unreachable default. An L2 circuit's encapsulations
// and BUM copies are looked up on the source port, so on such a port they go
// to the VRF table and stop there. Ports of other VRFs (unmanaged, opted
// out) work as they always have.
func (s *HeadendL2Server) refuseVrfPort(name string, ifindex uint32) error {
	if s.closedVRF == nil {
		return nil
	}
	vrf, closed, err := s.closedVRF(ifindex)
	if err != nil {
		return err
	}
	if closed {
		return fmt.Errorf("interface %q is a port of VRF %q, whose table ends in the unreachable default: "+
			"an L2 headend circuit on it would be dropped there (use a bridge port or a port in no VRF, or opt the VRF out)", name, vrf)
	}
	return nil
}

func resolveIfindex(name string) (uint32, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, fmt.Errorf("interface %q not found: %w", name, err)
	}
	return uint32(iface.Index), nil
}

// requireVrfDevice verifies that name is an actual VRF device, not just
// any resolvable interface.
func requireVrfDevice(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("vrf %q: %w", name, err)
	}
	if _, ok := link.(*netlink.Vrf); !ok {
		return fmt.Errorf("%q is a %s device, not a vrf", name, link.Type())
	}
	return nil
}

func ifindexToName(ifindex uint32) string {
	if ifindex == 0 {
		return ""
	}
	if iface, err := net.InterfaceByIndex(int(ifindex)); err == nil {
		return iface.Name
	}
	return ""
}

// HeadendL2Create creates Headend L2 entries
func (s *HeadendL2Server) HeadendL2Create(
	ctx context.Context,
	req *connect.Request[v1.HeadendL2CreateRequest],
) (*connect.Response[v1.HeadendL2CreateResponse], error) {
	resp := &v1.HeadendL2CreateResponse{
		Created: make([]*v1.HeadendL2, 0),
		Errors:  make([]*v1.OperationError, 0),
	}
	if s.vrfMu != nil {
		s.vrfMu.Lock()
		defer s.vrfMu.Unlock()
	}

	for _, headend := range req.Msg.HeadendL2S {
		ifindex, err := resolveIfindex(headend.InterfaceName)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("%s:vlan_%d", headend.InterfaceName, headend.VlanId),
				Reason:        err.Error(),
			})
			continue
		}

		if err := s.refuseVrfPort(headend.InterfaceName, ifindex); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("%s:vlan_%d", headend.InterfaceName, headend.VlanId),
				Reason:        err.Error(),
			})
			continue
		}

		entry, err := s.protoToEntry(headend)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("%s:vlan_%d", headend.InterfaceName, headend.VlanId),
				Reason:        err.Error(),
			})
			continue
		}

		esi, err := bpf.ParseESI(headend.Esi)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("%s:vlan_%d", headend.InterfaceName, headend.VlanId),
				Reason:        err.Error(),
			})
			continue
		}

		if err := s.createEntry(ifindex, uint16(headend.VlanId), entry, esi); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("%s:vlan_%d", headend.InterfaceName, headend.VlanId),
				Reason:        err.Error(),
			})
			continue
		}
		// The interface can vanish between the lookup and the write, and the
		// link watcher would then not see the entry.
		if s.linkGone(ifindex) {
			reason := fmt.Sprintf("interface %q was deleted during the create", headend.InterfaceName)
			if err := s.deleteEntry(ifindex, uint16(headend.VlanId)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				reason = fmt.Sprintf("%s; removing the entry failed: %v", reason, err)
			}
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("%s:vlan_%d", headend.InterfaceName, headend.VlanId),
				Reason:        reason,
			})
			continue
		}

		resp.Created = append(resp.Created, headend)
	}

	return connect.NewResponse(resp), nil
}

// HeadendL2Delete deletes Headend L2 entries
func (s *HeadendL2Server) HeadendL2Delete(
	ctx context.Context,
	req *connect.Request[v1.HeadendL2DeleteRequest],
) (*connect.Response[v1.HeadendL2DeleteResponse], error) {
	resp := &v1.HeadendL2DeleteResponse{
		Deleted: make([]*v1.HeadendL2DeleteTarget, 0),
		Errors:  make([]*v1.OperationError, 0),
	}

	for _, target := range req.Msg.Targets {
		if err := s.deleteTarget(target.InterfaceName, uint16(target.VlanId)); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("%s:vlan_%d", target.InterfaceName, target.VlanId),
				Reason:        err.Error(),
			})
			continue
		}
		resp.Deleted = append(resp.Deleted, target)
	}

	return connect.NewResponse(resp), nil
}

// HeadendL2Flush removes every headend L2 entry.
func (s *HeadendL2Server) HeadendL2Flush(
	ctx context.Context,
	req *connect.Request[v1.HeadendL2FlushRequest],
) (*connect.Response[v1.HeadendL2FlushResponse], error) {
	count, err := s.mapOps.FlushHeadendL2()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&v1.HeadendL2FlushResponse{DeletedCount: count}), nil
}

// HeadendL2List lists all Headend L2 entries
func (s *HeadendL2Server) HeadendL2List(
	ctx context.Context,
	req *connect.Request[v1.HeadendL2ListRequest],
) (*connect.Response[v1.HeadendL2ListResponse], error) {
	entries, err := s.mapOps.ListHeadendL2()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	resp := &v1.HeadendL2ListResponse{
		HeadendL2S: make([]*v1.HeadendL2, 0, len(entries)),
	}

	for key, entry := range entries {
		headend := s.entryToProto(key, entry)
		resp.HeadendL2S = append(resp.HeadendL2S, headend)
	}

	return connect.NewResponse(resp), nil
}

// HeadendL2Get retrieves a specific Headend L2 entry
func (s *HeadendL2Server) HeadendL2Get(
	ctx context.Context,
	req *connect.Request[v1.HeadendL2GetRequest],
) (*connect.Response[v1.HeadendL2GetResponse], error) {
	ifindex, err := resolveIfindex(req.Msg.InterfaceName)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	entry, err := s.mapOps.GetHeadendL2(ifindex, uint16(req.Msg.VlanId))
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}

	key := bpf.HeadendL2Key{Ifindex: ifindex, VlanId: uint16(req.Msg.VlanId)}
	resp := &v1.HeadendL2GetResponse{
		HeadendL2: s.entryToProto(key, entry),
	}

	return connect.NewResponse(resp), nil
}

// buildL2HeadendEntry builds a HeadendEntry from L2 headend parameters.
// Shared by HeadendL2Server and BdPeerServer.
func buildL2HeadendEntry(srcAddrStr string, segments []string, mode v1.Srv6HeadendBehavior, bdID uint32) (*bpf.HeadendEntry, error) {
	srcAddr, err := bpf.ParseIPv6(srcAddrStr)
	if err != nil {
		return nil, err
	}

	segs, numSegments, err := bpf.ParseSegments(segments)
	if err != nil {
		return nil, err
	}

	m := uint8(mode)
	if mode == v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_UNSPECIFIED {
		m = uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2)
	}

	return &bpf.HeadendEntry{
		Mode:        m,
		NumSegments: numSegments,
		SrcAddr:     srcAddr,
		Segments:    segs,
		BdId:        uint16(bdID),
	}, nil
}

// protoToEntry converts a protobuf HeadendL2 to a BPF map entry
func (s *HeadendL2Server) protoToEntry(headend *v1.HeadendL2) (*bpf.HeadendEntry, error) {
	return buildL2HeadendEntry(headend.SrcAddr, headend.Segments, headend.Mode, headend.BdId)
}

// entryToProto converts a BPF map entry to a protobuf HeadendL2
func (s *HeadendL2Server) entryToProto(key bpf.HeadendL2Key, entry *bpf.HeadendEntry) *v1.HeadendL2 {
	// Reverse-resolve ifindex to interface name (best-effort)
	ifaceName := fmt.Sprintf("ifindex:%d", key.Ifindex)
	if iface, err := net.InterfaceByIndex(int(key.Ifindex)); err == nil {
		ifaceName = iface.Name
	}

	out := &v1.HeadendL2{
		VlanId:        uint32(key.VlanId),
		SrcAddr:       bpf.FormatIPv6(entry.SrcAddr),
		Segments:      bpf.FormatSegments(entry.Segments, entry.NumSegments),
		BdId:          uint32(entry.BdId),
		InterfaceName: ifaceName,
		Mode:          v1.Srv6HeadendBehavior(entry.Mode),
	}
	if esi, err := s.mapOps.GetHeadendL2Esi(key.Ifindex, key.VlanId); err == nil {
		out.Esi = bpf.FormatESI(esi)
	}
	return out
}
