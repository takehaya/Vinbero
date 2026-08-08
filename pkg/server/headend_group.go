package server

import (
	"context"
	"fmt"
	"net/netip"
	"sort"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// HeadendGroupServer exposes the ECMP path groups the headend resolves
// through. Read-only: the BGP receive path writes groups as routes arrive,
// so there is nothing here to create.
type HeadendGroupServer struct {
	mapOps *bpf.MapOperations
}

func NewHeadendGroupServer(mapOps *bpf.MapOperations) *HeadendGroupServer {
	return &HeadendGroupServer{mapOps: mapOps}
}

// groupPrefixes builds group id -> trigger prefixes by scanning the headend
// maps.
//
// The group table does not record which prefix it serves: the owner tag has
// no room for one, so the association only exists in the trigger entries
// that point at a group. Deriving it here rather than asking the applier
// means the answer is the same whoever installed the group, and survives a
// restart that cleared the applier's own state.
func (s *HeadendGroupServer) groupPrefixes() (map[uint32][]string, error) {
	out := make(map[uint32][]string)
	v4, err := s.mapOps.ListHeadendV4()
	if err != nil {
		return nil, err
	}
	v6, err := s.mapOps.ListHeadendV6()
	if err != nil {
		return nil, err
	}
	for _, entries := range []map[string]*bpf.HeadendEntry{v4, v6} {
		for prefix, e := range entries {
			if e.GroupId == bpf.EcmpGroupNone {
				continue
			}
			out[e.GroupId] = append(out[e.GroupId], prefix)
		}
	}
	for id := range out {
		sort.Strings(out[id])
	}
	return out, nil
}

// buildGroup renders one group. paths comes from GetEcmpGroup and may hold
// nil elements: a group being resized is briefly missing a path entry the
// info already counts, and reporting that hole is more useful than hiding
// it behind a shorter list.
func buildGroup(
	groupID uint32,
	info *bpf.EcmpGroupInfo,
	paths []*bpf.HeadendEntry,
	prefixes []string,
	owner bpf.OwnerTag,
	liveBitmap uint64,
	liveKnown bool,
) *v1.HeadendGroup {
	g := &v1.HeadendGroup{
		GroupId:    groupID,
		Prefixes:   prefixes,
		Owner:      string(owner),
		LiveBitmap: liveBitmap,
		LiveKnown:  liveKnown,
	}
	for i, pe := range paths {
		m := &v1.HeadendGroupMember{Index: uint32(i)}
		if i < len(info.Weight) {
			m.Weight = uint32(info.Weight[i])
		}
		// A group with no liveness entry is used in full rather than treated
		// as entirely down, so report every path live in that case.
		m.Live = !liveKnown || liveBitmap&(1<<uint(i)) != 0
		if pe != nil {
			m.PolicyId = pe.PolicyId
			m.Segments = segmentStrings(pe)
		}
		g.Members = append(g.Members, m)
	}
	return g
}

// segmentStrings renders an entry's segment list, stopping at NumSegments so
// the unused tail of the fixed-size array is not reported as ::.
func segmentStrings(e *bpf.HeadendEntry) []string {
	n := int(e.NumSegments)
	if n > len(e.Segments) {
		n = len(e.Segments)
	}
	out := make([]string, 0, n)
	for i := range n {
		out = append(out, netip.AddrFrom16(e.Segments[i]).String())
	}
	return out
}

func (s *HeadendGroupServer) group(groupID uint32, prefixes []string) (*v1.HeadendGroup, error) {
	info, paths, err := s.mapOps.GetEcmpGroup(groupID)
	if err != nil {
		return nil, err
	}
	if info == nil {
		return nil, nil
	}
	owner, _, err := s.mapOps.EcmpGroupOwner(groupID)
	if err != nil {
		return nil, err
	}
	bitmap, known, err := s.mapOps.GetEcmpLive(groupID)
	if err != nil {
		return nil, err
	}
	return buildGroup(groupID, info, paths, prefixes, owner, bitmap, known), nil
}

func (s *HeadendGroupServer) HeadendGroupList(
	ctx context.Context,
	req *connect.Request[v1.HeadendGroupListRequest],
) (*connect.Response[v1.HeadendGroupListResponse], error) {
	infos, err := s.mapOps.ListEcmpGroups()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	prefixes, err := s.groupPrefixes()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	ids := make([]uint32, 0, len(infos))
	for id := range infos {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	resp := &v1.HeadendGroupListResponse{}
	for _, id := range ids {
		g, err := s.group(id, prefixes[id])
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		if g == nil {
			// Deleted between the list and the read; skip rather than
			// reporting a half-empty group.
			continue
		}
		resp.Groups = append(resp.Groups, g)
	}
	return connect.NewResponse(resp), nil
}

func (s *HeadendGroupServer) HeadendGroupGet(
	ctx context.Context,
	req *connect.Request[v1.HeadendGroupGetRequest],
) (*connect.Response[v1.HeadendGroupGetResponse], error) {
	id := req.Msg.GroupId
	if id == bpf.EcmpGroupNone {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("group id 0 is the no-group sentinel"))
	}
	prefixes, err := s.groupPrefixes()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	g, err := s.group(id, prefixes[id])
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if g == nil {
		return nil, connect.NewError(connect.CodeNotFound,
			fmt.Errorf("ecmp group %d not found", id))
	}
	return connect.NewResponse(&v1.HeadendGroupGetResponse{Group: g}), nil
}
