package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"connectrpc.com/connect"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/netresource"
)

// VrfBridgeMemberAdd / Remove drive the bridge ops of the attached facet and
// return the facet with its members updated; the FDB watcher and EVPN are not
// touched.
func TestVrfServer_BridgeMembers(t *testing.T) {
	hook := &fakeEvpnBridge{}
	s, bridges, _, _, events := newTestVrfServerBridge(hook)
	if _, err := s.VrfBridgeAttach(context.Background(), connect.NewRequest(&v1.VrfBridgeAttachRequest{
		VrfName: "evi-100", Bridge: &v1.Bridge{Name: "br100", BdId: 100},
	})); err != nil {
		t.Fatalf("VrfBridgeAttach: %v", err)
	}
	enables := hook.enableCnt
	*events = nil

	add, err := s.VrfBridgeMemberAdd(context.Background(), connect.NewRequest(&v1.VrfBridgeMemberAddRequest{
		VrfName: "evi-100", InterfaceName: "veth1",
	}))
	if err != nil {
		t.Fatalf("VrfBridgeMemberAdd: %v", err)
	}
	if got := add.Msg.GetVrf().GetBridge().GetMembers(); !slices.Equal(got, []string{"veth1"}) {
		t.Errorf("members after add = %v", got)
	}
	rm, err := s.VrfBridgeMemberRemove(context.Background(), connect.NewRequest(&v1.VrfBridgeMemberRemoveRequest{
		VrfName: "evi-100", InterfaceName: "veth1",
	}))
	if err != nil {
		t.Fatalf("VrfBridgeMemberRemove: %v", err)
	}
	if got := rm.Msg.GetVrf().GetBridge().GetMembers(); len(got) != 0 {
		t.Errorf("members after remove = %v", got)
	}
	want := []string{"member-add:br100:veth1", "member-remove:br100:veth1"}
	if !slices.Equal(*events, want) {
		t.Errorf("events = %v, want %v (no FDB registration change)", *events, want)
	}
	if hook.enableCnt != enables || hook.disableCnt != 0 {
		t.Errorf("member changes touched EVPN: %d enables, %d disables", hook.enableCnt-enables, hook.disableCnt)
	}

	s.mgr.Ensure("no-bridge")
	for _, tc := range []struct {
		vrf, member string
		code        connect.Code
	}{
		{"", "veth1", connect.CodeInvalidArgument},
		{"evi-100", "", connect.CodeInvalidArgument},
		{"evi-100", "a-name-past-15-bytes", connect.CodeInvalidArgument},
		{"evi-100", "../x", connect.CodeInvalidArgument},
		{"missing", "veth1", connect.CodeNotFound},
		{"no-bridge", "veth1", connect.CodeFailedPrecondition},
		{"evi-100", "br100", connect.CodeFailedPrecondition}, // the bridge itself
	} {
		_, err := s.VrfBridgeMemberAdd(context.Background(), connect.NewRequest(&v1.VrfBridgeMemberAddRequest{
			VrfName: tc.vrf, InterfaceName: tc.member,
		}))
		if connect.CodeOf(err) != tc.code {
			t.Errorf("VrfBridgeMemberAdd(%q, %q) = %v, want %v", tc.vrf, tc.member, err, tc.code)
		}
		_, err = s.VrfBridgeMemberRemove(context.Background(), connect.NewRequest(&v1.VrfBridgeMemberRemoveRequest{
			VrfName: tc.vrf, InterfaceName: tc.member,
		}))
		if connect.CodeOf(err) != tc.code {
			t.Errorf("VrfBridgeMemberRemove(%q, %q) = %v, want %v", tc.vrf, tc.member, err, tc.code)
		}
	}
	if len(*events) != 2 {
		t.Errorf("rejected requests reached the bridge ops: %v", *events)
	}

	// The mechanics layer's errors keep their meaning across the RPC.
	for _, tc := range []struct {
		err  error
		code connect.Code
	}{
		{fmt.Errorf("wrap: %w", netresource.ErrNoMember), connect.CodeNotFound},
		{fmt.Errorf("wrap: %w", netresource.ErrPersist), connect.CodeInternal},
		{errors.New("enslaved to another device"), connect.CodeFailedPrecondition},
	} {
		bridges.memberErr = tc.err
		_, err := s.VrfBridgeMemberAdd(context.Background(), connect.NewRequest(&v1.VrfBridgeMemberAddRequest{
			VrfName: "evi-100", InterfaceName: "veth2",
		}))
		if connect.CodeOf(err) != tc.code {
			t.Errorf("ops error %v: code %v, want %v", tc.err, connect.CodeOf(err), tc.code)
		}
	}
}
