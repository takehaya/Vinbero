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

// A member the config file declares for the attached bridge is enslaved
// again on every start, so removing it at runtime is refused; members added
// at runtime stay removable, and the claim goes with the bridge: a different
// bridge attached later with the same port does not inherit it.
func TestVrfServer_BridgeMemberRemoveRefusesConfigMember(t *testing.T) {
	s, _, _, _, events := newTestVrfServerBridge(&fakeEvpnBridge{})
	ctx := context.Background()
	attach := func(br string, bd uint32) {
		t.Helper()
		if _, err := s.VrfBridgeAttach(ctx, connect.NewRequest(&v1.VrfBridgeAttachRequest{
			VrfName: "evi-100", Bridge: &v1.Bridge{Name: br, BdId: bd, Members: []string{"eth1"}},
		})); err != nil {
			t.Fatalf("VrfBridgeAttach %s: %v", br, err)
		}
	}
	remove := func(member string) error {
		_, err := s.VrfBridgeMemberRemove(ctx, connect.NewRequest(&v1.VrfBridgeMemberRemoveRequest{
			VrfName: "evi-100", InterfaceName: member,
		}))
		return err
	}
	// What loadVRFs does for vrfs.entries[{name: evi-100, bridge: {br100, [eth1]}}].
	attach("br100", 100)
	if err := s.mgr.SetConfigBridgeMembers("evi-100", "br100", []string{"eth1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.VrfBridgeMemberAdd(ctx, connect.NewRequest(&v1.VrfBridgeMemberAddRequest{
		VrfName: "evi-100", InterfaceName: "veth1",
	})); err != nil {
		t.Fatalf("VrfBridgeMemberAdd: %v", err)
	}
	// An idempotent re-attach over the API keeps the config's claim.
	attach("br100", 100)
	*events = nil

	if err := remove("eth1"); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("removing a config member: %v, want FailedPrecondition", err)
	}
	if len(*events) != 0 {
		t.Errorf("refused remove reached the bridge ops: %v", *events)
	}
	if err := remove("veth1"); err != nil {
		t.Fatalf("removing a runtime member: %v", err)
	}

	// Detach br100 and attach br101 with eth1 at runtime: eth1 is now an
	// API member of another bridge and can be removed.
	if _, err := s.VrfBridgeDetach(ctx, connect.NewRequest(&v1.VrfBridgeDetachRequest{VrfName: "evi-100"})); err != nil {
		t.Fatalf("VrfBridgeDetach: %v", err)
	}
	attach("br101", 101)
	if err := remove("eth1"); err != nil {
		t.Errorf("removing eth1 from a runtime bridge: %v", err)
	}
	if err := s.mgr.SetConfigBridgeMembers("evi-100", "br100", []string{"eth1"}); err == nil {
		t.Error("config members recorded for a bridge the VRF does not carry")
	}
}
