package server

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"go.uber.org/zap"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/locator"
)

// locator_ref registration is action-aware: uN/uT take the uSID locator's
// own prefix (nothing allocated), uA and the /64-shaped REPLACE behaviors
// mint a function CSID (the allocation doubling as the uSID claim), and
// everything else keeps the classic /128 materialization.

func lrefServer(t *testing.T, mgr *locator.Manager) *SidFunctionServer {
	t.Helper()
	return NewSidFunctionServer(nil, nil, mgr, zap.NewNop())
}

func lref(action v1.Srv6LocalAction, name string, fn *uint32) *v1.SidFunction {
	return &v1.SidFunction{
		Action:     action,
		LocatorRef: &v1.LocatorRef{Name: name, Function: fn},
	}
}

func TestResolveLocatorRef_UsidShapes(t *testing.T) {
	u32 := func(v uint32) *uint32 { return &v }

	t.Run("uN takes the locator prefix without allocating", func(t *testing.T) {
		mgr := usidLocator(t, "loc1", "fd00:aaaa:b002::/48")
		s := lrefServer(t, mgr)
		sf := lref(v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_UN, "loc1", nil)
		release, err := s.resolveLocatorRef(sf)
		if err != nil {
			t.Fatalf("resolveLocatorRef: %v", err)
		}
		release()
		if sf.TriggerPrefix != "fd00:aaaa:b002::/48" {
			t.Errorf("trigger = %q, want the locator /48", sf.TriggerPrefix)
		}
		// Nothing was allocated: the whole function range stays free.
		fn := uint32(0xd004)
		if _, _, err := mgr.AllocateSID("loc1", &fn); err != nil {
			t.Errorf("uN locator_ref must not consume a function: %v", err)
		}
	})

	t.Run("uN rejects a pinned function", func(t *testing.T) {
		s := lrefServer(t, usidLocator(t, "loc1", "fd00:aaaa:b002::/48"))
		_, err := s.resolveLocatorRef(lref(v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_UN, "loc1", u32(5)))
		if err == nil || !strings.Contains(err.Error(), "no function CSID") {
			t.Fatalf("err = %v, want function rejection", err)
		}
	})

	t.Run("uN rejects a classic locator", func(t *testing.T) {
		mgr := locator.NewManager()
		if err := mgr.Add(&locator.Locator{
			Name: "cls", Prefix: netip.MustParsePrefix("fd00:cccc::/48"),
			BlockLen: 32, NodeLen: 16, FunctionLen: 16, ArgumentLen: 64,
			Behavior: locator.BehaviorClassic, FunctionAutoStart: 1, FunctionAutoEnd: 0xfffe,
		}); err != nil {
			t.Fatalf("add classic locator: %v", err)
		}
		s := lrefServer(t, mgr)
		_, err := s.resolveLocatorRef(lref(v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_UN, "cls", nil))
		if err == nil || !strings.Contains(err.Error(), "usid locator") {
			t.Fatalf("err = %v, want usid-locator requirement", err)
		}
	})

	t.Run("uA mints a /64 and the allocation is the claim", func(t *testing.T) {
		mgr := usidLocator(t, "loc1", "fd00:aaaa:b002::/48")
		s := lrefServer(t, mgr)
		sf := lref(v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_UA, "loc1", u32(0xd004))
		release, err := s.resolveLocatorRef(sf)
		if err != nil {
			t.Fatalf("resolveLocatorRef: %v", err)
		}
		if sf.TriggerPrefix != "fd00:aaaa:b002:d004::/64" {
			t.Errorf("trigger = %q, want fd00:aaaa:b002:d004::/64", sf.TriggerPrefix)
		}
		fn := uint32(0xd004)
		if _, _, err := mgr.AllocateSID("loc1", &fn); err == nil {
			t.Error("the minted CSID must be claimed against service SIDs")
		}
		release()
		if _, _, err := mgr.AllocateSID("loc1", &fn); err != nil {
			t.Errorf("after release: %v", err)
		}
	})

	t.Run("REPLACE derives the block length and mints a /64", func(t *testing.T) {
		mgr := usidLocator(t, "loc1", "fd00:aaaa:b002::/48")
		s := lrefServer(t, mgr)
		sf := lref(v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_REPLACE, "loc1", u32(0xd004))
		if _, err := s.resolveLocatorRef(sf); err != nil {
			t.Fatalf("resolveLocatorRef: %v", err)
		}
		if sf.TriggerPrefix != "fd00:aaaa:b002:d004::/64" {
			t.Errorf("trigger = %q, want /64", sf.TriggerPrefix)
		}
		if sf.UsidBlockLen == nil || *sf.UsidBlockLen != 32 {
			t.Errorf("usid_block_len = %v, want derived 32", sf.UsidBlockLen)
		}
	})

	t.Run("REPLACE rejects a contradicting block length", func(t *testing.T) {
		s := lrefServer(t, usidLocator(t, "loc1", "fd00:aaaa:b002::/48"))
		sf := lref(v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_REPLACE, "loc1", u32(0xd004))
		bl := uint32(48)
		sf.UsidBlockLen = &bl
		if _, err := s.resolveLocatorRef(sf); err == nil || !strings.Contains(err.Error(), "contradicts") {
			t.Fatalf("err = %v, want contradiction rejection", err)
		}
	})

	t.Run("REPLACE rejects csid_len 16 from a locator_ref", func(t *testing.T) {
		s := lrefServer(t, usidLocator(t, "loc1", "fd00:aaaa:b002::/48"))
		sf := lref(v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_X_REPLACE, "loc1", u32(0xd004))
		cl := uint32(16)
		sf.CsidLen = &cl
		if _, err := s.resolveLocatorRef(sf); err == nil || !strings.Contains(err.Error(), "csid_len 32 only") {
			t.Fatalf("err = %v, want csid_len rejection", err)
		}
	})

	t.Run("End.LBS takes the locator prefix like uN", func(t *testing.T) {
		s := lrefServer(t, usidLocator(t, "loc1", "fd00:aaaa:b002::/48"))
		sf := lref(v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_LBS, "loc1", nil)
		if _, err := s.resolveLocatorRef(sf); err != nil {
			t.Fatalf("resolveLocatorRef: %v", err)
		}
		if sf.TriggerPrefix != "fd00:aaaa:b002::/48" {
			t.Errorf("trigger = %q, want the locator /48", sf.TriggerPrefix)
		}
	})

	t.Run("End.XLBS mints a /64 like uA", func(t *testing.T) {
		s := lrefServer(t, usidLocator(t, "loc1", "fd00:aaaa:b002::/48"))
		sf := lref(v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_XLBS, "loc1", u32(0xd004))
		if _, err := s.resolveLocatorRef(sf); err != nil {
			t.Fatalf("resolveLocatorRef: %v", err)
		}
		if sf.TriggerPrefix != "fd00:aaaa:b002:d004::/64" {
			t.Errorf("trigger = %q, want /64", sf.TriggerPrefix)
		}
	})

	t.Run("a pinned CSID held by a service SID collides", func(t *testing.T) {
		mgr := usidLocator(t, "loc1", "fd00:aaaa:b002::/48")
		fn := uint32(0xd004)
		if _, _, err := mgr.AllocateSID("loc1", &fn); err != nil {
			t.Fatalf("service SID allocation: %v", err)
		}
		s := lrefServer(t, mgr)
		if _, err := s.resolveLocatorRef(lref(v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_UA, "loc1", &fn)); err == nil {
			t.Fatal("minting a CSID a service SID holds must fail")
		}
	})
}

// The materialized prefix flows through protoToEntry's own validation:
// a locator-minted uA /64 passes the shape checks by construction.
func TestResolveLocatorRef_FeedsProtoToEntry(t *testing.T) {
	mgr := usidLocator(t, "loc1", "fd00:aaaa:b002::/48")
	s := lrefServer(t, mgr)
	sf := lref(v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_UA, "loc1", nil)
	sf.Nexthop = "fe80::1"
	if _, err := s.resolveLocatorRef(sf); err != nil {
		t.Fatalf("resolveLocatorRef: %v", err)
	}
	if _, _, err := s.protoToEntry(sf); err != nil {
		t.Fatalf("protoToEntry on the minted prefix: %v", err)
	}
}

// End-to-end lifecycle with the real maps: a locator_ref uA creates a /64
// whose function stays claimed across an upsert (the pinned re-create
// resolves to the same prefix without double-allocating) and returns to
// the pool on delete.
func TestLocatorRefUA_CreateUpsertDelete(t *testing.T) {
	objs, err := bpf.ReadCollection(nil, nil)
	if err != nil {
		t.Skipf("BPF collection load failed (needs sudo): %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	mgr := usidLocator(t, "loc1", "fd00:aaaa:b002::/48")
	s := NewSidFunctionServer(bpf.NewMapOperations(objs), nil, mgr, zap.NewNop())

	fn := uint32(0xd004)
	mk := func() *v1.SidFunction {
		sf := lref(v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_UA, "loc1", &fn)
		sf.Nexthop = "fe80::1"
		return sf
	}
	if err := s.createOneSidFunction(mk()); err != nil {
		t.Fatalf("first create: %v", err)
	}
	const prefix = "fd00:aaaa:b002:d004::/64"
	t.Cleanup(func() { _ = s.deleteOneSidFunction(prefix) })

	upsert := mk()
	if err := s.createOneSidFunction(upsert); err != nil {
		t.Fatalf("pinned upsert: %v", err)
	}
	if upsert.TriggerPrefix != prefix {
		t.Errorf("upsert prefix = %q, want %q", upsert.TriggerPrefix, prefix)
	}
	if _, _, err := mgr.AllocateSID("loc1", &fn); !errors.Is(err, locator.ErrFunctionInUse) {
		t.Fatalf("CSID after upsert: err = %v, want ErrFunctionInUse", err)
	}
	if err := s.deleteOneSidFunction(prefix); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, _, err := mgr.AllocateSID("loc1", &fn); err != nil {
		t.Fatalf("CSID was not released on delete: %v", err)
	}
}

// A uSID locator whose own prefix is an installed uN/uT trigger cannot be
// deleted without force: the entry holds no allocation binding, so the
// guard is the only thing standing between the delete and a stranded
// shift entry.
func TestDeleteLocatorGuarded_UsidPrefixTrigger(t *testing.T) {
	objs, err := bpf.ReadCollection(nil, nil)
	if err != nil {
		t.Skipf("BPF collection load failed (needs sudo): %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	mgr := usidLocator(t, "loc1", "fd00:aaaa:b002::/48")
	s := NewSidFunctionServer(bpf.NewMapOperations(objs), nil, mgr, zap.NewNop())

	sf := lref(v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_UN, "loc1", nil)
	if err := s.createOneSidFunction(sf); err != nil {
		t.Fatalf("create uN from locator_ref: %v", err)
	}
	t.Cleanup(func() { _ = s.deleteOneSidFunction("fd00:aaaa:b002::/48") })

	if err := s.DeleteLocatorGuarded("loc1", false); err == nil ||
		!strings.Contains(err.Error(), "is the trigger of SID entry") {
		t.Fatalf("unforced delete: err = %v, want trigger-reference refusal", err)
	}
	if err := s.deleteOneSidFunction("fd00:aaaa:b002::/48"); err != nil {
		t.Fatalf("delete the entry: %v", err)
	}
	if err := s.DeleteLocatorGuarded("loc1", false); err != nil {
		t.Fatalf("delete after the entry is gone: %v", err)
	}
}

// LocatorCreate echoes the STORED (host-bit-normalized) locator, not the
// request, so the response matches what Get/List and locator_ref resolve.
func TestLocatorCreate_ResponseIsNormalized(t *testing.T) {
	mgr := locator.NewManager()
	ls := NewLocatorServer(mgr, nil, nil)
	resp, err := ls.LocatorCreate(t.Context(), connect.NewRequest(&v1.LocatorCreateRequest{
		Locators: []*v1.Locator{{
			Name: "hb", Prefix: "fd00:aaaa:b002::1/48",
			BlockLen: 32, NodeLen: 16, FunctionLen: 16,
			Behavior: v1.LocatorBehaviorMode_LOCATOR_BEHAVIOR_MODE_USID, FunctionAutoStart: 1, FunctionAutoEnd: 0xfffe,
		}},
	}))
	if err != nil {
		t.Fatalf("LocatorCreate: %v", err)
	}
	if len(resp.Msg.Created) != 1 || len(resp.Msg.Errors) != 0 {
		t.Fatalf("created=%d errors=%v", len(resp.Msg.Created), resp.Msg.Errors)
	}
	if got := resp.Msg.Created[0].Prefix; got != "fd00:aaaa:b002::/48" {
		t.Errorf("created prefix = %q, want the normalized fd00:aaaa:b002::/48", got)
	}
}
