package cplane

import (
	"context"
	"testing"
	"time"

	"github.com/takehaya/vinbero/pkg/bgp"
)

func TestMUPObserverReplacementClearsInheritedOutput(t *testing.T) {
	for _, backend := range []string{BackendNative, BackendWASM} {
		for _, observe := range []string{`,"observe_only":true`, ""} {
			mode := "explicit"
			if observe == "" {
				mode = "default"
			}
			t.Run(backend+"/"+mode, func(t *testing.T) {
				source := &compositionSource{newFakeSource()}
				source.rib = mupFixture(t)
				reg := handoffRegistration(t, backend)
				reg.Name = "observer-replacement"
				observerReplacement(t, source, reg, `{"context":"mobile","source":"fd00:feed::1","args_offset":7`, observe)
			})
		}
	}
}

// The observer does not submit an empty desired set; the manager must remove
// inherited state when the opaque business configuration changes.
func observerReplacement(t *testing.T, source *compositionSource, reg Registration, config, observe string) {
	t.Helper()
	maps := newServiceFake()
	reg.Config = []byte(config + `,"observe_only":false}`)
	manager, err := NewManager(ManagerConfig{AllowNative: true, Source: source, Headend: maps, ForwardingMaps: maps, ResolveMUPInstance: func(string) (uint32, error) { return 7, nil }, ResolveInputTarget: func(bgp.RouteEvent) (string, uint16, bool) {
		if reg.Input.Contexts[0].BridgeDomain != 0 {
			return "", uint16(reg.Input.Contexts[0].BridgeDomain), true
		}
		return "", 0, true
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close(context.Background())
	idle := func() {
		t.Helper()
		if !manager.WaitIdle(reg.Name, 5*time.Second) {
			t.Fatal("worker did not drain")
		}
		st, _ := manager.StatsFor(reg.Name)
		if !st.InputReady || st.InputFault != "" || st.OutputFailure != "" {
			t.Fatalf("unhealthy: %+v", st)
		}
	}
	count := func() int {
		return len(maps.v4) + len(maps.v6) + len(maps.uplinks) + len(maps.uplinks6) + len(maps.fdb) + len(maps.peers)
	}
	if err = manager.Register(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	idle()
	if count() == 0 {
		t.Fatal("writer installed no output")
	}
	reg.Config = []byte(config + observe + `}`)
	if err = manager.Register(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	idle()
	if count() != 0 {
		t.Fatalf("observer inherited %d forwarding entries", count())
	}
	withdrawal := source.rib[1]
	withdrawal.IsWithdraw = true
	source.emit(reg.Name, withdrawal)
	idle()
	if count() != 0 {
		t.Fatalf("observer retained output after withdrawal: %d", count())
	}
	// Going back to writing replays the current RIB and can publish normally.
	reg.Config = []byte(config + `,"observe_only":false}`)
	if err = manager.Register(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	idle()
	if count() == 0 {
		t.Fatal("writer did not recover after replacement")
	}
}
