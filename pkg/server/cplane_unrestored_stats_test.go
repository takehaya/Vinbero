package server

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/cplane"
)

type unrestoredStatsManager struct{ fakeCplane }

func (*unrestoredStatsManager) Unrestored() []cplane.UnrestoredPlugin {
	return []cplane.UnrestoredPlugin{{Name: "broken", Reason: "module missing", Behaviors: []uint16{0xfe01}}}
}
func TestNamedUnrestoredStats(t *testing.T) {
	s := &PluginServer{cplane: &unrestoredStatsManager{}}
	all, err := s.CplanePluginStats(context.Background(), connect.NewRequest(&v1.CplanePluginStatsRequest{}))
	if err != nil || len(all.Msg.Unrestored) != 1 {
		t.Fatalf("setup: %v, %v", all, err)
	}
	named, err := s.CplanePluginStats(context.Background(), connect.NewRequest(&v1.CplanePluginStatsRequest{Name: "broken"}))
	if err != nil {
		t.Fatalf("named stats lost the existing unrestored plugin: %v", err)
	}
	if len(named.Msg.Unrestored) != 1 {
		t.Fatal("named stats omitted unrestored reason and claim")
	}
}
