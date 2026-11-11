package main

import (
	"testing"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/netresource"
)

// After the session starts, a restored segment gets what EsCreate gives it:
// a locally attached one its DF election, one with an RD its RT4 too.
func TestResumeSegments(t *testing.T) {
	recs := []netresource.ManagedEthernetSegment{
		{ESI: "01:00:00:00:00:00:00:00:00:01", LocalAttached: true, RedundancyMode: "ESI_REDUNDANCY_MODE_ALL_ACTIVE", LocalPeSrcAddr: "fc00:1::1", RD: "65000:1"},
		{ESI: "01:00:00:00:00:00:00:00:00:02", LocalAttached: true, RedundancyMode: "ESI_REDUNDANCY_MODE_ALL_ACTIVE", LocalPeSrcAddr: "fc00:1::1"},
		{ESI: "01:00:00:00:00:00:00:00:00:03", RedundancyMode: "ESI_REDUNDANCY_MODE_ALL_ACTIVE", RD: "65000:3"},
	}
	var elected []string
	enabled := map[string]string{}
	resumeSegments(recs,
		func(esi [bpf.ESILen]byte) { elected = append(elected, bpf.FormatESI(esi)) },
		func(esi [bpf.ESILen]byte, rd string) error { enabled[bpf.FormatESI(esi)] = rd; return nil },
		zap.NewNop())
	if len(elected) != 2 || elected[0] != recs[0].ESI || elected[1] != recs[1].ESI {
		t.Errorf("elected %v", elected)
	}
	if len(enabled) != 1 || enabled[recs[0].ESI] != "65000:1" {
		t.Errorf("enabled %v", enabled)
	}
	// Without BGP hooks nothing is called.
	resumeSegments(recs, nil, nil, zap.NewNop())
}
