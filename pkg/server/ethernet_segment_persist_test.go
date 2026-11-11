package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"
	"github.com/cilium/ebpf"
	"go.uber.org/zap"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/netresource"
	"github.com/takehaya/vinbero/pkg/vinbero"
)

type memEsiMap map[[bpf.ESILen]byte]bpf.EsiEntry

func (f memEsiMap) CreateEsi(esi [bpf.ESILen]byte, e *bpf.EsiEntry) error { f[esi] = *e; return nil }
func (f memEsiMap) DeleteEsi(esi [bpf.ESILen]byte) error {
	if _, ok := f[esi]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(f, esi)
	return nil
}
func (f memEsiMap) GetEsi(esi [bpf.ESILen]byte) (*bpf.EsiEntry, error) {
	e, ok := f[esi]
	if !ok {
		return nil, fmt.Errorf("lookup: %w", ebpf.ErrKeyNotExist)
	}
	return &e, nil
}
func (f memEsiMap) SetEsiDfPe(esi [bpf.ESILen]byte, df [bpf.IPv6AddrLen]byte) (*bpf.EsiEntry, error) {
	e, ok := f[esi]
	if !ok {
		return nil, fmt.Errorf("lookup: %w", ebpf.ErrKeyNotExist)
	}
	e.DfPeSrcAddr = df
	f[esi] = e
	return &e, nil
}

type recordingES struct{ enabled, disabled int }

func (r *recordingES) EnableES([bpf.ESILen]byte, string) error { r.enabled++; return nil }
func (r *recordingES) DisableES([bpf.ESILen]byte)              { r.disabled++ }
func (r *recordingES) RDForESI([bpf.ESILen]byte) (string, bool) {
	return "", false
}

// A create or delete whose save fails reports the error for its ESI and does
// not advertise, withdraw or elect anything; a DF change reports internal.
func TestEthernetSegmentServer_SaveFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	res, err := netresource.NewResourceManager(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	m := memEsiMap{}
	hook := &recordingES{}
	elected := 0
	s := NewEthernetSegmentServer(nil, func([bpf.ESILen]byte) { elected++ }, hook, zap.NewNop())
	s.SetSegments(vinbero.NewEthernetSegments(m, res, zap.NewNop()))
	es := &v1.EthernetSegment{Esi: "01:00:00:00:00:00:00:00:01:00", LocalAttached: true, LocalPeSrcAddr: "fc00:1::1",
		RedundancyMode: v1.EsiRedundancyMode_ESI_REDUNDANCY_MODE_ALL_ACTIVE, Rd: "65000:1"}
	create := func() *v1.EsCreateResponse {
		resp, err := s.EsCreate(context.Background(), connect.NewRequest(&v1.EsCreateRequest{Entries: []*v1.EthernetSegment{es}}))
		if err != nil {
			t.Fatal(err)
		}
		return resp.Msg
	}
	if r := create(); len(r.Errors) != 0 || hook.enabled != 1 || elected != 1 {
		t.Fatalf("create: %+v enabled=%d elected=%d", r.Errors, hook.enabled, elected)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0755); err != nil {
		t.Fatal(err)
	}
	es.Rd = "65000:2"
	if r := create(); len(r.Errors) != 1 || len(r.Created) != 0 || hook.enabled != 1 || elected != 1 {
		t.Errorf("create with a failed save: %+v enabled=%d elected=%d", r, hook.enabled, elected)
	}
	resp, err := s.EsDelete(context.Background(), connect.NewRequest(&v1.EsDeleteRequest{Esis: []string{es.Esi}}))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Msg.Errors) != 1 || len(resp.Msg.Deleted) != 0 || hook.disabled != 0 || len(m) != 1 {
		t.Errorf("delete with a failed save: %+v disabled=%d map=%v", resp.Msg, hook.disabled, m)
	}
	_, err = s.EsSetDf(context.Background(), connect.NewRequest(&v1.EsSetDfRequest{Esi: es.Esi, DfPeSrcAddr: "fc00:2::2"}))
	if connect.CodeOf(err) != connect.CodeInternal {
		t.Errorf("set-df with a failed save: %v", err)
	}
	if recs := res.EthernetSegments(); len(recs) != 1 || recs[0].RD != "65000:1" || recs[0].DfPeSrcAddr != "" {
		t.Errorf("record after failed calls = %+v", recs)
	}
	_, err = s.EsSetDf(context.Background(), connect.NewRequest(&v1.EsSetDfRequest{Esi: "01:00:00:00:00:00:00:00:00:09", DfPeSrcAddr: "fc00:2::2"}))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("set-df of an unknown ESI: %v", err)
	}
}
