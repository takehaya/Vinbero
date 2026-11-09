package bpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf/ringbuf"
)

// FDB event kinds, matching FDB_EVENT_* in src/l2vpn/bum_xdp.h.
const (
	FdbEventAdd  uint8 = 1
	FdbEventMove uint8 = 2
)

const fdbEventSize = 16

// FdbEvent is a local MAC the XDP learner installed or moved in an
// xdp-mode bridge domain (struct fdb_event).
type FdbEvent struct {
	BdID uint16
	MAC  net.HardwareAddr
	Oif  uint32
	Kind uint8
}

// ParseFdbEvent decodes one fdb_event_rb record (host byte order, which is
// little endian on every architecture bpf2go builds this package for here).
func ParseFdbEvent(raw []byte) (FdbEvent, error) {
	if len(raw) < fdbEventSize {
		return FdbEvent{}, fmt.Errorf("fdb event: short record (%d bytes)", len(raw))
	}
	return FdbEvent{
		BdID: binary.NativeEndian.Uint16(raw[0:2]),
		MAC:  net.HardwareAddr(append([]byte(nil), raw[2:8]...)),
		Oif:  binary.NativeEndian.Uint32(raw[8:12]),
		Kind: raw[12],
	}, nil
}

// FdbEventReader reads XDP learning events from fdb_event_rb.
type FdbEventReader struct {
	rd *ringbuf.Reader
}

// NewFdbEventReader opens a reader on the collection's learning ring buffer.
func (m *MapOperations) NewFdbEventReader() (*FdbEventReader, error) {
	rd, err := ringbuf.NewReader(m.objs.FdbEventRb)
	if err != nil {
		return nil, fmt.Errorf("open fdb event ring buffer: %w", err)
	}
	return &FdbEventReader{rd: rd}, nil
}

// ErrFdbEventsClosed is returned by Read after Close.
var ErrFdbEventsClosed = errors.New("fdb event reader closed")

// Read blocks for the next event.
func (r *FdbEventReader) Read() (FdbEvent, error) {
	rec, err := r.rd.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return FdbEvent{}, ErrFdbEventsClosed
		}
		return FdbEvent{}, err
	}
	return ParseFdbEvent(rec.RawSample)
}

// Close unblocks a pending Read.
func (r *FdbEventReader) Close() error { return r.rd.Close() }

// ListLocalDynamicFdb returns the MACs the data plane learned on local ports
// of bdID (bdID 0: every BD): dynamic, not remote, and not owned by a
// control-plane writer. The xdp-mode replay and reconciliation read these
// instead of the kernel bridge FDB, which never sees those frames.
func (m *MapOperations) ListLocalDynamicFdb(bdID uint16) (map[uint16][]net.HardwareAddr, error) {
	out := map[uint16][]net.HardwareAddr{}
	var (
		key   FdbKey
		entry FdbEntry
	)
	iter := m.objs.FdbMap.Iterate()
	for iter.Next(&key, &entry) {
		if (bdID != 0 && key.BdId != bdID) || entry.IsRemote != 0 || entry.IsStatic != 0 || entry.Oif == 0 {
			continue
		}
		k := key
		if _, owned, err := m.fdbOwners.Lookup(&k); err != nil {
			return nil, err
		} else if owned {
			continue
		}
		out[key.BdId] = append(out[key.BdId], net.HardwareAddr(append([]byte(nil), key.Mac[:]...)))
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("scan fdb map: %w", err)
	}
	return out, nil
}
