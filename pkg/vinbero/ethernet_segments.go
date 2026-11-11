package vinbero

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"sync"

	"github.com/cilium/ebpf"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/netresource"
	"go.uber.org/zap"
)

// esiMaps is the esi_map surface the segments are written to.
// *bpf.MapOperations satisfies it.
type esiMaps interface {
	CreateEsi(esi [bpf.ESILen]byte, entry *bpf.EsiEntry) error
	DeleteEsi(esi [bpf.ESILen]byte) error
	GetEsi(esi [bpf.ESILen]byte) (*bpf.EsiEntry, error)
	SetEsiDfPe(esi [bpf.ESILen]byte, dfAddr [bpf.IPv6AddrLen]byte) (*bpf.EsiEntry, error)
}

// esStore keeps the segment records. *netresource.ResourceManager satisfies
// it.
type esStore interface {
	EthernetSegments() []netresource.ManagedEthernetSegment
	SaveEthernetSegments([]netresource.ManagedEthernetSegment) error
}

// EthernetSegments keeps the Ethernet Segments made over the API in esi_map
// and in the state file together. Every change of either goes through it and
// runs under its lock: the RPCs and the restore at boot. The BGP DF election
// writes the map's designated forwarder directly and is not recorded.
type EthernetSegments struct {
	mu     sync.Mutex
	maps   esiMaps
	store  esStore // nil: nothing is saved
	logger *zap.Logger
}

// NewEthernetSegments returns the segment book over maps and store. A nil
// store saves nothing.
func NewEthernetSegments(maps esiMaps, store esStore, logger *zap.Logger) *EthernetSegments {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &EthernetSegments{maps: maps, store: store, logger: logger}
}

// segmentRecord is the saved form of the entry esi_map holds for esi.
func segmentRecord(esi [bpf.ESILen]byte, e *bpf.EsiEntry, rd string) netresource.ManagedEthernetSegment {
	var zero [bpf.IPv6AddrLen]byte
	r := netresource.ManagedEthernetSegment{
		ESI:            bpf.FormatESI(esi),
		LocalAttached:  e.IsLocalAttached(),
		RedundancyMode: v1.EsiRedundancyMode(e.RedundancyMode).String(),
		RD:             rd,
	}
	if e.LocalPeSrcAddr != zero {
		r.LocalPeSrcAddr = bpf.FormatIPv6(e.LocalPeSrcAddr)
	}
	if e.DfPeSrcAddr != zero {
		r.DfPeSrcAddr = bpf.FormatIPv6(e.DfPeSrcAddr)
	}
	return r
}

// SegmentEntry is the ESI and the esi_map entry a record restores.
func SegmentEntry(r netresource.ManagedEthernetSegment) ([bpf.ESILen]byte, *bpf.EsiEntry, error) {
	esi, err := bpf.ParseESI(r.ESI)
	if err != nil {
		return esi, nil, err
	}
	if esi == ([bpf.ESILen]byte{}) {
		return esi, nil, errors.New("the all-zero ESI is not an Ethernet Segment")
	}
	mode, ok := v1.EsiRedundancyMode_value[r.RedundancyMode]
	if !ok {
		n, perr := strconv.ParseUint(r.RedundancyMode, 10, 8)
		if perr != nil {
			return esi, nil, fmt.Errorf("redundancy_mode %q is not a redundancy mode", r.RedundancyMode)
		}
		mode = int32(n)
	}
	local, err := bpf.ParseIPv6(r.LocalPeSrcAddr)
	if err != nil {
		return esi, nil, fmt.Errorf("local_pe_src_addr: %w", err)
	}
	df, err := bpf.ParseIPv6(r.DfPeSrcAddr)
	if err != nil {
		return esi, nil, fmt.Errorf("df_pe_src_addr: %w", err)
	}
	return esi, bpf.NewEsiEntry(bpf.EsiConfig{
		LocalAttached:  r.LocalAttached,
		RedundancyMode: uint8(mode),
		LocalPeSrcAddr: local,
		DfPeSrcAddr:    df,
	}), nil
}

func indexOfSegment(recs []netresource.ManagedEthernetSegment, esi [bpf.ESILen]byte) int {
	s := bpf.FormatESI(esi)
	return slices.IndexFunc(recs, func(r netresource.ManagedEthernetSegment) bool { return r.ESI == s })
}

// previous reads the entry esi_map holds for esi, nil when there is none.
func (s *EthernetSegments) previous(esi [bpf.ESILen]byte) (*bpf.EsiEntry, error) {
	prev, err := s.maps.GetEsi(esi)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil, nil
	}
	return prev, err
}

// putBack writes prev back for esi, or removes the entry when there was none,
// after a change that failed with cause.
func (s *EthernetSegments) putBack(esi [bpf.ESILen]byte, prev *bpf.EsiEntry, cause error) error {
	var err error
	if prev != nil {
		err = s.maps.CreateEsi(esi, prev)
	} else if err = s.maps.DeleteEsi(esi); errors.Is(err, ebpf.ErrKeyNotExist) {
		err = nil
	}
	if err != nil {
		return fmt.Errorf("%w; putting the previous Ethernet Segment back failed: %v", cause, err)
	}
	return cause
}

// Create writes the segment (an upsert) and saves it with the RD its RT4 is
// advertised with. When the save fails the map gets the entry it had back,
// so a failed create changes neither the map nor the state file.
func (s *EthernetSegments) Create(esi [bpf.ESILen]byte, entry *bpf.EsiEntry, rd string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, err := s.previous(esi)
	if err != nil {
		return fmt.Errorf("read the Ethernet Segment the create replaces: %w", err)
	}
	if err := s.maps.CreateEsi(esi, entry); err != nil {
		return err
	}
	if s.store == nil {
		return nil
	}
	recs := s.store.EthernetSegments()
	rec := segmentRecord(esi, entry, rd)
	if i := indexOfSegment(recs, esi); i >= 0 {
		recs[i] = rec
	} else {
		recs = append(recs, rec)
	}
	if err := s.store.SaveEthernetSegments(recs); err != nil {
		return s.putBack(esi, prev, fmt.Errorf("the Ethernet Segment is not created: %w", err))
	}
	return nil
}

// Delete removes the segment from the map and the state file and reports
// whether there was one. When the save fails the entry is written back.
func (s *EthernetSegments) Delete(esi [bpf.ESILen]byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, err := s.previous(esi)
	if err != nil {
		return false, fmt.Errorf("read the Ethernet Segment: %w", err)
	}
	var recs []netresource.ManagedEthernetSegment
	i := -1
	if s.store != nil {
		recs = s.store.EthernetSegments()
		i = indexOfSegment(recs, esi)
	}
	if prev == nil && i < 0 {
		return false, nil
	}
	if prev != nil {
		if err := s.maps.DeleteEsi(esi); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, err
		}
	}
	if i < 0 {
		return true, nil
	}
	if err := s.store.SaveEthernetSegments(slices.Delete(recs, i, i+1)); err != nil {
		cause := fmt.Errorf("the Ethernet Segment is not deleted: %w", err)
		if prev == nil {
			return false, cause
		}
		return false, s.putBack(esi, prev, cause)
	}
	return true, nil
}

// SetDF sets the segment's designated forwarder (all-zero clears it) and
// saves it. The map's entry wraps ebpf.ErrKeyNotExist when there is no such
// segment. When the save fails the previous forwarder is written back.
func (s *EthernetSegments) SetDF(esi [bpf.ESILen]byte, df [bpf.IPv6AddrLen]byte) (*bpf.EsiEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, err := s.maps.GetEsi(esi)
	if err != nil {
		return nil, err
	}
	entry, err := s.maps.SetEsiDfPe(esi, df)
	if err != nil {
		return nil, err
	}
	if s.store == nil {
		return entry, nil
	}
	recs := s.store.EthernetSegments()
	i := indexOfSegment(recs, esi)
	if i < 0 {
		return entry, nil
	}
	recs[i].DfPeSrcAddr = ""
	if df != ([bpf.IPv6AddrLen]byte{}) {
		recs[i].DfPeSrcAddr = bpf.FormatIPv6(df)
	}
	if err := s.store.SaveEthernetSegments(recs); err != nil {
		cause := fmt.Errorf("the designated forwarder is not changed: %w", err)
		if _, uerr := s.maps.SetEsiDfPe(esi, prev.DfPeSrcAddr); uerr != nil {
			return nil, fmt.Errorf("%w; putting the previous one back failed: %v", cause, uerr)
		}
		return nil, cause
	}
	return entry, nil
}

// restore writes the saved segments into esi_map at boot, before the L2
// circuits that name them are restored and before the data plane is
// attached, so a circuit's first frame meets its segment's split-horizon
// and DF checks, and the BGP DF election finds the local attachment from the
// first RT4. A segment names no interface and is restored as it was; the
// circuits on it follow their own interfaces (L2Circuits.restore). A record
// that does not decode, two records of one ESI and a map write that fails
// stop the start.
func (s *EthernetSegments) restore() error {
	if s.store == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	recs := s.store.EthernetSegments()
	seen := map[[bpf.ESILen]byte]bool{}
	for i, r := range recs {
		esi, _, err := SegmentEntry(r)
		if err != nil {
			return fmt.Errorf("runtime_ethernet_segments[%d] (%s): %w", i, r.ESI, err)
		}
		if seen[esi] {
			return fmt.Errorf("runtime_ethernet_segments[%d]: a second Ethernet Segment %s", i, r.ESI)
		}
		seen[esi] = true
	}
	for _, r := range recs {
		esi, entry, _ := SegmentEntry(r)
		if err := s.maps.CreateEsi(esi, entry); err != nil {
			return fmt.Errorf("restore the Ethernet Segment %s: %w", r.ESI, err)
		}
	}
	if len(recs) > 0 {
		s.logger.Info("Ethernet Segments restored from the state file", zap.Int("segments", len(recs)))
	}
	return nil
}
