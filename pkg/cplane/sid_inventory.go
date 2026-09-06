package cplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"

	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/locator"
)

const sidInventoryVersion = 1

type sidRecord struct {
	Owner    bpf.OwnerTag    `json:"-"`
	Plugin   string          `json:"plugin"`
	Name     string          `json:"name"`
	SID      netip.Addr      `json:"sid"`
	Locator  locator.Locator `json:"locator"`
	Function uint32          `json:"function"`
	Slot     uint32          `json:"slot"`
	AuxRaw   []byte          `json:"aux_raw,omitempty"`
	DecapVRF string          `json:"decap_vrf,omitempty"`
}

type sidInventory struct {
	Version int         `json:"version"`
	Records []sidRecord `json:"records"`
}

// A separate directory keeps allocation cleanup independent of registration
// replacement and of Store.Remove. An empty inventory is retained as well.
type sidInventoryStore struct {
	path  string
	write func(string, []byte) error
}

func openSIDInventory(dir string) (*sidInventoryStore, error) {
	invDir := filepath.Join(dir, "local-sids")
	s := &sidInventoryStore{path: filepath.Join(invDir, "state.json"), write: writeFileAtomic}
	marker := filepath.Join(dir, "local-sids.version")
	version, markerErr := os.ReadFile(marker)
	if markerErr != nil && !errors.Is(markerErr, os.ErrNotExist) {
		return nil, markerErr
	}
	if markerErr == nil && string(version) != "1\n" {
		return nil, fmt.Errorf("unsupported local SID inventory marker")
	}
	_, err := os.Stat(invDir)
	if errors.Is(err, os.ErrNotExist) {
		if markerErr == nil {
			return nil, fmt.Errorf("local SID inventory directory is missing")
		}
		if err := os.Mkdir(invDir, 0o700); err != nil {
			return nil, err
		}
		if err := syncDir(dir); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if _, err := s.load(); err != nil {
		// Before the enrollment marker is durable, no successful store
		// open can have installed a SID. Resume an interrupted first open
		// only when its snapshot is absent; never overwrite existing data.
		if !errors.Is(markerErr, os.ErrNotExist) || !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err := s.save(nil); err != nil {
			return nil, err
		}
	}
	if errors.Is(markerErr, os.ErrNotExist) {
		if err := writeFileAtomic(marker, []byte("1\n")); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *sidInventoryStore) load() ([]sidRecord, error) {
	body, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("read local SID inventory: %w", err)
	}
	var inv sidInventory
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&inv); err != nil {
		return nil, fmt.Errorf("decode local SID inventory: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("local SID inventory has trailing data")
	}
	if inv.Version != sidInventoryVersion {
		return nil, fmt.Errorf("local SID inventory version %d is unsupported", inv.Version)
	}
	if inv.Records == nil {
		return nil, fmt.Errorf("local SID inventory is missing its records array")
	}
	names := make(map[string]bool)
	addresses := make(map[netip.Addr]bool)
	reservations := make([]locator.SIDReservation, 0, len(inv.Records))
	for i := range inv.Records {
		r := &inv.Records[i]
		if err := bpf.ValidatePluginBundleName(r.Plugin); err != nil {
			return nil, err
		}
		r.Owner = bpf.OwnerPluginBundle(r.Plugin)
		if err := validateLocalSID(r.desired()); err != nil {
			return nil, err
		}
		if err := r.Locator.Validate(); err != nil {
			return nil, err
		}
		sid, err := r.Locator.BuildSID(r.Function)
		if err != nil || sid != r.SID || r.SID.Zone() != "" {
			return nil, fmt.Errorf("local SID inventory %q/%q has inconsistent address", r.Owner, r.Name)
		}
		key := sidReservationKey(r.Owner, r.Name)
		if names[key] || addresses[r.SID] {
			return nil, fmt.Errorf("local SID inventory duplicates %q/%q or address %s", r.Owner, r.Name, r.SID)
		}
		names[key], addresses[r.SID] = true, true
		reservations = append(reservations, r.reservation())
	}
	if err := locator.NewManager().RestoreSIDReservations(reservations); err != nil {
		return nil, err
	}
	return inv.Records, nil
}

func (s *sidInventoryStore) save(records []sidRecord) error {
	if records == nil {
		records = []sidRecord{}
	}
	for i := range records {
		owner, ok, err := bpf.ParsePluginOwnerTag(string(records[i].Owner))
		if err != nil || !ok || !owner.IsBundle() {
			return fmt.Errorf("local SID inventory has invalid owner %q", records[i].Owner)
		}
		records[i].Plugin = owner.Bundle
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Owner != records[j].Owner {
			return records[i].Owner < records[j].Owner
		}
		return records[i].Name < records[j].Name
	})
	body, err := json.MarshalIndent(sidInventory{Version: sidInventoryVersion, Records: records}, "", "  ")
	if err != nil {
		return err
	}
	if err := s.write(s.path, body); err != nil {
		return fmt.Errorf("save local SID inventory: %w", err)
	}
	return nil
}

func (r sidRecord) desired() LocalSID {
	return LocalSID{Name: r.Name, Locator: r.Locator.Name, Slot: r.Slot, AuxRaw: r.AuxRaw, DecapVRF: r.DecapVRF}
}

func sidReservationKey(owner bpf.OwnerTag, name string) string {
	// Length framing is unambiguous even if a guest name contains separators.
	return fmt.Sprintf("cplane/%d:%s%s", len(owner), owner, name)
}

func (r sidRecord) reservation() locator.SIDReservation {
	return locator.SIDReservation{Key: sidReservationKey(r.Owner, r.Name), Locator: r.Locator, Function: r.Function}
}

// PersistentSIDAllocator protects caller-keyed allocations even before locators
// are registered. The daemon's locator.Manager implements this interface.
type PersistentSIDAllocator interface {
	SIDAllocator
	RestoreSIDReservations([]locator.SIDReservation) error
	AllocateReservedSID(key, locatorName string) (netip.Addr, locator.SIDReservation, error)
	ReleaseReservedSID(key string)
}

// ReserveStoredLocalSIDs must run before config locators, exporters or RPC can
// allocate. It restores reservations without requiring a guest or a live locator.
func ReserveStoredLocalSIDs(store *Store, alloc PersistentSIDAllocator) error {
	if store == nil {
		return nil
	}
	records, err := store.sids.load()
	if err != nil {
		return err
	}
	if len(records) == 0 {
		return nil
	}
	if alloc == nil {
		return fmt.Errorf("local SID inventory requires a persistent allocator")
	}
	reservations := make([]locator.SIDReservation, 0, len(records))
	for _, r := range records {
		reservations = append(reservations, r.reservation())
	}
	return alloc.RestoreSIDReservations(reservations)
}
