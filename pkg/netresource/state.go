package netresource

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

type ManagedState struct {
	VRFs    []ManagedVrf    `json:"vrfs"`
	Bridges []ManagedBridge `json:"bridges"`
	// Devices are the interfaces attached to the data plane at runtime
	// (DeviceAttach). internal.devices entries are not recorded here.
	Devices []ManagedDevice `json:"devices,omitempty"`
	// VrfObjects are the VRF objects' identities and runtime facets. Nil on
	// a file written before they were recorded.
	VrfObjects *ManagedVrfObjects `json:"vrf_objects,omitempty"`
}

// ManagedVrfObjects is the vrf_id allocator and one record per VRF object.
// Both fields are required: without the watermark the ids of deleted VRFs
// could be handed out again, and without the entries every saved id and AC
// would be lost, so a record missing either is refused like a file that does
// not parse.
type ManagedVrfObjects struct {
	NextVrfID uint32             `json:"next_vrf_id"`
	Entries   []ManagedVrfObject `json:"entries"`
}

func (o *ManagedVrfObjects) UnmarshalJSON(data []byte) error {
	var raw struct {
		NextVrfID *uint32             `json:"next_vrf_id"`
		Entries   *[]ManagedVrfObject `json:"entries"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.NextVrfID == nil || *raw.NextVrfID == 0 {
		return errors.New("vrf_objects: next_vrf_id is missing or 0")
	}
	if raw.Entries == nil {
		return errors.New("vrf_objects: entries is missing")
	}
	o.NextVrfID, o.Entries = *raw.NextVrfID, *raw.Entries
	return nil
}

// clone copies o, with an empty rather than nil Entries so it encodes as [].
func (o *ManagedVrfObjects) clone() *ManagedVrfObjects {
	c := &ManagedVrfObjects{NextVrfID: o.NextVrfID, Entries: make([]ManagedVrfObject, 0, len(o.Entries))}
	for _, e := range o.Entries {
		e.RuntimeACs = slices.Clone(e.RuntimeACs)
		c.Entries = append(c.Entries, e)
	}
	return c
}

// ManagedVrfObject is what a VRF object keeps across a restart, by name. A
// VRF without a kernel device has a record here and none in ManagedState.VRFs.
// State declared at runtime for one VRF belongs in this record, a field per
// facet.
type ManagedVrfObject struct {
	Name  string `json:"name"`
	VrfID uint32 `json:"vrf_id"`
	// RuntimeACs are the ACs added over the API. Unlike the ACs of the
	// config, one whose interface is gone is skipped with a warning.
	RuntimeACs []ManagedAC `json:"runtime_acs,omitempty"`
	// Config is set when the VRF came from the boot-time load (the config
	// file, or a device or bridge record) rather than from the API. Such a
	// VRF is not restored once the config no longer declares it and it holds
	// no AC, device or bridge; its id stays retired.
	Config bool `json:"config,omitempty"`
}

// ManagedAC is one ingress access circuit.
type ManagedAC struct {
	Interface string `json:"interface"`
	VLAN      uint16 `json:"vlan"`
}

// ManagedDevice is a runtime-attached device: the interface name and the
// XDP mode it was attached in (config spelling, never empty).
type ManagedDevice struct {
	Name string `json:"name"`
	Mode string `json:"mode"`
}

type ManagedVrf struct {
	Name             string   `json:"name"`
	TableID          uint32   `json:"table_id"`
	Members          []string `json:"members"`
	EnableL3mdevRule bool     `json:"enable_l3mdev_rule"`
	Ifindex          uint32   `json:"ifindex"`
}

type ManagedBridge struct {
	Name    string   `json:"name"`
	BdID    uint16   `json:"bd_id"`
	Members []string `json:"members"`
	Ifindex uint32   `json:"ifindex"`
	// VRF is the name of the VRF object this bridge is attached to as its L2
	// facet. Empty on records written before the facet existed; boot seeding
	// then falls back to the bridge's own name as a synthetic VRF. To move
	// such a bridge under its real VRF, stop the daemon, set this field in
	// the state file, and restart (detaching instead would delete the kernel
	// bridge and disrupt traffic).
	VRF string `json:"vrf,omitempty"`
	// RuntimeMembers are ports added one at a time (VrfBridgeMemberAdd),
	// typically veths that come and go with their workload. Unlike Members,
	// a runtime member that is gone at boot is dropped instead of failing
	// the reconcile.
	RuntimeMembers []string `json:"runtime_members,omitempty"`
}

func loadState(path string) (*ManagedState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &ManagedState{VRFs: []ManagedVrf{}, Bridges: []ManagedBridge{}}, nil
		}
		return nil, err
	}
	var state ManagedState
	if err := json.Unmarshal(data, &state); err != nil {
		// Refuse to guess which kernel devices the daemon owns: starting with
		// an empty state would silently abandon every managed VRF / bridge.
		return nil, fmt.Errorf("parse state: %w (repair the file or move it aside and restart)", err)
	}
	return &state, nil
}

// persist snapshots the state under the read lock and writes it to the state
// file atomically. Callers must NOT hold m.mu (RWMutex is not reentrant); the
// file I/O happens outside the lock so a slow disk does not stall readers.
// writeMu spans the snapshot and the rename: the VRF service and the device
// service persist independently, and an older snapshot must not be renamed
// in after a newer one.
func (m *ResourceManager) persist() error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	m.mu.RLock()
	data, err := json.MarshalIndent(m.state, "", "  ")
	m.mu.RUnlock()
	if err != nil {
		return err
	}
	return writeFileAtomic(m.statePath, data)
}

// writeFileAtomic writes data to path through a same-directory temp file and
// a rename, fsyncing both the file and the directory. A crash or an ENOSPC
// mid-write leaves the previous file intact instead of a truncated one --
// the old os.WriteFile (O_TRUNC in place) turned exactly that crash window
// into a state file the next boot refuses to parse.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Best-effort cleanup on every early return; a no-op once the rename won.
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// CreateTemp uses 0600; the state file is device names / table IDs, kept
	// world-readable like the old direct write.
	if err := os.Chmod(tmpName, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	// fsync the directory so the rename itself survives a crash.
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
