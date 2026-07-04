package netresource

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type ManagedState struct {
	VRFs    []ManagedVrf    `json:"vrfs"`
	Bridges []ManagedBridge `json:"bridges"`
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
func (m *ResourceManager) persist() error {
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
