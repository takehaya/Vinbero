package netresource

import (
	"encoding/json"
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
		return nil, err
	}
	return &state, nil
}

func saveState(path string, state *ManagedState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
