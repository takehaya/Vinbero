package netresource

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
)

// ManagedL2Circuit is one L2 headend circuit as the API created it. It is
// keyed by the interface's ifindex and the VLAN, like the headend_l2 entry;
// the name and the hardware address are the ones the interface had then, or
// after a rename the daemon saw. A restart restores the circuit only on an
// interface that still has that ifindex, name and address.
type ManagedL2Circuit struct {
	Interface string `json:"interface"`
	Ifindex   uint32 `json:"ifindex"`
	MAC       string `json:"mac,omitempty"`
	VLAN      uint16 `json:"vlan"`
	// Mode is the headend behavior's enum name.
	Mode     string   `json:"mode"`
	SrcAddr  string   `json:"src_addr,omitempty"`
	Segments []string `json:"segments,omitempty"`
	BdID     uint16   `json:"bd_id,omitempty"`
	// ESI is empty for a single-homed circuit.
	ESI string `json:"esi,omitempty"`
	// Deleting marks a circuit a delete has started on: the next start
	// removes its entry instead of restoring it.
	Deleting bool `json:"deleting,omitempty"`
}

// UnmarshalJSON refuses a field this version does not know, like a binding
// record: a newer version may record a property of the circuit this one
// would drop when it restores it.
func (c *ManagedL2Circuit) UnmarshalJSON(data []byte) error {
	type plain ManagedL2Circuit
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p plain
	if err := dec.Decode(&p); err != nil {
		return fmt.Errorf("runtime_l2_circuits: %w (a newer vinberod may have written it)", err)
	}
	*c = ManagedL2Circuit(p)
	return nil
}

// cloneL2Circuits copies circuits in key order; none is nil, so an empty
// record is not written.
func cloneL2Circuits(in []ManagedL2Circuit) []ManagedL2Circuit {
	if len(in) == 0 {
		return nil
	}
	out := make([]ManagedL2Circuit, len(in))
	for i, c := range in {
		c.Segments = slices.Clone(c.Segments)
		out[i] = c
	}
	slices.SortFunc(out, func(a, b ManagedL2Circuit) int {
		return cmp.Or(cmp.Compare(a.Ifindex, b.Ifindex), cmp.Compare(a.VLAN, b.VLAN))
	})
	return out
}

// L2Circuits returns a copy of the saved L2 headend circuits.
func (m *ResourceManager) L2Circuits() []ManagedL2Circuit {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cloneL2Circuits(m.state.RuntimeL2Circuits)
}

// SaveL2Circuits records the L2 headend circuits and writes the state file.
// Like SaveRuntimeVrfBindings, a failed write puts the previous record back,
// so the caller can undo its change and memory and file stay the same. A
// record equal to the one in memory is not written again, unless an earlier
// write failed.
func (m *ResourceManager) SaveL2Circuits(circuits []ManagedL2Circuit) error {
	c := cloneL2Circuits(circuits)
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	m.mu.Lock()
	prev := m.state.RuntimeL2Circuits
	if reflect.DeepEqual(prev, c) && !m.fileBehind.Load() {
		m.mu.Unlock()
		return nil
	}
	m.state.RuntimeL2Circuits = c
	data, err := json.MarshalIndent(m.state, "", "  ")
	m.mu.Unlock()
	if err == nil {
		err = writeFileAtomic(m.statePath, data)
	}
	if err != nil {
		m.fileBehind.Store(true)
		m.mu.Lock()
		m.state.RuntimeL2Circuits = prev
		m.mu.Unlock()
		return fmt.Errorf("persist state after updating L2 circuits: %w", err)
	}
	m.fileBehind.Store(false)
	return nil
}

// DropL2Circuits records the L2 headend circuits and writes the state file,
// keeping the new record when the write fails. It forgets circuits whose
// interface is gone or whose delete finished at boot; the next successful
// write of any record carries it.
func (m *ResourceManager) DropL2Circuits(circuits []ManagedL2Circuit) error {
	c := cloneL2Circuits(circuits)
	m.mu.Lock()
	same := reflect.DeepEqual(m.state.RuntimeL2Circuits, c)
	m.state.RuntimeL2Circuits = c
	m.mu.Unlock()
	if same {
		return nil
	}
	if err := m.persist(); err != nil {
		return fmt.Errorf("persist state after updating L2 circuits: %w", err)
	}
	return nil
}
