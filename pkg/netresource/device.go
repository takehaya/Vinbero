package netresource

import (
	"fmt"
	"slices"
)

// AddDevice records a runtime-attached device, or updates the mode of a
// recorded one, and persists the state. The attach itself is the caller's.
func (m *ResourceManager) AddDevice(name, mode string) error {
	m.mu.Lock()
	i := slices.IndexFunc(m.state.Devices, func(d ManagedDevice) bool { return d.Name == name })
	if i >= 0 {
		m.state.Devices[i].Mode = mode
	} else {
		m.state.Devices = append(m.state.Devices, ManagedDevice{Name: name, Mode: mode})
	}
	m.mu.Unlock()
	if err := m.persist(); err != nil {
		return fmt.Errorf("persist state after recording device %s: %w", name, err)
	}
	return nil
}

// RemoveDevices drops the named devices from the state and persists it once.
// Names that are not recorded are ignored, and nothing is written when none
// was.
func (m *ResourceManager) RemoveDevices(names ...string) error {
	m.mu.Lock()
	before := len(m.state.Devices)
	m.state.Devices = slices.DeleteFunc(m.state.Devices, func(d ManagedDevice) bool {
		return slices.Contains(names, d.Name)
	})
	changed := len(m.state.Devices) != before
	m.mu.Unlock()
	if !changed {
		return nil
	}
	if err := m.persist(); err != nil {
		return fmt.Errorf("persist state after removing devices %v: %w", names, err)
	}
	return nil
}

// ListDevices returns a copy of the recorded runtime devices.
func (m *ResourceManager) ListDevices() []ManagedDevice {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return slices.Clone(m.state.Devices)
}
