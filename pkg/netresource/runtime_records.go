package netresource

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
)

// ManagedLocator is one SRv6 locator registered over the API, as the
// locator manager holds it (the prefix without host bits).
type ManagedLocator struct {
	Name        string `json:"name"`
	Prefix      string `json:"prefix"`
	BlockLen    uint8  `json:"block_len"`
	NodeLen     uint8  `json:"node_len"`
	FunctionLen uint8  `json:"function_len"`
	ArgumentLen uint8  `json:"argument_len"`
	// Behavior is "classic" or "usid".
	Behavior          string `json:"behavior"`
	FunctionAutoStart uint32 `json:"function_auto_start"`
	FunctionAutoEnd   uint32 `json:"function_auto_end"`
}

// UnmarshalJSON refuses a field this version does not know: a newer version
// may record a property of the locator this one would drop, and the SIDs it
// mints would then differ from the ones the locator was meant to give.
func (l *ManagedLocator) UnmarshalJSON(data []byte) error {
	type plain ManagedLocator
	var p plain
	if err := decodeStrict(data, &p); err != nil {
		return fmt.Errorf("runtime_locators: %w (a newer vinberod may have written it)", err)
	}
	*l = ManagedLocator(p)
	return nil
}

// ManagedEthernetSegment is one Ethernet Segment created over the API, as
// esi_map holds it, with the RD its RT4 is advertised with. DfPeSrcAddr is
// the designated forwarder the operator set (EsCreate, EsSetDf, EsClearDf);
// one the BGP election chose is not recorded.
type ManagedEthernetSegment struct {
	ESI           string `json:"esi"`
	LocalAttached bool   `json:"local_attached,omitempty"`
	// RedundancyMode is the EsiRedundancyMode enum name, or the number for a
	// value the enum does not name.
	RedundancyMode string `json:"redundancy_mode"`
	LocalPeSrcAddr string `json:"local_pe_src_addr,omitempty"`
	DfPeSrcAddr    string `json:"df_pe_src_addr,omitempty"`
	RD             string `json:"rd,omitempty"`
}

// UnmarshalJSON refuses a field this version does not know, like the other
// runtime records.
func (e *ManagedEthernetSegment) UnmarshalJSON(data []byte) error {
	type plain ManagedEthernetSegment
	var p plain
	if err := decodeStrict(data, &p); err != nil {
		return fmt.Errorf("runtime_ethernet_segments: %w (a newer vinberod may have written it)", err)
	}
	*e = ManagedEthernetSegment(p)
	return nil
}

// ManagedVrfPolicy is the global VRF ingress policy set over the API
// (VrfSetPolicy). DenyAction is "drop" or "pass".
type ManagedVrfPolicy struct {
	DefaultDeny bool   `json:"default_deny"`
	DenyAction  string `json:"deny_action"`
}

// UnmarshalJSON refuses a field this version does not know: a newer version
// may record a policy this one would not enforce.
func (p *ManagedVrfPolicy) UnmarshalJSON(data []byte) error {
	type plain ManagedVrfPolicy
	var v plain
	if err := decodeStrict(data, &v); err != nil {
		return fmt.Errorf("runtime_vrf_policy: %w (a newer vinberod may have written it)", err)
	}
	*p = ManagedVrfPolicy(v)
	return nil
}

func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// RuntimeLocators returns a copy of the saved locators, in the order they
// were registered.
func (m *ResourceManager) RuntimeLocators() []ManagedLocator {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return slices.Clone(m.state.RuntimeLocators)
}

// SaveRuntimeLocators records the locators made over the API and writes the
// state file. Like SaveRuntimeVrfBindings, a failed write puts the previous
// record back, and an equal record is written only after a failed write.
func (m *ResourceManager) SaveRuntimeLocators(locs []ManagedLocator) error {
	c := slices.Clone(locs)
	if len(c) == 0 {
		c = nil
	}
	return saveReverting(m, func(s *ManagedState) *[]ManagedLocator { return &s.RuntimeLocators }, c, "locators")
}

// DropRuntimeLocators records the locators with some the boot dropped, and
// keeps that record when the write fails (see DropRuntimeVrfBindings).
func (m *ResourceManager) DropRuntimeLocators(locs []ManagedLocator) error {
	c := slices.Clone(locs)
	if len(c) == 0 {
		c = nil
	}
	return saveKeeping(m, func(s *ManagedState) *[]ManagedLocator { return &s.RuntimeLocators }, c, "locators")
}

// EthernetSegments returns a copy of the saved Ethernet Segments.
func (m *ResourceManager) EthernetSegments() []ManagedEthernetSegment {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return slices.Clone(m.state.RuntimeEthernetSegments)
}

// SaveEthernetSegments records the Ethernet Segments made over the API, in
// ESI order, and writes the state file. A failed write puts the previous
// record back.
func (m *ResourceManager) SaveEthernetSegments(segs []ManagedEthernetSegment) error {
	c := slices.Clone(segs)
	slices.SortFunc(c, func(a, b ManagedEthernetSegment) int { return cmp.Compare(a.ESI, b.ESI) })
	if len(c) == 0 {
		c = nil
	}
	return saveReverting(m, func(s *ManagedState) *[]ManagedEthernetSegment { return &s.RuntimeEthernetSegments }, c, "Ethernet Segments")
}

// RuntimeVrfPolicy returns the saved VRF policy, nil when none is saved.
func (m *ResourceManager) RuntimeVrfPolicy() *ManagedVrfPolicy {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.state.RuntimeVrfPolicy == nil {
		return nil
	}
	p := *m.state.RuntimeVrfPolicy
	return &p
}

// SaveRuntimeVrfPolicy records the VRF policy set over the API and writes the
// state file. A failed write puts the previous record back.
func (m *ResourceManager) SaveRuntimeVrfPolicy(p ManagedVrfPolicy) error {
	return saveReverting(m, func(s *ManagedState) **ManagedVrfPolicy { return &s.RuntimeVrfPolicy }, &p, "the VRF policy")
}

// DropRuntimeVrfPolicy removes the saved VRF policy, for the boot when the
// config owns the policy, and keeps it removed when the write fails.
func (m *ResourceManager) DropRuntimeVrfPolicy() error {
	return saveKeeping(m, func(s *ManagedState) **ManagedVrfPolicy { return &s.RuntimeVrfPolicy }, nil, "the VRF policy")
}

// saveReverting sets the record field selects to v and writes the state file.
// A failed write puts the previous record back, so the caller can undo its
// change and memory and file stay the same; writeMu is held from the swap to
// the revert, so no other write puts the refused record on disk. A record
// equal to the one in memory is not written again, unless an earlier write
// failed.
func saveReverting[T any](m *ResourceManager, field func(*ManagedState) *T, v T, what string) error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	m.mu.Lock()
	p := field(m.state)
	prev := *p
	if reflect.DeepEqual(prev, v) && !m.fileBehind.Load() {
		m.mu.Unlock()
		return nil
	}
	*p = v
	data, err := json.MarshalIndent(m.state, "", "  ")
	m.mu.Unlock()
	if err == nil {
		err = writeFileAtomic(m.statePath, data)
	}
	if err != nil {
		m.fileBehind.Store(true)
		m.mu.Lock()
		*field(m.state) = prev
		m.mu.Unlock()
		return fmt.Errorf("persist state after updating %s: %w", what, err)
	}
	m.fileBehind.Store(false)
	return nil
}

// saveKeeping sets the record field selects to v and writes the state file,
// keeping v when the write fails: the next successful write of any record
// carries it.
func saveKeeping[T any](m *ResourceManager, field func(*ManagedState) *T, v T, what string) error {
	m.mu.Lock()
	p := field(m.state)
	same := reflect.DeepEqual(*p, v)
	*p = v
	m.mu.Unlock()
	if same {
		return nil
	}
	if err := m.persist(); err != nil {
		return fmt.Errorf("persist state after updating %s: %w", what, err)
	}
	return nil
}
