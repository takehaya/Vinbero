package cni

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Attachment records what ADD set up for one {container, interface}, so DEL
// can undo it after the pod's network namespace or the network
// configuration it was created with is gone.
type Attachment struct {
	ContainerID string `json:"containerId"`
	IfName      string `json:"ifName"`
	Network     string `json:"network"`
	// Mode is the attachment mode ("l2"; empty means the default "l3").
	// A record an older plugin wrote has no mode field, so it reads as L3
	// and DEL/CHECK keep working.
	Mode    string `json:"mode,omitempty"`
	VRF     string `json:"vrf"`
	TableID uint32 `json:"tableId"`
	// Bridge and BdID are the bridge domain in L2 mode.
	Bridge   string `json:"bridge,omitempty"`
	BdID     uint32 `json:"bdId,omitempty"`
	HostVeth string `json:"hostVeth"`
	// Address is the pod address with the prefix length IPAM handed out. In
	// L3 mode the pod interface carries it as a /32; in L2 mode it carries
	// the whole prefix on-link.
	Address netip.Prefix `json:"address,omitzero"`
	PodMAC  string       `json:"podMac,omitempty"`
	HostMAC string       `json:"hostMac,omitempty"`
}

// isL2 reports whether the record is an L2 attachment.
func (a Attachment) isL2() bool { return a.Mode == ModeL2 }

// Store keeps one JSON file per attachment under a directory.
type Store struct {
	Dir string
}

func (s *Store) path(containerID, ifName string) string {
	return filepath.Join(s.Dir, containerID+"_"+ifName+".json")
}

func checkKey(containerID, ifName string) error {
	for _, v := range []string{containerID, ifName} {
		if v == "" || strings.ContainsAny(v, "/\x00") || v == "." || v == ".." {
			return fmt.Errorf("invalid attachment key %q", v)
		}
	}
	return nil
}

// Lock takes an exclusive lock on the directory for one ADD, DEL or CHECK,
// so two commands for the same attachment never interleave their steps.
func (s *Store) Lock() (unlock func(), err error) {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", s.Dir, err)
	}
	f, err := os.OpenFile(filepath.Join(s.Dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock %s: %w", s.Dir, err)
	}
	return func() { _ = f.Close() }, nil
}

// Get returns the record, or ok=false when there is none.
func (s *Store) Get(containerID, ifName string) (Attachment, bool, error) {
	if err := checkKey(containerID, ifName); err != nil {
		return Attachment{}, false, err
	}
	data, err := os.ReadFile(s.path(containerID, ifName))
	if errors.Is(err, os.ErrNotExist) {
		return Attachment{}, false, nil
	}
	if err != nil {
		return Attachment{}, false, err
	}
	var a Attachment
	if err := json.Unmarshal(data, &a); err != nil {
		return Attachment{}, false, fmt.Errorf("decode %s: %w", s.path(containerID, ifName), err)
	}
	return a, true, nil
}

// Put writes the record atomically.
func (s *Store) Put(a Attachment) error {
	if err := checkKey(a.ContainerID, a.IfName); err != nil {
		return err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(a)
	if err != nil {
		return err
	}
	p := s.path(a.ContainerID, a.IfName)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Delete removes the record; a missing one succeeds.
func (s *Store) Delete(containerID, ifName string) error {
	if err := checkKey(containerID, ifName); err != nil {
		return err
	}
	err := os.Remove(s.path(containerID, ifName))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
