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
	Netns       string `json:"netns,omitempty"`
	Network     string `json:"network"`
	VRF         string `json:"vrf"`
	TableID     uint32 `json:"tableId"`
	HostVeth    string `json:"hostVeth"`
	// Address is the pod address with the prefix length IPAM handed out;
	// the pod interface carries it as a /32.
	Address netip.Prefix `json:"address,omitzero"`
	PodMAC  string       `json:"podMac,omitempty"`
	HostMAC string       `json:"hostMac,omitempty"`
}

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
// so the overlap check and the records see a consistent view.
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

// List returns every record in the directory.
func (s *Store) List() ([]Attachment, error) {
	paths, err := filepath.Glob(filepath.Join(s.Dir, "*.json"))
	if err != nil {
		return nil, err
	}
	out := make([]Attachment, 0, len(paths))
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var a Attachment
		if err := json.Unmarshal(data, &a); err != nil {
			return nil, fmt.Errorf("decode %s: %w", p, err)
		}
		out = append(out, a)
	}
	return out, nil
}
