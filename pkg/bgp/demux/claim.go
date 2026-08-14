package demux

import (
	"fmt"
	"sync"
)

// ClaimRegistry records which SRv6 endpoint behavior codepoints belong to a
// plugin rather than to the built-in appliers.
//
// A plugin that brings its own SRv6 behavior needs the routes naming that
// behavior, and the built-in applier must not act on them: it would read an
// unrecognized codepoint as an ordinary service SID and install a headend
// entry with the wrong semantics, while the plugin's own write to the same
// prefix then fails the cross-owner check. Neither half ends up correct.
//
// So a plugin declares its codepoints at registration and the demux
// consults this registry to decide who a route is for. A codepoint may be
// claimed by one plugin at a time; a second claim is rejected at
// registration rather than resolved at delivery, so the conflict surfaces
// to whoever is deploying rather than as a forwarding anomaly later.
//
// Codepoints Vinbero implements itself are not claimable -- an operator
// cannot take End.DT4 away from the built-in path.
type ClaimRegistry struct {
	mu sync.RWMutex
	// byCodepoint maps an endpoint behavior to the plugin holding it.
	byCodepoint map[uint16]string
	// reserved are the codepoints the built-in appliers implement.
	reserved map[uint16]struct{}
}

// NewClaimRegistry builds a registry whose reserved codepoints are the ones
// Vinbero's own appliers handle.
func NewClaimRegistry(reserved []uint16) *ClaimRegistry {
	r := &ClaimRegistry{
		byCodepoint: make(map[uint16]string),
		reserved:    make(map[uint16]struct{}, len(reserved)),
	}
	for _, cp := range reserved {
		r.reserved[cp] = struct{}{}
	}
	return r
}

// Claim assigns every codepoint to plugin, or returns an error and changes
// nothing. Claiming is all-or-nothing so a partially applied claim cannot
// leave a plugin owning half its behaviors.
//
// Re-claiming the exact same set under the same plugin name succeeds, which
// is what an in-place upgrade of a plugin does.
func (r *ClaimRegistry) Claim(plugin string, codepoints []uint16) error {
	if plugin == "" {
		return fmt.Errorf("claim: empty plugin name")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, cp := range codepoints {
		if cp == 0 {
			return fmt.Errorf("claim: codepoint 0 means \"no behavior\" and cannot be claimed")
		}
		if _, isReserved := r.reserved[cp]; isReserved {
			return fmt.Errorf("claim: codepoint %#x is implemented by vinbero and cannot be claimed", cp)
		}
		if holder, taken := r.byCodepoint[cp]; taken && holder != plugin {
			return fmt.Errorf("claim: codepoint %#x is already claimed by plugin %q", cp, holder)
		}
	}
	for _, cp := range codepoints {
		r.byCodepoint[cp] = plugin
	}
	return nil
}

// Release drops every codepoint held by plugin. Safe to call for a plugin
// that holds none.
func (r *ClaimRegistry) Release(plugin string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for cp, holder := range r.byCodepoint {
		if holder == plugin {
			delete(r.byCodepoint, cp)
		}
	}
}

// HolderOf returns the plugin holding a codepoint.
func (r *ClaimRegistry) HolderOf(codepoint uint16) (string, bool) {
	if r == nil {
		return "", false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	holder, ok := r.byCodepoint[codepoint]
	return holder, ok
}

// IsClaimed reports whether a codepoint belongs to some plugin. A nil
// registry claims nothing, so a daemon with no plugin support behaves as it
// did before this existed.
func (r *ClaimRegistry) IsClaimed(codepoint uint16) bool {
	_, ok := r.HolderOf(codepoint)
	return ok
}

// Claims returns the codepoints held by plugin.
func (r *ClaimRegistry) Claims(plugin string) []uint16 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []uint16
	for cp, holder := range r.byCodepoint {
		if holder == plugin {
			out = append(out, cp)
		}
	}
	return out
}
