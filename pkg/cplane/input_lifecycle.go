package cplane

import (
	"context"
	"errors"
	"fmt"
)

func (p *PluginOps) holdInputReplay() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.strictInputs {
		p.inputReady = false
		p.inputReplaying = true
	}
}
func (p *PluginOps) beginInputReplay() {
	if !p.strictInputs {
		return
	}
	p.applyMu.Lock()
	defer p.applyMu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.inputEpoch++
	p.inputReady = false
	p.inputReplaying = true
	// A failed cleanup must finish before a replay can authorize new writes.
	if !p.inputCleanupPending {
		p.inputFault = ""
		p.inputRecoveryReplay = false
	}
	p.open = map[uint64]*applyTxn{}
	p.staged = nil
	p.pending = nil
	p.latestComposition = nil
}
func (p *PluginOps) finishInputReplay() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.strictInputs {
		return nil
	}
	if p.inputFault != "" || p.inputCleanupPending {
		return fmt.Errorf("input incomplete: %s", p.inputFault)
	}
	p.inputReady = true
	p.inputReplaying = false
	return nil
}
func (p *PluginOps) noteInputLoss() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.strictInputs {
		p.inputReady = false
		p.inputReplaying = false
		p.inputFault = "delivery queue lost input"
		p.inputRecoveryReplay = true
		p.inputCleanupPending = true
		p.inputEpoch++
		p.pending = nil
		p.latestComposition = nil
		p.staged = nil
		p.open = map[uint64]*applyTxn{}
	}
}
func (p *PluginOps) failInput(reason string) error {
	if !p.strictInputs {
		return nil
	}
	p.applyMu.Lock()
	p.mu.Lock()
	p.inputReady = false
	p.inputReplaying = false
	p.latestComposition = nil
	p.inputFault = reason
	p.inputRecoveryReplay = false
	p.inputCleanupPending = true
	p.inputEpoch++
	p.open = map[uint64]*applyTxn{}
	p.pending = nil
	p.staged = nil
	p.mu.Unlock()
	p.applyMu.Unlock()
	return p.cleanupInput()
}
func (p *PluginOps) cleanupInput() error {
	p.applyMu.Lock()
	defer p.applyMu.Unlock()
	var errs []error
	if p.advertise != nil {
		if err := p.advertise.WithdrawOwner(context.Background(), p.owner); err != nil {
			errs = append(errs, err)
		}
	}
	if p.services != nil {
		if err := p.services.flush(p.owner); err != nil {
			errs = append(errs, err)
		}
	}
	p.compositionValid = false
	// An incomplete input cannot keep forwarding stale traffic while withdrawal
	// retries. Keep advertising failures and their leases visible independently.
	for _, af := range []AddressFamily{AFv4, AFv6} {
		if _, err := p.headend.PruneOwner(p.owner, af); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 && p.localSIDs != nil {
		if err := p.localSIDs.ReleaseOwner(p.owner); err != nil {
			errs = append(errs, err)
		}
	}
	p.mu.Lock()
	p.inputCleanupPending = len(errs) > 0
	p.mu.Unlock()
	return errors.Join(errs...)
}

// InputState reports host-enforced readiness, independent of guest diagnostics.
func (p *PluginOps) InputState() (bool, string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.inputReady, p.inputFault, p.inputCleanupPending
}

// A replay started before cleanup completed cannot authorize writes. Request a
// fresh barrier after transient queue-loss cleanup; malformed inputs stay stopped.
func (p *PluginOps) takeInputRecoveryReplay() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.inputRecoveryReplay || p.inputCleanupPending {
		return false
	}
	p.inputRecoveryReplay = false
	return true
}
