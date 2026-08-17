package wasm

import (
	"context"
	"fmt"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"go.uber.org/zap"
)

// Status codes host functions return to the guest. They are small integers
// rather than an error string because the boundary carries no exceptions:
// the guest must be able to branch on the outcome.
const (
	// StatusOK means the call succeeded.
	StatusOK int32 = 0
	// StatusInvalid means the guest supplied something the host rejected
	// (an unknown generation, an out-of-range buffer, a malformed chunk).
	StatusInvalid int32 = 1
	// StatusDenied means the operation was refused by policy -- a key
	// leased by another owner, or a quota that is spent.
	StatusDenied int32 = 2
	// StatusInternal means the host failed for reasons the guest cannot
	// act on.
	StatusInternal int32 = 3
)

// linkHost defines the host module the guest imports from. Every function
// is closed over this instance, so the plugin's identity is fixed at link
// time: there is no owner parameter for a guest to forge.
func (i *Instance) linkHost(ctx context.Context) error {
	b := i.runtime.NewHostModuleBuilder(HostModule)

	b.NewFunctionBuilder().
		WithFunc(i.hostLog).
		Export(HostLog)

	b.NewFunctionBuilder().
		WithFunc(i.hostNowMonotonic).
		Export(HostNowMonotonic)

	b.NewFunctionBuilder().
		WithFunc(i.hostApplyBegin).
		Export(HostApplyBegin)

	b.NewFunctionBuilder().
		WithFunc(i.hostApplyPut).
		Export(HostApplyPut)

	b.NewFunctionBuilder().
		WithFunc(i.hostApplyCommit).
		Export(HostApplyCommit)

	b.NewFunctionBuilder().
		WithFunc(i.hostApplyAbort).
		Export(HostApplyAbort)

	if _, err := b.Instantiate(ctx); err != nil {
		return fmt.Errorf("wasm: link host module: %w", err)
	}
	return nil
}

// hostLog forwards a plugin message into the daemon log.
//
// A sandboxed module has no stdout, no filesystem, and no network, so
// without this a plugin author debugging a quarantined event has nothing
// to look at. The message is read out of guest memory and bounded by the
// same buffer limit as everything else, so a plugin cannot log its way
// through the host's memory.
func (i *Instance) hostLog(_ context.Context, mod api.Module, level, ptr, length int32) {
	if length < 0 || int(length) > i.limits.MaxBufferBytes {
		i.logger.Warn("plugin log rejected: length out of range",
			zap.Int32("length", length))
		return
	}
	msg := ""
	if length > 0 {
		raw, ok := mod.Memory().Read(uint32(ptr), uint32(length))
		if !ok {
			i.logger.Warn("plugin log rejected: buffer out of range",
				zap.Int32("ptr", ptr), zap.Int32("len", length))
			return
		}
		msg = string(raw)
	}
	i.ops.Log(level, msg)
}

// hostNowMonotonic gives the guest a clock.
//
// It is a deliberate hole in the sandbox's determinism: a plugin that
// withdraws a route when a peer has been quiet for N seconds cannot be
// written without one, and on_tick alone does not tell a plugin how much
// time passed. The epoch is unspecified and only differences are
// meaningful, which keeps it useless as a fingerprint of the host.
func (i *Instance) hostNowMonotonic(context.Context) int64 {
	return int64(monotonicSince(i.started))
}

// hostApplyBegin opens a desired-set transaction.
//
// Transactions exist because a desired set does not fit in one call: a
// large set is chunked, and the host must know when the guest has finished
// declaring before it computes a diff. A generation of 0 means the host
// refused to open one.
func (i *Instance) hostApplyBegin(_ context.Context, kind int32) int64 {
	if kind < 0 {
		return 0
	}
	gen, err := i.ops.ApplyBegin(uint32(kind))
	if err != nil {
		i.logger.Warn("plugin apply_begin failed", zap.Int32("kind", kind), zap.Error(err))
		return 0
	}
	return int64(gen)
}

// hostApplyPut appends a chunk of the declared set to an open transaction.
// Nothing is applied here: a chunk that arrives and then a guest that
// traps must leave the data plane untouched.
func (i *Instance) hostApplyPut(_ context.Context, mod api.Module, generation int64, ptr, length int32) int32 {
	if generation <= 0 {
		return StatusInvalid
	}
	if length < 0 || int(length) > i.limits.MaxBufferBytes {
		return StatusInvalid
	}
	var chunk []byte
	if length > 0 {
		raw, ok := mod.Memory().Read(uint32(ptr), uint32(length))
		if !ok {
			return StatusInvalid
		}
		// Copy: the transaction outlives this call, and linear memory
		// moves when the guest grows it.
		chunk = append([]byte(nil), raw...)
	}
	if err := i.ops.ApplyPut(uint64(generation), chunk); err != nil {
		i.logger.Warn("plugin apply_put failed", zap.Error(err))
		return StatusInvalid
	}
	return StatusOK
}

// hostApplyCommit reconciles what the transaction accumulated. This is the
// only point at which a plugin's declaration reaches the data plane.
func (i *Instance) hostApplyCommit(_ context.Context, generation int64) int32 {
	if generation <= 0 {
		return StatusInvalid
	}
	if err := i.ops.ApplyCommit(uint64(generation)); err != nil {
		i.logger.Warn("plugin apply_commit failed", zap.Error(err))
		return commitStatus(err)
	}
	return StatusOK
}

// hostApplyAbort discards an open transaction.
func (i *Instance) hostApplyAbort(_ context.Context, generation int64) {
	if generation <= 0 {
		return
	}
	i.ops.ApplyAbort(uint64(generation))
}

// commitStatus maps a commit failure onto the status the guest sees. A
// plugin can act on "another owner holds this key" -- by narrowing its own
// set -- so that case is distinguished from a host-side failure it can do
// nothing about.
func commitStatus(err error) int32 {
	if isDenied(err) {
		return StatusDenied
	}
	return StatusInternal
}

// compile-time check that the runtime builder shape is what we expect.
var _ = wazero.NewRuntimeConfig
