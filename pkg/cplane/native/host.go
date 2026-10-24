package native

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	"github.com/takehaya/vinbero/sdk/go/cplane"
	"go.uber.org/zap"
)

// host preserves the guest Host transport and status semantics. PluginOps owns
// all capability, scope, quota and ownership validation behind this adapter.
type host struct {
	ops                  wasm.HostOps
	logger               *zap.Logger
	limit                int
	active               context.Context
	logWindow            time.Time
	logCount, logDropped int
}

func (h *host) canceled() bool { return h.active == nil || h.active.Err() != nil }

func (h *host) Begin(kind cplane.Kind) uint64 {
	if h.canceled() {
		return 0
	}
	generation, err := h.ops.ApplyBegin(uint32(kind))
	if err != nil {
		h.logger.Warn("plugin apply_begin failed", zap.Uint32("kind", uint32(kind)), zap.Error(err))
		return 0
	}
	return generation
}

func (h *host) Put(generation uint64, chunk []byte) cplane.Status {
	if h.canceled() || generation == 0 || generation > math.MaxInt64 || len(chunk) > h.limit {
		return cplane.StatusInvalid
	}
	if err := h.ops.ApplyPut(generation, append([]byte(nil), chunk...)); err != nil {
		h.logger.Warn("plugin apply_put failed", zap.Error(err))
		return cplane.StatusInvalid
	}
	return cplane.StatusOK
}

func (h *host) Commit(generation uint64) cplane.Status {
	if generation == 0 || generation > math.MaxInt64 {
		return cplane.StatusInvalid
	}
	if h.canceled() {
		h.ops.ApplyAbort(generation)
		return cplane.StatusInternal
	}
	if err := h.ops.ApplyCommit(generation); err != nil {
		h.logger.Warn("plugin apply_commit failed", zap.Error(err))
		var denied interface{ Denied() bool }
		if errors.As(err, &denied) && denied.Denied() {
			return cplane.StatusDenied
		}
		return cplane.StatusInternal
	}
	return cplane.StatusOK
}

func (h *host) Abort(generation uint64) {
	if generation > 0 && generation <= math.MaxInt64 {
		h.ops.ApplyAbort(generation)
	}
}

// These limits match wasm/host.go. Calls are serialized by Instance.mu.
func (h *host) log(level cplane.LogLevel, message string) {
	now := time.Now()
	if now.Sub(h.logWindow) >= time.Second {
		if h.logDropped > 0 {
			h.logger.Warn("dropped log lines from a plugin writing faster than the limit", zap.Int("dropped", h.logDropped))
		}
		h.logWindow, h.logCount, h.logDropped = now, 0, 0
	}
	if h.logCount >= 64 {
		h.logDropped++
		return
	}
	h.logCount++
	if len(message) > 4096 {
		h.logger.Warn("plugin log rejected: message too long", zap.Int("length", len(message)), zap.Int("limit", 4096))
		return
	}
	h.ops.Log(int32(level), message)
}
