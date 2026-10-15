package wasm

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestOversizedLogRespectsQuota(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	inst := &Instance{logger: zap.New(core), logWindow: time.Now(), logCount: logBurst}
	// This instance already exhausted the current one-second logging quota.
	// Oversized lengths need no memory lookup, so no guest memory is required.
	for j := 0; j < 1000; j++ {
		inst.hostLog(context.Background(), nil, 1, 0, maxLogMessageBytes+1)
	}
	t.Logf("already exhausted quota=%d; rejected guest calls=1000; emitted warning lines=%d", logBurst, logs.Len())
	if logs.Len() != 0 {
		t.Fatalf("guest still emits %d warnings after exhausting log quota", logs.Len())
	}
}
