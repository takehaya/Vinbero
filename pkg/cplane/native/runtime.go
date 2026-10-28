package native

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/bgpobserver"
	"github.com/takehaya/vinbero/sdk/go/cplane/cdplanecontroller"
	"github.com/takehaya/vinbero/sdk/go/cplane/customcontroller"
	"github.com/takehaya/vinbero/sdk/go/cplane/evpncontroller"
	"github.com/takehaya/vinbero/sdk/go/cplane/mupcontroller"
	"go.uber.org/zap"
)

// Config supplies the same encoded input and host surface as a WASM instance.
// Module must be empty. MaxMemoryPages and MaxModuleBytes do not constrain the
// native heap or executable. CallTimeout is checked cooperatively, not enforced
// by interrupting a running Go function.
type Config struct {
	wasm.Config
	Implementation string
	Version        string
}

var (
	ErrClosed = errors.New("native: instance closed")
	ErrPanic  = errors.New("native: controller panicked")
)

type controller interface {
	Update([]cplane.Event) []cplane.EventResult
	Tick(int64)
}

// Instance owns one controller. Calls, including Close, are serialized. A hung
// call can block this worker and Close; process supervision is the hard stop.
type Instance struct {
	mu         sync.Mutex
	closed     bool
	controller controller
	host       *host
	limit      int
	timeout    time.Duration
}

// Instantiate validates the catalog and config before constructing a controller.
// The manager must authorize registration before calling this function.
func Instantiate(ctx context.Context, cfg Config) (inst *Instance, err error) {
	if err = ValidateIdentity(cfg.Implementation, cfg.Version); err != nil {
		return nil, err
	}
	if cfg.Name == "" || cfg.Ops == nil || len(cfg.Module) != 0 {
		return nil, fmt.Errorf("%w: native requires name, host ops and no WASM module", wasm.ErrAdmission)
	}
	descriptor, _ := Lookup(cfg.Implementation)
	if descriptor.Write && !grantsWrite(cfg.Capabilities) {
		return nil, fmt.Errorf("%w: native writing profile requires a write capability", wasm.ErrAdmission)
	}
	limit := cfg.Limits.MaxBufferBytes
	if limit <= 0 {
		limit = wasm.DefaultLimits().MaxBufferBytes
	}
	timeout := cfg.Limits.CallTimeout
	if timeout <= 0 {
		timeout = wasm.DefaultLimits().CallTimeout
	}
	if len(cfg.ConfigBlob) > limit {
		return nil, fmt.Errorf("%w: native config exceeds buffer limit %d", wasm.ErrAdmission, limit)
	}
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	h := &host{ops: cfg.Ops, logger: logger.With(zap.String("plugin", cfg.Name)), limit: limit}
	i := &Instance{host: h, limit: limit, timeout: timeout}
	err = i.call(ctx, func() error {
		switch cfg.Implementation {
		case MUPComposition, MUPCompositionObserver:
			input, decodeErr := cplane.DecodeInputConfig(cfg.ConfigBlob, wasm.InputFeatureBGPPath|wasm.InputFeatureContexts)
			if decodeErr != nil {
				return decodeErr
			}
			var client mupcontroller.CompositionClient
			if descriptor.Write {
				client = &cplane.Client{Host: h}
			}
			i.controller, err = mupcontroller.New(input, client, h.log)
		case EVPNIMET:
			input, decodeErr := cplane.DecodeInputConfig(cfg.ConfigBlob, wasm.InputFeatureBGPPath|wasm.InputFeatureContexts)
			if decodeErr != nil {
				return decodeErr
			}
			i.controller, err = evpncontroller.New(input, &cplane.Client{Host: h}, h.log)
		case CustomBehavior:
			i.controller, err = customcontroller.New(cfg.ConfigBlob, &cplane.Client{Host: h}, h.log)
		case CustomCDplaneBehavior:
			i.controller, err = cdplanecontroller.New(cfg.ConfigBlob, &cplane.Client{Host: h}, h.log)
		case BGPObserver:
			i.controller, err = bgpobserver.New(wasm.InputFeatureBGPPath, h.log)
		default:
			return fmt.Errorf("native: no constructor for %q", cfg.Implementation)
		}
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("%w: native configure: %w", wasm.ErrAdmission, err)
	}
	return i, nil
}

// HandleEvents uses the same event decoder and status encoder as the guest ABI.
func (i *Instance) HandleEvents(ctx context.Context, batch []byte) (out []byte, err error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	err = i.call(ctx, func() error {
		if len(batch) > i.limit {
			return fmt.Errorf("native: event buffer exceeds limit %d", i.limit)
		}
		events, err := cplane.DecodeEvents(batch)
		if err != nil {
			return fmt.Errorf("native: malformed event batch: %w", err)
		}
		out = cplane.EncodeResults(i.controller.Update(events))
		if len(out) > i.limit {
			out = nil
			return fmt.Errorf("native: result buffer exceeds limit %d", i.limit)
		}
		return nil
	})
	if err != nil {
		out = nil
	}
	return out, err
}

// Tick retries pending output using the same serial call path as event delivery.
func (i *Instance) Tick(ctx context.Context, nowNs int64) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.call(ctx, func() error { i.controller.Tick(nowNs); return nil })
}

// Close releases the controller after any active call returns.
func (i *Instance) Close(context.Context) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.closed = true
	i.controller = nil
	return nil
}

// call never launches a detached goroutine. Expiry is observed at host calls and
// after the controller returns, and cannot undo already committed host writes.
func (i *Instance) call(ctx context.Context, fn func() error) (err error) {
	if i.closed {
		return ErrClosed
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	callCtx, cancel := context.WithTimeout(ctx, i.timeout)
	defer cancel()
	i.host.active = callCtx
	defer func() {
		i.host.active = nil
		if recovered := recover(); recovered != nil {
			i.closed = true
			err = fmt.Errorf("%w: %v", ErrPanic, recovered)
		}
	}()
	err = fn()
	if deadline := callCtx.Err(); deadline != nil {
		i.closed = true
		return fmt.Errorf("native: cooperative call deadline: %w", deadline)
	}
	return err
}

func grantsWrite(caps wasm.Capabilities) bool {
	return caps.Has(wasm.CapHeadend) || caps.Has(wasm.CapMUP) || caps.Has(wasm.CapEVPN) || caps.Has(wasm.CapAdvertise) || caps.Has(wasm.CapLocalSID)
}
