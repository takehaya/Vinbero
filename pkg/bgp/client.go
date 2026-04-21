// Package bgp is Vinbero's BGP control-plane integration. It hosts the
// GoBGP lifecycle and relays decoded EVPN routes (pkg/evpn) to the BPF
// plumbing. Until the full implementation lands, NewClient returns a Client
// whose Start is a no-op unless WithEnabled(true) is passed.
package bgp

import (
	"context"
	"errors"

	"go.uber.org/zap"
)

// Client is the BGP peer for Vinbero. A zero Client is not usable; use NewClient.
type Client struct {
	logger  *zap.Logger
	enabled bool
}

// NewClient constructs a Client. Start is a no-op unless WithEnabled(true)
// is passed; callers that want real BGP must opt in explicitly.
func NewClient(logger *zap.Logger, opts ...Option) *Client {
	c := &Client{logger: logger.Named("bgp")}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Option configures a Client at construction time.
type Option func(*Client)

// WithEnabled marks the client as "should start" so Start() doesn't early-return.
func WithEnabled(v bool) Option { return func(c *Client) { c.enabled = v } }

// Start launches background goroutines for the BGP peer and returns promptly.
// Callers should pair it with `defer client.Stop()` registered before the
// Start call so cleanup still runs if Start fails partway.
func (c *Client) Start(ctx context.Context) error {
	if !c.enabled {
		c.logger.Debug("BGP client disabled, skipping Start")
		return nil
	}
	return errors.New("BGP integration is not yet implemented; leave --bgp-enabled unset")
}

// Stop is safe to call on a Client that never Started, or after a partial
// Start failure. It blocks until in-flight route handlers drain so callers
// can safely tear down downstream BPF state afterwards.
func (c *Client) Stop() {}
