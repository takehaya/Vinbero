package bgp

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

func TestClientDisabledByDefault(t *testing.T) {
	c := NewClient(zap.NewNop())
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("disabled Start should no-op, got %v", err)
	}
	c.Stop()
}

func TestClientEnabledErrorsUntilImplemented(t *testing.T) {
	c := NewClient(zap.NewNop(), WithEnabled(true))
	if err := c.Start(context.Background()); err == nil {
		t.Fatal("enabled Start should error until Phase E is implemented")
	}
}
