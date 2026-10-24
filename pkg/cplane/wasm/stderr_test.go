package wasm

import (
	"errors"
	"strings"
	"testing"
)

func TestGuestStderrBoundedPerCall(t *testing.T) {
	var stderr guestStderr
	for _, text := range []string{"fatal error: ", strings.Repeat("x", 8192), "discarded tail"} {
		if n, err := stderr.Write([]byte(text)); n != len(text) || err != nil {
			t.Fatalf("stderr changed write result: %d %v", n, err)
		}
	}
	cause := errors.New("guest trapped")
	err := stderr.annotate(cause)
	if !errors.Is(err, cause) || !strings.Contains(err.Error(), "fatal error: ") ||
		!strings.Contains(err.Error(), "truncated") || strings.Contains(err.Error(), "discarded tail") ||
		strings.Contains(err.Error(), strings.Repeat("x", 4097)) {
		t.Fatalf("unbounded or missing diagnostics: %v", err)
	}
	stderr.reset()
	if err := stderr.annotate(cause); err != cause {
		t.Fatalf("previous call's stderr leaked: %v", err)
	}
}
