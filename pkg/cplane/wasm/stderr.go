package wasm

import (
	"fmt"
	"strings"
)

// Guest stderr is diagnostic only; it cannot grow host memory or become a log stream.
type guestStderr struct {
	data      [4096]byte
	n         int
	truncated bool
}

func (s *guestStderr) Write(p []byte) (int, error) {
	n := copy(s.data[s.n:], p)
	s.n += n
	s.truncated = s.truncated || n < len(p)
	return len(p), nil
}

func (s *guestStderr) reset() { s.n, s.truncated = 0, false }

func (s *guestStderr) annotate(err error) error {
	detail := strings.TrimSpace(string(s.data[:s.n]))
	if detail == "" {
		return err
	}
	label := "guest stderr"
	if s.truncated {
		label += " (truncated)"
	}
	return fmt.Errorf("%w; %s: %q", err, label, detail)
}
