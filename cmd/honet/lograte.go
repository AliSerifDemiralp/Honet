package main

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// rateLimitedWriter passes at most one log line per interval and reports how
// many were dropped in between. Browsers that have not accepted the
// self-signed certificate yet cause a TLS handshake error on every request;
// this keeps those visible in the journal without flooding the SD card.
type rateLimitedWriter struct {
	out   io.Writer
	every time.Duration
	now   func() time.Time

	mu         sync.Mutex
	last       time.Time
	suppressed int
}

func (w *rateLimitedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	if !w.last.IsZero() && now.Sub(w.last) < w.every {
		w.suppressed++
		return len(p), nil
	}
	w.last = now
	line := strings.TrimRight(string(p), "\n")
	if w.suppressed > 0 {
		line += fmt.Sprintf(" (%d similar suppressed)", w.suppressed)
		w.suppressed = 0
	}
	_, err := io.WriteString(w.out, line+"\n")
	return len(p), err
}
