package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestRateLimitedWriter(t *testing.T) {
	var out bytes.Buffer
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	w := &rateLimitedWriter{out: &out, every: time.Minute, now: func() time.Time { return now }}
	w.Write([]byte("http: TLS handshake error from 1.2.3.4: bad certificate\n"))
	w.Write([]byte("http: TLS handshake error from 1.2.3.5: bad certificate\n"))
	if got := strings.Count(out.String(), "\n"); got != 1 {
		t.Fatalf("%d lines within a minute, want 1:\n%s", got, out.String())
	}
	now = now.Add(61 * time.Second)
	w.Write([]byte("http: TLS handshake error from 1.2.3.6: bad certificate\n"))
	if !strings.Contains(out.String(), "1.2.3.6") || !strings.Contains(out.String(), "1 similar suppressed") {
		t.Fatalf("after a minute:\n%s", out.String())
	}
}
