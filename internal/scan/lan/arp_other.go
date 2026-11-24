//go:build !linux

package lan

import (
	"context"
	"net/netip"
	"time"
)

type arpDiscoverer struct{}

// NewARPDiscoverer returns a discoverer that always fails off Linux.
func NewARPDiscoverer(pps int, collect time.Duration) Discoverer { return arpDiscoverer{} }

func (arpDiscoverer) Discover(ctx context.Context, iface string, p netip.Prefix) ([]Host, error) {
	return nil, ErrUnsupported
}
