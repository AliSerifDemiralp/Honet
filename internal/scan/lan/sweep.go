package lan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// SweepPorts are tried on addresses that do not answer ping. A refused
// connection proves a host is there just as well as an accepted one. The
// list is short: every silent address costs one connection per port, and
// NAT layers such as Docker Desktop's drop new connections after a few
// thousand, which would spoil the port scans that follow.
var SweepPorts = []int{80, 443, 445, 62078}

// Pinger sends ICMP echo requests (see netmon.Pinger); lost replies are -1.
type Pinger interface {
	Ping(ctx context.Context, ip netip.Addr, n int, timeout time.Duration) ([]time.Duration, error)
}

// SweepDiscoverer finds hosts in ranges this machine is not attached to
// (for example the home LAN seen from a Docker Desktop VM), using ICMP and
// TCP connects. It cannot learn MAC addresses.
type SweepDiscoverer struct {
	Pinger      Pinger // optional
	Dial        func(ctx context.Context, network, addr string) (net.Conn, error)
	Ports       []int
	Concurrency int
	Timeout     time.Duration
}

// NewSweepDiscoverer returns a sweep with sensible defaults.
func NewSweepDiscoverer(p Pinger) SweepDiscoverer {
	d := &net.Dialer{}
	return SweepDiscoverer{Pinger: p, Dial: d.DialContext, Ports: SweepPorts, Concurrency: 64, Timeout: time.Second}
}

func refused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }

func (s SweepDiscoverer) alive(ctx context.Context, ip netip.Addr) bool {
	if s.Pinger != nil {
		rtts, err := s.Pinger.Ping(ctx, ip, 1, s.Timeout)
		if err == nil && len(rtts) > 0 && rtts[0] >= 0 {
			return true // no TCP needed
		}
	}
	ctx, cancel := context.WithTimeout(ctx, s.Timeout+500*time.Millisecond)
	defer cancel()
	found := make(chan struct{}, 1)
	hit := func() {
		select {
		case found <- struct{}{}:
		default:
		}
		cancel()
	}
	var wg sync.WaitGroup
	for _, port := range s.Ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			dctx, dcancel := context.WithTimeout(ctx, s.Timeout)
			defer dcancel()
			c, err := s.Dial(dctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
			if err == nil {
				c.Close()
				hit()
			} else if refused(err) {
				hit()
			}
		}(port)
	}
	wg.Wait()
	select {
	case <-found:
		return true
	default:
		return false
	}
}

// Discover checks every host address of p. iface is ignored.
func (s SweepDiscoverer) Discover(ctx context.Context, iface string, p netip.Prefix) ([]Host, error) {
	p = p.Masked()
	conc := max(s.Concurrency, 1)
	sem := make(chan struct{}, conc)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var out []Host
	last := lastAddr(p)
	for ip := p.Addr().Next(); ip.IsValid() && ip.Less(last) && p.Contains(ip); ip = ip.Next() {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(ip netip.Addr) {
			defer wg.Done()
			defer func() { <-sem }()
			if s.alive(ctx, ip) {
				mu.Lock()
				out = append(out, Host{IP: ip})
				mu.Unlock()
			}
		}(ip)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sortHosts(out)
	return out, nil
}

// lastAddr is the broadcast address of an IPv4 prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	bits := p.Bits()
	for i := 0; i < 4; i++ {
		for b := 0; b < 8; b++ {
			if i*8+b >= bits {
				a[i] |= 0x80 >> b
			}
		}
	}
	return netip.AddrFrom4(a)
}

func sortHosts(h []Host) {
	sort.Slice(h, func(i, j int) bool { return h[i].IP.Less(h[j].IP) })
}
