// Package lan discovers hosts on the local network with ARP and probes
// their TCP ports with plain connects (no root needed for probing).
package lan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/netutil"
)

// Host is one discovered device.
type Host struct {
	IP         netip.Addr
	MAC        string
	Vendor     string
	Hostname   string
	Randomized bool
	Self       bool // the machine honet runs on
}

// Discoverer finds hosts on iface within p. If two MACs answer for the same
// IP, both are returned.
type Discoverer interface {
	Discover(ctx context.Context, iface string, p netip.Prefix) ([]Host, error)
}

// ErrUnsupported is returned by the ARP discoverer on non-Linux systems.
var ErrUnsupported = errors.New("ARP discovery is only supported on Linux")

// CommonPorts is the port list carried over from the original Honet
// scanner, plus ports that identify printers, cameras, NAS boxes, media
// players and iPhones.
var CommonPorts = []int{20, 21, 69, 22, 23, 3389, 5900, 5985, 5986, 25, 110, 143, 465, 587,
	53, 67, 68, 123, 139, 161, 162, 389, 445, 80, 443, 8000, 8008, 8080, 8443, 5000, 3000,
	5432, 3306, 1433, 1521, 27017, 6379, 9042, 9200, 11211, 6443, 10250, 9092, 2181, 9090, 5601,
	9100, 631, 515, 554, 8554, 548, 2049, 5001, 7000, 8009, 62078}

// Prober reports which of ports accept TCP connections on ip.
type Prober interface {
	Probe(ctx context.Context, ip netip.Addr, ports []int) ([]int, error)
}

// TCPProber probes with full TCP connects.
type TCPProber struct {
	Concurrency int
	Timeout     time.Duration
}

// Probe returns the open ports in ascending order. A cancelled context
// stops early and returns what was found so far.
func (p TCPProber) Probe(ctx context.Context, ip netip.Addr, ports []int) ([]int, error) {
	conc := probeConcurrency(p.Concurrency, len(ports))
	d := net.Dialer{Timeout: p.Timeout}
	sem := make(chan struct{}, conc)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var open []int
	for _, port := range ports {
		if ctx.Err() != nil {
			break
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			continue
		}
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()
			c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
			if err != nil {
				return
			}
			c.Close()
			mu.Lock()
			open = append(open, port)
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	sort.Ints(open)
	return open, nil
}

// Resolver is the subset of net.Resolver used for reverse lookups.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// ReverseName returns the first PTR name for ip, cleaned, or "".
func ReverseName(ctx context.Context, r Resolver, ip netip.Addr, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	names, err := r.LookupAddr(ctx, ip.String())
	if err != nil || len(names) == 0 {
		return ""
	}
	return netutil.CleanText(strings.TrimRight(netutil.CleanText(names[0], 256), "."), 64)
}

// Enrich fills Vendor, Randomized and Hostname for each host.
func Enrich(hosts []Host, ouiLookup func(string) string, names func(netip.Addr) string) {
	for i := range hosts {
		h := &hosts[i]
		h.Randomized = netutil.IsLocallyAdministered(h.MAC)
		if h.Vendor == "" && !h.Randomized {
			h.Vendor = ouiLookup(h.MAC)
		}
		if names != nil {
			h.Hostname = names(h.IP)
		}
	}
}

// merge combines ARP replies, kernel ARP table rows for iface within p, and
// the local host, removing duplicate IP+MAC pairs. Result is sorted by IP.
func merge(replies []Host, table []netutil.ARPEntry, iface string, p netip.Prefix, self *Host) []Host {
	type key struct {
		ip  netip.Addr
		mac string
	}
	seen := map[key]bool{}
	var out []Host
	add := func(h Host) {
		k := key{h.IP, h.MAC}
		if seen[k] || !p.Contains(h.IP) {
			return
		}
		seen[k] = true
		out = append(out, h)
	}
	if self != nil {
		add(*self)
	}
	for _, h := range replies {
		add(h)
	}
	for _, e := range table {
		if e.Iface == iface {
			add(Host{IP: e.IP, MAC: e.MAC})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].IP.Less(out[j].IP) })
	return out
}

// probeConcurrency raises the connection limit for wide scans: a host that
// drops packets makes every port wait for the timeout, and all 65535 ports
// at the base limit would hold the single scan worker for half an hour.
func probeConcurrency(base, ports int) int {
	base = max(base, 1)
	if ports > 1024 {
		return max(base, 128)
	}
	return base
}
