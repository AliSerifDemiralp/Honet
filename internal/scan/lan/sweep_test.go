package lan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
)

type fakePing struct{ alive map[string]bool }

func (f fakePing) Ping(ctx context.Context, ip netip.Addr, n int, timeout time.Duration) ([]time.Duration, error) {
	if f.alive[ip.String()] {
		return []time.Duration{time.Millisecond}, nil
	}
	return []time.Duration{-1}, nil
}

// fakeDial: "open" accepts, "refused" answers with RST, everything else times out.
func fakeDial(open, refused map[string]bool) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		switch {
		case open[addr]:
			c1, c2 := net.Pipe()
			c2.Close()
			return c1, nil
		case refused[addr]:
			return nil, &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}
		}
		return nil, errors.New("i/o timeout")
	}
}

func sweepIPs(t *testing.T, s SweepDiscoverer, cidr string) []string {
	t.Helper()
	hosts, err := s.Discover(context.Background(), "eth0", netip.MustParsePrefix(cidr))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, h := range hosts {
		if h.MAC != "" {
			t.Fatalf("sweep cannot know MACs: %+v", h)
		}
		out = append(out, h.IP.String())
	}
	return out
}

func TestSweepAliveOnRefused(t *testing.T) {
	s := SweepDiscoverer{Dial: fakeDial(map[string]bool{"192.168.1.1:80": true}, map[string]bool{"192.168.1.7:445": true}),
		Ports: []int{80, 445}, Concurrency: 8, Timeout: 50 * time.Millisecond}
	got := sweepIPs(t, s, "192.168.1.0/28")
	if len(got) != 2 || got[0] != "192.168.1.1" || got[1] != "192.168.1.7" {
		t.Fatalf("%v", got)
	}
}

func TestSweepICMPOnly(t *testing.T) {
	s := SweepDiscoverer{Pinger: fakePing{alive: map[string]bool{"192.168.1.9": true}}, Dial: fakeDial(nil, nil),
		Ports: []int{80}, Concurrency: 8, Timeout: 50 * time.Millisecond}
	if got := sweepIPs(t, s, "192.168.1.0/28"); len(got) != 1 || got[0] != "192.168.1.9" {
		t.Fatalf("%v", got)
	}
}

func TestSweepSkipsNetworkAndBroadcast(t *testing.T) {
	all := map[string]bool{}
	for i := 0; i < 16; i++ {
		all["192.168.1."+strconv.Itoa(i)] = true
	}
	s := SweepDiscoverer{Pinger: fakePing{alive: all}, Dial: fakeDial(nil, nil), Ports: []int{80}, Concurrency: 4, Timeout: 50 * time.Millisecond}
	got := sweepIPs(t, s, "192.168.1.0/28")
	if len(got) != 14 || got[0] != "192.168.1.1" || got[13] != "192.168.1.14" {
		t.Fatalf("%v", got)
	}
}

func TestSweepSkipsTCPWhenPingAnswers(t *testing.T) {
	var mu sync.Mutex
	dialed := map[string]bool{}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		dialed[addr] = true
		mu.Unlock()
		return nil, errors.New("i/o timeout")
	}
	s := SweepDiscoverer{Pinger: fakePing{alive: map[string]bool{"192.168.1.9": true}}, Dial: dial,
		Ports: []int{80, 443}, Concurrency: 4, Timeout: 50 * time.Millisecond}
	if got := sweepIPs(t, s, "192.168.1.8/30"); len(got) != 1 || got[0] != "192.168.1.9" {
		t.Fatalf("%v", got)
	}
	if dialed["192.168.1.9:80"] || !dialed["192.168.1.10:80"] {
		t.Fatalf("dials %v: a host that answers ping needs no TCP; silent ones do", dialed)
	}
}

func TestSweepPortsAreFew(t *testing.T) {
	// Each silent address costs len(SweepPorts) connections; NAT layers
	// (Docker Desktop) drop new connections after a few thousand.
	if len(SweepPorts) > 4 {
		t.Fatalf("%d sweep ports", len(SweepPorts))
	}
}
