//go:build linux

package lan

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/mdlayher/arp"

	"github.com/AliSerifDemiralp/honet/internal/netutil"
)

type arpDiscoverer struct {
	pps     int
	collect time.Duration
}

// NewARPDiscoverer sends pps ARP requests per second and collects replies
// for collect after the last request. Needs CAP_NET_RAW.
func NewARPDiscoverer(pps int, collect time.Duration) Discoverer {
	if pps < 1 {
		pps = 1
	}
	return arpDiscoverer{pps: pps, collect: collect}
}

func (d arpDiscoverer) Discover(ctx context.Context, iface string, p netip.Prefix) ([]Host, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	self, err := selfHost(ifi)
	if err != nil {
		return nil, err
	}
	c, err := arp.Dial(ifi)
	if err != nil {
		return nil, fmt.Errorf("arp: %w (is CAP_NET_RAW granted?)", err)
	}
	defer c.Close()

	var (
		mu      sync.Mutex
		replies []Host
		done    = make(chan struct{})
	)
	go func() {
		defer close(done)
		for {
			pkt, _, err := c.Read()
			if err != nil {
				return // deadline reached or socket closed
			}
			if pkt.Operation != arp.OperationReply || !p.Contains(pkt.SenderIP) {
				continue
			}
			mac, err := netutil.NormalizeMAC(pkt.SenderHardwareAddr.String())
			if err != nil {
				continue
			}
			mu.Lock()
			replies = append(replies, Host{IP: pkt.SenderIP, MAC: mac})
			mu.Unlock()
		}
	}()

	tick := time.NewTicker(time.Second / time.Duration(d.pps))
	defer tick.Stop()
	for _, ip := range netutil.Hosts(p) {
		if ip == self.IP {
			continue
		}
		select {
		case <-ctx.Done():
			c.Close()
			<-done
			return nil, ctx.Err()
		case <-tick.C:
		}
		_ = c.Request(ip)
	}
	_ = c.SetReadDeadline(time.Now().Add(d.collect))
	select {
	case <-done:
	case <-ctx.Done():
		c.Close()
		<-done
		return nil, ctx.Err()
	}

	var table []netutil.ARPEntry
	if f, err := os.Open("/proc/net/arp"); err == nil {
		table, _ = netutil.ParseProcARP(f)
		f.Close()
	}
	mu.Lock()
	defer mu.Unlock()
	var selfPtr *Host
	if p.Contains(self.IP) {
		selfPtr = &self
	}
	return merge(replies, table, iface, p, selfPtr), nil
}

func selfHost(ifi *net.Interface) (Host, error) {
	addrs, err := ifi.Addrs()
	if err != nil {
		return Host{}, err
	}
	mac, _ := netutil.NormalizeMAC(ifi.HardwareAddr.String())
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP.To4()); ok && n.IP.To4() != nil {
				return Host{IP: ip, MAC: mac, Self: true}, nil
			}
		}
	}
	return Host{}, fmt.Errorf("interface %s has no IPv4 address", ifi.Name)
}
