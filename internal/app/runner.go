// Package app wires scanners, the inventory and the scheduler together.
package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/inventory"
	"github.com/AliSerifDemiralp/honet/internal/netutil"
	"github.com/AliSerifDemiralp/honet/internal/scan/lan"
	"github.com/AliSerifDemiralp/honet/internal/scheduler"
	"github.com/AliSerifDemiralp/honet/internal/speedtest"
	"github.com/AliSerifDemiralp/honet/internal/store"
)

// Runner executes scheduler jobs.
type Runner struct {
	Inv      *inventory.Inventory
	Store    *store.Store
	Disc     lan.Discoverer
	Sweep    lan.Discoverer // for ranges this host is not attached to
	Prober   lan.Prober
	Resolver lan.Resolver
	OUI      func(string) string
	Route    func() (iface string, gw netip.Addr, err error)
	IfaceNet func(iface string) (netip.Prefix, error)
	Enqueue  func(scheduler.Job) bool
	Now      func() time.Time
	Speed    interface {
		Run(context.Context) (speedtest.Result, error)
	}
	// NetBIOS asks a host for its NetBIOS name; nil disables it.
	NetBIOS func(ctx context.Context, ip netip.Addr) string
	// Sleep waits d or until ctx ends; nil uses a timer.
	Sleep func(ctx context.Context, d time.Duration) error
	// HTTPInfo reads a web page title; nil disables it.
	HTTPInfo func(ctx context.Context, ip netip.Addr, port int) string

	mu       sync.Mutex
	lastGood time.Time
	sweptAt  time.Time // end of the last sweep discovery
}

// LastGood returns when the last successful discovery finished.
func (r *Runner) LastGood() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastGood
}

// Run executes one job and records it in the scans table.
func (r *Runner) Run(ctx context.Context, j scheduler.Job) error {
	started := r.Now()
	res, err := r.Store.DB.ExecContext(ctx, `INSERT INTO scans(kind, started) VALUES (?, ?)`, string(j.Kind), store.FormatTime(started))
	if err != nil {
		return err
	}
	scanID, _ := res.LastInsertId()
	var found int
	switch j.Kind {
	case scheduler.KindDiscovery:
		found, err = r.discover(ctx)
	case scheduler.KindPorts:
		found, err = r.probe(ctx, j.DeviceID, j.Ports)
	case scheduler.KindSpeed:
		err = r.speedTest(ctx)
	default:
		err = fmt.Errorf("unknown job kind %q", j.Kind)
	}
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	if _, uerr := r.Store.DB.ExecContext(context.WithoutCancel(ctx), `UPDATE scans SET finished = ?, found = ?, error = ? WHERE id = ?`,
		store.FormatTime(r.Now()), found, msg, scanID); uerr != nil && err == nil {
		err = uerr
	}
	return err
}

func (r *Runner) target(ctx context.Context) (string, netip.Prefix, netip.Addr, error) {
	s, err := r.Store.LoadSettings(ctx)
	if err != nil {
		return "", netip.Prefix{}, netip.Addr{}, err
	}
	routeIface, gw, rerr := r.Route()
	iface := s.Interface
	if iface == "" {
		if rerr != nil {
			return "", netip.Prefix{}, netip.Addr{}, fmt.Errorf("no default route; set the interface in Settings: %w", rerr)
		}
		iface = routeIface
	}
	if iface != routeIface {
		gw = netip.Addr{}
	}
	cidr := s.CIDR
	if cidr == "" {
		p, err := r.IfaceNet(iface)
		if err != nil {
			return "", netip.Prefix{}, netip.Addr{}, err
		}
		if p.Bits() < 22 {
			// Automatic mode on a large subnet (Docker bridge, some routers):
			// scan the /24 around this host instead of refusing to scan.
			p = netip.PrefixFrom(p.Addr(), 24)
		}
		cidr = p.Masked().String()
	}
	p, err := netutil.ValidateScanCIDR(cidr)
	if err != nil {
		return "", netip.Prefix{}, netip.Addr{}, fmt.Errorf("scan range %s: %w", cidr, err)
	}
	return iface, p, gw, nil
}

func (r *Runner) discover(ctx context.Context) (int, error) {
	iface, p, gw, err := r.target(ctx)
	if err != nil {
		return 0, err
	}
	disc, hostNet, offLink := r.Disc, netip.Prefix{}, false
	if r.Sweep != nil {
		if n, err := r.IfaceNet(iface); err == nil {
			hostNet = n.Masked()
			offLink = !(hostNet.Contains(p.Addr()) && hostNet.Bits() <= p.Bits())
		}
	}
	if offLink {
		// ARP only reaches the attached network; elsewhere probe each
		// address. MAC addresses (and the gateway MAC check) are unknown.
		disc, gw = r.Sweep, netip.Addr{}
	}
	hosts, err := disc.Discover(ctx, iface, p)
	if err != nil {
		return 0, err
	}
	lan.Enrich(hosts, r.OUI, func(ip netip.Addr) string {
		return lan.ReverseName(ctx, r.Resolver, ip, time.Second)
	})
	r.netbiosNames(ctx, hosts)
	need, err := r.Inv.ApplyDiscovery(ctx, hosts, gw)
	if offLink && errors.Is(err, inventory.ErrEmptyDiscovery) {
		return 0, fmt.Errorf("no device answered in %s; this host is on %s (%s), check the scan range in Settings", p, hostNet, iface)
	}
	if err != nil {
		return len(hosts), err
	}
	good := r.Now()
	r.mu.Lock()
	r.lastGood = good
	if offLink {
		r.sweptAt = good
	}
	r.mu.Unlock()
	if err := r.Inv.EvaluateWatch(ctx, good); err != nil {
		return len(hosts), err
	}
	if err := r.Inv.EvaluatePresence(ctx); err != nil {
		return len(hosts), err
	}
	for _, id := range need {
		r.Enqueue(scheduler.Job{Kind: scheduler.KindPorts, DeviceID: id})
	}
	return len(hosts), nil
}

// speedTest runs one speed test and stores the result, failures included.
func (r *Runner) speedTest(ctx context.Context) error {
	if r.Speed == nil {
		return errors.New("speed test not configured")
	}
	at := r.Now()
	res, err := r.Speed.Run(ctx)
	if serr := r.Inv.SaveSpeedTest(context.WithoutCancel(ctx), at, res, err); serr != nil && err == nil {
		err = serr
	}
	return err
}

// SweepSettle is how long port scans wait after a sweep. Connection
// attempts to silent addresses linger in NAT layers (Docker Desktop on
// Windows keeps each one about 21 s), and new connections are dropped
// until they clear, which would make open ports look closed.
const SweepSettle = 25 * time.Second

func (r *Runner) settle(ctx context.Context) error {
	r.mu.Lock()
	wait := SweepSettle - r.Now().Sub(r.sweptAt)
	if r.sweptAt.IsZero() {
		wait = 0
	}
	r.sweptAt = time.Time{} // wait once per sweep
	r.mu.Unlock()
	if wait <= 0 {
		return nil
	}
	if r.Sleep != nil {
		return r.Sleep(ctx, wait)
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *Runner) probe(ctx context.Context, id int64, spec string) (int, error) {
	ports, err := lan.JobPorts(spec)
	if err != nil {
		return 0, err
	}
	if err := r.settle(ctx); err != nil {
		return 0, err
	}
	ids := []int64{id}
	if id == 0 {
		since := r.LastGood()
		if since.IsZero() {
			return 0, errors.New("no successful discovery yet")
		}
		var err error
		if ids, err = r.Inv.OnlineIDs(ctx, since.Add(-time.Minute)); err != nil {
			return 0, err
		}
	}
	n := 0
	for _, id := range ids {
		if ctx.Err() != nil {
			return n, ctx.Err()
		}
		ip, err := r.Inv.IPOf(ctx, id)
		if err != nil {
			continue // device was deleted meanwhile
		}
		open, err := r.Prober.Probe(ctx, ip, ports)
		if err != nil {
			return n, err
		}
		if ctx.Err() != nil {
			return n, ctx.Err() // partial results would look like closed ports
		}
		if err := r.Inv.ApplyPortScan(ctx, id, ports, open); err != nil {
			return n, err
		}
		if err := r.webTitle(ctx, id, ip, open); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// netbiosNames asks hosts without a DNS name for their NetBIOS name.
func (r *Runner) netbiosNames(ctx context.Context, hosts []lan.Host) {
	if r.NetBIOS == nil {
		return
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32)
	for i := range hosts {
		if hosts[i].Hostname != "" || hosts[i].Self {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(h *lan.Host) {
			defer func() { <-sem; wg.Done() }()
			h.Hostname = r.NetBIOS(ctx, h.IP)
		}(&hosts[i])
	}
	wg.Wait()
}

// webPorts are tried in this order for a page title.
var webPorts = []int{80, 443, 8080, 8443}

// webTitle stores the title of the device's web page, if it has one. A
// device that stops answering keeps its last title.
func (r *Runner) webTitle(ctx context.Context, id int64, ip netip.Addr, open []int) error {
	if r.HTTPInfo == nil {
		return nil
	}
	for _, p := range webPorts {
		if !slices.Contains(open, p) {
			continue
		}
		if info := r.HTTPInfo(ctx, ip, p); info != "" {
			return r.Inv.SetHTTPInfo(ctx, id, info)
		}
		return nil
	}
	return nil
}

// DefaultRoute reads the IPv4 default route from /proc/net/route.
func DefaultRoute() (string, netip.Addr, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", netip.Addr{}, err
	}
	defer f.Close()
	return netutil.ParseProcRoute(f)
}

// InterfacePrefix returns the first IPv4 address of iface with its prefix
// length (host bits kept, so callers know this host's address).
func InterfacePrefix(iface string) (netip.Prefix, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return netip.Prefix{}, err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return netip.Prefix{}, err
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
			ip, _ := netip.AddrFromSlice(n.IP.To4())
			ones, _ := n.Mask.Size()
			return netip.PrefixFrom(ip, ones), nil
		}
	}
	return netip.Prefix{}, fmt.Errorf("interface %s has no IPv4 address", iface)
}
