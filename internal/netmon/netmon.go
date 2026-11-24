// Package netmon measures latency to the gateway and to internet hosts and
// condenses the samples into 5-minute summaries.
package netmon

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"
)

// Window is the length of one summary.
const Window = 5 * time.Minute

// GatewayTarget is the target name used for the default gateway.
const GatewayTarget = "gateway"

// ErrUnavailable means ICMP sockets cannot be opened (no CAP_NET_RAW and
// unprivileged ping disabled).
var ErrUnavailable = errors.New("ICMP ping not available")

// Pinger sends n echo requests to ip. A lost packet is reported as -1.
// An error means the measurement could not be made at all.
type Pinger interface {
	Ping(ctx context.Context, ip netip.Addr, n int, timeout time.Duration) ([]time.Duration, error)
}

// Sample is one round of pings to one target. DNS < 0 means the lookup
// failed; 0 means it was not measured.
type Sample struct {
	At     time.Time
	Target string
	RTTs   []time.Duration
	DNS    time.Duration
}

// Summary condenses the samples of one window for one target. DNSMs is -1
// when no lookup succeeded in the window.
type Summary struct {
	At       time.Time
	Target   string
	MinMs    float64
	AvgMs    float64
	MaxMs    float64
	JitterMs float64 // mean absolute difference of successive replies
	LossPct  float64
	DNSMs    float64
}

func toMs(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// Summarize computes a summary from round-trip times (-1 = lost) and DNS
// lookup times in milliseconds.
func Summarize(at time.Time, target string, rtts []time.Duration, dnsMs []float64) Summary {
	s := Summary{At: at, Target: target, DNSMs: -1}
	var ok []float64
	for _, r := range rtts {
		if r >= 0 {
			ok = append(ok, toMs(r))
		}
	}
	if len(rtts) > 0 {
		s.LossPct = 100 * float64(len(rtts)-len(ok)) / float64(len(rtts))
	}
	if len(ok) > 0 {
		s.MinMs, s.MaxMs = ok[0], ok[0]
		sum := 0.0
		for i, v := range ok {
			sum += v
			s.MinMs = min(s.MinMs, v)
			s.MaxMs = max(s.MaxMs, v)
			if i > 0 {
				d := v - ok[i-1]
				if d < 0 {
					d = -d
				}
				s.JitterMs += d
			}
		}
		s.AvgMs = sum / float64(len(ok))
		if len(ok) > 1 {
			s.JitterMs /= float64(len(ok) - 1)
		}
	}
	if len(dnsMs) > 0 {
		sum := 0.0
		for _, v := range dnsMs {
			sum += v
		}
		s.DNSMs = sum / float64(len(dnsMs))
	}
	return s
}

// Aggregator collects samples and emits summaries when a window closes.
type Aggregator struct {
	win   time.Time
	order []string
	rtts  map[string][]time.Duration
	dns   map[string][]float64
}

// Add records s. When s starts a new window, the summaries of the previous
// window are returned, one per target in the order first seen.
func (a *Aggregator) Add(s Sample) []Summary {
	w := s.At.Truncate(Window)
	var out []Summary
	if a.rtts != nil && !w.Equal(a.win) {
		out = a.Flush()
	}
	if a.rtts == nil {
		a.win, a.order = w, nil
		a.rtts, a.dns = map[string][]time.Duration{}, map[string][]float64{}
	}
	if _, ok := a.rtts[s.Target]; !ok {
		a.order = append(a.order, s.Target)
	}
	a.rtts[s.Target] = append(a.rtts[s.Target], s.RTTs...)
	if s.DNS > 0 {
		a.dns[s.Target] = append(a.dns[s.Target], toMs(s.DNS))
	}
	return out
}

// Flush returns the summaries of the current, possibly partial, window and
// starts over. It returns nil when nothing was collected.
func (a *Aggregator) Flush() []Summary {
	if a.rtts == nil {
		return nil
	}
	var out []Summary
	for _, t := range a.order {
		out = append(out, Summarize(a.win, t, a.rtts[t], a.dns[t]))
	}
	a.rtts = nil
	return out
}

// Monitor pings the gateway and the configured targets.
type Monitor struct {
	Pinger   Pinger
	Resolver interface {
		LookupHost(ctx context.Context, host string) ([]string, error)
	}
	Gateway func() (netip.Addr, error)
	Targets func() []string
	Busy    func() bool // true while a speed test saturates the link
	Save    func(context.Context, []Summary) error
	Now     func() time.Time
	Log     func(string)

	agg Aggregator
	mu  sync.Mutex
	err error
}

// Err returns the error of the last round, if pinging was impossible.
func (m *Monitor) Err() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.err
}

func (m *Monitor) setErr(err error) {
	m.mu.Lock()
	changed := (err == nil) != (m.err == nil) || (err != nil && err.Error() != m.err.Error())
	m.err = err
	m.mu.Unlock()
	if changed && err != nil && m.Log != nil {
		m.Log("latency monitor: " + err.Error())
	}
}

// Once runs one round: five pings per target and one DNS lookup.
func (m *Monitor) Once(ctx context.Context) error {
	if m.Busy != nil && m.Busy() {
		return nil
	}
	if m.Pinger == nil {
		m.setErr(ErrUnavailable)
		return ErrUnavailable
	}
	now := m.Now()
	var dns time.Duration
	if m.Resolver != nil {
		lctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		start := time.Now()
		if _, err := m.Resolver.LookupHost(lctx, "cloudflare.com"); err != nil {
			dns = -1
		} else {
			dns = max(time.Since(start), time.Microsecond)
		}
		cancel()
	}
	type target struct {
		name string
		ip   netip.Addr
	}
	var targets []target
	if m.Gateway != nil {
		if gw, err := m.Gateway(); err == nil && gw.IsValid() {
			targets = append(targets, target{GatewayTarget, gw})
		}
	}
	for _, t := range m.Targets() {
		if ip, err := netip.ParseAddr(t); err == nil {
			targets = append(targets, target{ip.String(), ip})
		}
	}
	var firstErr error
	var out []Summary
	for _, t := range targets {
		rtts, err := m.Pinger.Ping(ctx, t.ip, 5, time.Second)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		s := Sample{At: now, Target: t.name, RTTs: rtts}
		if t.name != GatewayTarget {
			s.DNS = dns
		}
		out = append(out, m.agg.Add(s)...)
	}
	m.setErr(firstErr)
	if len(out) > 0 && m.Save != nil {
		if err := m.Save(ctx, out); err != nil {
			return err
		}
	}
	return firstErr
}

// Run calls Once every every() until ctx ends; 0 pauses the monitor and
// the interval is checked again after a minute. On exit the partial window
// is saved, so a restart does not lose up to five minutes of data.
func (m *Monitor) Run(ctx context.Context, every func() time.Duration) {
	defer func() {
		if out := m.agg.Flush(); len(out) > 0 && m.Save != nil {
			sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			if err := m.Save(sctx, out); err != nil && m.Log != nil {
				m.Log("latency monitor: save on stop: " + err.Error())
			}
		}
	}()
	for {
		d := every()
		if d > 0 {
			m.Once(ctx)
		} else {
			d = time.Minute
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(d):
		}
	}
}
