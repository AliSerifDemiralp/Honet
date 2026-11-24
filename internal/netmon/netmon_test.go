package netmon

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func ms(v ...int) []time.Duration {
	out := make([]time.Duration, len(v))
	for i, x := range v {
		if x < 0 {
			out[i] = -1
		} else {
			out[i] = time.Duration(x) * time.Millisecond
		}
	}
	return out
}

func near(a, b float64) bool { return math.Abs(a-b) < 0.01 }

func TestSummaryMath(t *testing.T) {
	s := Summarize(time.Time{}, "1.1.1.1", ms(10, 20, -1, 30, 40), []float64{12, 14})
	if s.MinMs != 10 || s.AvgMs != 25 || s.MaxMs != 40 || s.LossPct != 20 || !near(s.JitterMs, 10) || s.DNSMs != 13 {
		t.Fatalf("%+v", s)
	}
}

func TestAllLost(t *testing.T) {
	s := Summarize(time.Time{}, "1.1.1.1", ms(-1, -1, -1), nil)
	if s.LossPct != 100 || s.MinMs != 0 || s.AvgMs != 0 || s.MaxMs != 0 || s.JitterMs != 0 || s.DNSMs != -1 {
		t.Fatalf("%+v", s)
	}
}

func TestAggregatorFlushesOnWindowChange(t *testing.T) {
	at := func(m int) time.Time { return time.Date(2026, 11, 23, 12, m, 0, 0, time.UTC) }
	var a Aggregator
	if out := a.Add(Sample{At: at(1), Target: "gateway", RTTs: ms(1, 2)}); out != nil {
		t.Fatal(out)
	}
	if out := a.Add(Sample{At: at(4), Target: "gateway", RTTs: ms(3, -1), DNS: -1}); out != nil {
		t.Fatal(out)
	}
	a.Add(Sample{At: at(4), Target: "1.1.1.1", RTTs: ms(9), DNS: 5 * time.Millisecond})
	out := a.Add(Sample{At: at(5), Target: "gateway", RTTs: ms(1)})
	if len(out) != 2 {
		t.Fatalf("%+v", out)
	}
	g := out[0]
	if g.Target != "gateway" || !g.At.Equal(at(0)) || g.MaxMs != 3 || g.LossPct != 25 {
		t.Fatalf("%+v", g)
	}
	if out[1].Target != "1.1.1.1" || out[1].DNSMs != 5 {
		t.Fatalf("%+v", out[1])
	}
}

type fakePinger struct {
	calls atomic.Int32
	err   error
	rtts  map[string][]time.Duration
}

func (f *fakePinger) Ping(ctx context.Context, ip netip.Addr, n int, timeout time.Duration) ([]time.Duration, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	return f.rtts[ip.String()], nil
}

type fakeResolver struct{}

func (fakeResolver) LookupHost(context.Context, string) ([]string, error) {
	return []string{"1.2.3.4"}, nil
}

func newMon(p Pinger, now *time.Time, saved *[]Summary) *Monitor {
	return &Monitor{
		Pinger:   p,
		Resolver: fakeResolver{},
		Gateway:  func() (netip.Addr, error) { return netip.MustParseAddr("192.168.1.1"), nil },
		Targets:  func() []string { return []string{"1.1.1.1", "not-an-ip"} },
		Save: func(_ context.Context, s []Summary) error {
			*saved = append(*saved, s...)
			return nil
		},
		Now: func() time.Time { return *now },
	}
}

func TestMonitorSkipsWhenBusy(t *testing.T) {
	p := &fakePinger{}
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	var saved []Summary
	m := newMon(p, &now, &saved)
	m.Busy = func() bool { return true }
	if err := m.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p.calls.Load() != 0 {
		t.Fatalf("pinger called %d times while busy", p.calls.Load())
	}
}

func TestMonitorSavesWindow(t *testing.T) {
	p := &fakePinger{rtts: map[string][]time.Duration{"192.168.1.1": ms(1, 1), "1.1.1.1": ms(10, 12)}}
	now := time.Date(2026, 11, 23, 12, 3, 0, 0, time.UTC)
	var saved []Summary
	m := newMon(p, &now, &saved)
	m.Once(context.Background())
	now = now.Add(2 * time.Minute)
	if err := m.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(saved) != 2 || saved[0].Target != "gateway" || saved[1].Target != "1.1.1.1" {
		t.Fatalf("%+v", saved)
	}
	if m.Err() != nil {
		t.Fatal(m.Err())
	}
}

func TestMonitorUnavailable(t *testing.T) {
	p := &fakePinger{err: ErrUnavailable}
	now := time.Date(2026, 11, 23, 12, 3, 0, 0, time.UTC)
	var saved []Summary
	var logs []string
	m := newMon(p, &now, &saved)
	m.Log = func(s string) { logs = append(logs, s) }
	for i := 0; i < 3; i++ {
		if err := m.Once(context.Background()); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("err %v", err)
		}
		now = now.Add(5 * time.Minute)
	}
	if len(saved) != 0 {
		t.Fatalf("saved %+v", saved)
	}
	if !errors.Is(m.Err(), ErrUnavailable) {
		t.Fatal(m.Err())
	}
	if len(logs) != 1 {
		t.Fatalf("want the error logged once, got %q", logs)
	}
}

func TestMonitorWithoutPinger(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 3, 0, 0, time.UTC)
	var saved []Summary
	m := newMon(nil, &now, &saved)
	if err := m.Once(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err %v", err)
	}
}

func TestAggregatorFlush(t *testing.T) {
	var a Aggregator
	if a.Flush() != nil {
		t.Fatal("empty aggregator flushed something")
	}
	a.Add(Sample{At: time.Date(2026, 11, 23, 12, 1, 0, 0, time.UTC), Target: "gateway", RTTs: ms(1)})
	if out := a.Flush(); len(out) != 1 || out[0].Target != "gateway" {
		t.Fatalf("%+v", out)
	}
	if a.Flush() != nil {
		t.Fatal("flushed twice")
	}
}

func TestRunSavesPartialWindowOnStop(t *testing.T) {
	p := &fakePinger{rtts: map[string][]time.Duration{"192.168.1.1": ms(1), "1.1.1.1": ms(10)}}
	now := time.Date(2026, 11, 23, 12, 1, 0, 0, time.UTC)
	var saved []Summary
	m := newMon(p, &now, &saved)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx, func() time.Duration { return time.Hour }); close(done) }()
	for i := 0; i < 200 && p.calls.Load() < 2; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if len(saved) != 2 {
		t.Fatalf("partial window not saved: %+v", saved)
	}
}
