package scheduler

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newClock() *clock { return &clock{t: time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)} }

func fixed(iv Intervals) func() Intervals { return func() Intervals { return iv } }

func TestTickDueJobs(t *testing.T) {
	c := newClock()
	var ran []Job
	s := New(func(ctx context.Context, j Job) error { ran = append(ran, j); return nil },
		fixed(Intervals{KindDiscovery: 5 * time.Minute, KindPorts: time.Hour}), c.now)
	s.Tick()
	if q := s.Status().Queued; len(q) != 2 || q[0].Kind != KindDiscovery || q[1].Kind != KindPorts {
		t.Fatalf("queue %+v", q)
	}
	for s.Step(context.Background()) {
	}
	if len(ran) != 2 {
		t.Fatalf("ran %v", ran)
	}
	c.advance(4 * time.Minute)
	s.Tick()
	if len(s.Status().Queued) != 0 {
		t.Fatal("nothing should be due at 4m")
	}
	c.advance(2 * time.Minute)
	s.Tick()
	if q := s.Status().Queued; len(q) != 1 || q[0].Kind != KindDiscovery {
		t.Fatalf("queue at 6m %+v", q)
	}
}

func TestTickInsaneClock(t *testing.T) {
	c := &clock{t: time.Unix(0, 0).UTC()}
	s := New(func(context.Context, Job) error { return nil }, fixed(Intervals{KindDiscovery: time.Minute}), c.now)
	s.Tick()
	if len(s.Status().Queued) != 0 {
		t.Fatal("queued with 1970 clock")
	}
}

func TestEnqueueDedupe(t *testing.T) {
	s := New(func(context.Context, Job) error { return nil }, fixed(nil), newClock().now)
	if !s.Enqueue(Job{Kind: KindDiscovery}) || s.Enqueue(Job{Kind: KindDiscovery}) {
		t.Fatal("discovery dedupe")
	}
	if !s.Enqueue(Job{Kind: KindPorts}) || s.Enqueue(Job{Kind: KindPorts, DeviceID: 7}) {
		t.Fatal("ports/all should absorb ports/7")
	}
	s2 := New(func(context.Context, Job) error { return nil }, fixed(nil), newClock().now)
	if !s2.Enqueue(Job{Kind: KindPorts, DeviceID: 7}) || !s2.Enqueue(Job{Kind: KindPorts, DeviceID: 8}) || s2.Enqueue(Job{Kind: KindPorts, DeviceID: 7}) {
		t.Fatal("per-device dedupe")
	}
}

func TestIntervalZeroDisables(t *testing.T) {
	s := New(func(context.Context, Job) error { return nil }, fixed(Intervals{KindDiscovery: 0, KindPorts: time.Hour}), newClock().now)
	s.Tick()
	if q := s.Status().Queued; len(q) != 1 || q[0].Kind != KindPorts {
		t.Fatalf("%+v", q)
	}
}

func TestSequential(t *testing.T) {
	var active, maxActive, count int32
	done := make(chan struct{})
	s := New(func(ctx context.Context, j Job) error {
		n := atomic.AddInt32(&active, 1)
		for {
			m := atomic.LoadInt32(&maxActive)
			if n <= m || atomic.CompareAndSwapInt32(&maxActive, m, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		atomic.AddInt32(&active, -1)
		if atomic.AddInt32(&count, 1) == 5 {
			close(done)
		}
		return nil
	}, fixed(nil), newClock().now)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	for i := int64(1); i <= 5; i++ {
		s.Enqueue(Job{Kind: KindPorts, DeviceID: i})
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("jobs did not run")
	}
	if maxActive != 1 {
		t.Fatalf("max concurrent %d", maxActive)
	}
}

func TestStatusRecordsError(t *testing.T) {
	s := New(func(context.Context, Job) error { return context.DeadlineExceeded }, fixed(nil), newClock().now)
	s.Enqueue(Job{Kind: KindDiscovery})
	s.Step(context.Background())
	st := s.Status()
	if st.LastErr[KindDiscovery] == "" || st.LastRun[KindDiscovery].IsZero() || st.Running != nil {
		t.Fatalf("%+v", st)
	}
}

func TestTickSpeedKind(t *testing.T) {
	c := newClock()
	s := New(func(context.Context, Job) error { return nil }, fixed(Intervals{KindSpeed: 3 * time.Hour}), c.now)
	s.Tick()
	if q := s.Status().Queued; len(q) != 1 || q[0].Kind != KindSpeed {
		t.Fatalf("queue %+v", q)
	}
	s2 := New(func(context.Context, Job) error { return nil }, fixed(Intervals{KindSpeed: 0}), c.now)
	s2.Tick()
	if q := s2.Status().Queued; len(q) != 0 {
		t.Fatalf("queue %+v", q)
	}
}

func TestMarkRunDelaysTick(t *testing.T) {
	c := newClock()
	s := New(func(context.Context, Job) error { return nil }, fixed(Intervals{KindSpeed: 3 * time.Hour}), c.now)
	s.MarkRun(KindSpeed, c.now().Add(-time.Hour))
	s.Tick()
	if q := s.Status().Queued; len(q) != 0 {
		t.Fatalf("a test from an hour ago must not be repeated at boot: %+v", q)
	}
	c.advance(2 * time.Hour)
	s.Tick()
	if q := s.Status().Queued; len(q) != 1 {
		t.Fatalf("queue %+v", q)
	}
}

func TestJobPortsDedupe(t *testing.T) {
	s := New(func(context.Context, Job) error { return nil }, func() Intervals { return nil }, time.Now)
	if !s.Enqueue(Job{Kind: KindPorts}) {
		t.Fatal("first")
	}
	if s.Enqueue(Job{Kind: KindPorts, DeviceID: 3}) {
		t.Fatal("common scan of all devices covers device 3")
	}
	if !s.Enqueue(Job{Kind: KindPorts, DeviceID: 3, Ports: "1-1024"}) {
		t.Fatal("wider scan must not be swallowed")
	}
	if s.Enqueue(Job{Kind: KindPorts, DeviceID: 3, Ports: "1-1024"}) {
		t.Fatal("duplicate wide scan queued")
	}
}

func TestCancelRunningAndQueued(t *testing.T) {
	started := make(chan struct{})
	s := New(func(ctx context.Context, j Job) error {
		if j.Ports != "" {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	}, func() Intervals { return nil }, time.Now)
	s.Enqueue(Job{Kind: KindPorts, DeviceID: 7, Ports: "1-65535"})
	s.Enqueue(Job{Kind: KindPorts, DeviceID: 7, Ports: "1-1024"})
	s.Enqueue(Job{Kind: KindPorts, DeviceID: 8, Ports: "1-1024"})
	done := make(chan bool)
	go func() { done <- s.Step(context.Background()) }()
	<-started
	n := s.Cancel(func(j Job) bool { return j.Kind == KindPorts && j.DeviceID == 7 })
	if !<-done || n != 2 {
		t.Fatalf("cancelled %d", n)
	}
	st := s.Status()
	if len(st.Queued) != 1 || st.Queued[0].DeviceID != 8 || st.LastErr[KindPorts] != "stopped by user" {
		t.Fatalf("%+v", st)
	}
}
