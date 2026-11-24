// Package scheduler runs scan jobs one at a time. WiFi and Bluetooth share
// one radio on the Pi Zero W, so scans must never overlap.
package scheduler

import (
	"context"
	"sync"
	"time"
)

// Kind names a type of job.
type Kind string

// Job kinds.
const (
	KindDiscovery Kind = "discovery"
	KindPorts     Kind = "ports"
	KindSpeed     Kind = "speedtest"
)

// periodic lists kinds Tick may enqueue, in priority order.
var periodic = []Kind{KindDiscovery, KindPorts, KindSpeed}

// Job is one unit of work. For KindPorts, DeviceID 0 means all online
// devices and Ports is a port list such as "1-1024" ("" = common ports).
type Job struct {
	Kind     Kind
	DeviceID int64
	Ports    string
}

// Intervals maps a kind to how often it runs; 0 disables periodic runs.
type Intervals map[Kind]time.Duration

// Status is a snapshot for the UI.
type Status struct {
	Running      *Job
	RunningSince time.Time
	Queued       []Job
	LastRun      map[Kind]time.Time
	LastErr      map[Kind]string
}

// Scheduler is a single-worker job queue.
type Scheduler struct {
	run       func(context.Context, Job) error
	intervals func() Intervals
	now       func() time.Time

	mu      sync.Mutex
	queue   []Job
	running *Job
	since   time.Time
	lastRun map[Kind]time.Time
	lastErr map[Kind]string
	wake    chan struct{}
	cancel  context.CancelFunc // of the running job
	stopped bool               // the running job was cancelled by the user
}

// New returns a scheduler that executes jobs with run.
func New(run func(context.Context, Job) error, intervals func() Intervals, now func() time.Time) *Scheduler {
	return &Scheduler{
		run: run, intervals: intervals, now: now,
		lastRun: map[Kind]time.Time{}, lastErr: map[Kind]string{},
		wake: make(chan struct{}, 1),
	}
}

func (s *Scheduler) covered(j Job) bool {
	same := func(x Job) bool {
		return x == j || (j.Kind == KindPorts && x.Kind == KindPorts && x.DeviceID == 0 && x.Ports == j.Ports)
	}
	if s.running != nil && same(*s.running) {
		return true
	}
	for _, q := range s.queue {
		if same(q) {
			return true
		}
	}
	return false
}

// Enqueue adds j unless an equivalent job is queued or running.
func (s *Scheduler) Enqueue(j Job) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enqueueLocked(j)
}

func (s *Scheduler) enqueueLocked(j Job) bool {
	if s.covered(j) {
		return false
	}
	s.queue = append(s.queue, j)
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return true
}

// Tick enqueues periodic jobs that are due. It does nothing while the clock
// is obviously wrong (the Pi has no RTC and boots in the past until NTP syncs).
func (s *Scheduler) Tick() {
	now := s.now()
	if now.Year() < 2025 {
		return
	}
	iv := s.intervals()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range periodic {
		d := iv[k]
		if d <= 0 {
			continue
		}
		last, ok := s.lastRun[k]
		if !ok || now.Sub(last) >= d || now.Before(last) {
			s.enqueueLocked(Job{Kind: k})
		}
	}
}

// MarkRun records that a job of kind k last ran at t. At startup this
// carries over runs from before a restart, so a restart does not repeat
// an expensive job such as a speed test.
func (s *Scheduler) MarkRun(k Kind, t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastRun[k] = t
}

// Step runs the next queued job. It returns false if the queue was empty.
func (s *Scheduler) Step(ctx context.Context) bool {
	s.mu.Lock()
	if len(s.queue) == 0 {
		s.mu.Unlock()
		return false
	}
	j := s.queue[0]
	s.queue = s.queue[1:]
	s.running = &j
	s.since = s.now()
	if j.DeviceID == 0 {
		s.lastRun[j.Kind] = s.since
	}
	jctx, cancel := context.WithCancel(ctx)
	s.cancel, s.stopped = cancel, false
	s.mu.Unlock()

	err := s.run(jctx, j)
	cancel()

	s.mu.Lock()
	s.running, s.cancel = nil, nil
	if s.stopped {
		s.lastErr[j.Kind] = "stopped by user"
	} else if err != nil {
		s.lastErr[j.Kind] = err.Error()
	} else {
		delete(s.lastErr, j.Kind)
	}
	s.mu.Unlock()
	return true
}

// Cancel stops the running job and drops queued jobs that match. It
// returns how many jobs it stopped or dropped.
func (s *Scheduler) Cancel(match func(Job) bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	if s.running != nil && match(*s.running) && s.cancel != nil {
		s.cancel()
		s.stopped = true
		n++
	}
	kept := s.queue[:0]
	for _, j := range s.queue {
		if match(j) {
			n++
			continue
		}
		kept = append(kept, j)
	}
	s.queue = kept
	return n
}

// Run ticks every 15 seconds and drains the queue until ctx is done.
func (s *Scheduler) Run(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		s.Tick()
		for ctx.Err() == nil && s.Step(ctx) {
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.wake:
		}
	}
}

// Status returns a snapshot of the scheduler state.
func (s *Scheduler) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{
		Queued:  append([]Job(nil), s.queue...),
		LastRun: map[Kind]time.Time{},
		LastErr: map[Kind]string{},
	}
	if s.running != nil {
		j := *s.running
		st.Running = &j
		st.RunningSince = s.since
	}
	for k, v := range s.lastRun {
		st.LastRun[k] = v
	}
	for k, v := range s.lastErr {
		st.LastErr[k] = v
	}
	return st
}
