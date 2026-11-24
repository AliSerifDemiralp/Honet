package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/auth"
	"github.com/AliSerifDemiralp/honet/internal/config"
	"github.com/AliSerifDemiralp/honet/internal/inventory"
	"github.com/AliSerifDemiralp/honet/internal/netmon"
	"github.com/AliSerifDemiralp/honet/internal/scan/lan"
	"github.com/AliSerifDemiralp/honet/internal/scheduler"
	"github.com/AliSerifDemiralp/honet/internal/speedtest"
	"github.com/AliSerifDemiralp/honet/internal/store"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type fakeDisc struct{}

func (fakeDisc) Discover(ctx context.Context, iface string, p netip.Prefix) ([]lan.Host, error) {
	return nil, errors.New("fake: no network in tests")
}

func testConfig(t *testing.T, extra ...string) config.Config {
	t.Helper()
	args := append([]string{"--data-dir", t.TempDir()}, extra...)
	cfg, err := config.Parse(args, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestServeStartsAndPrintsSetupCode(t *testing.T) {
	cfg := testConfig(t, "--http", "--listen", "127.0.0.1:0")
	ready := make(chan net.Addr, 1)
	deps := serveDeps{
		Disc:     fakeDisc{},
		Route:    func() (string, netip.Addr, error) { return "", netip.Addr{}, errors.New("fake: no route") },
		IfaceNet: func(string) (netip.Prefix, error) { return netip.Prefix{}, errors.New("fake") },
		Ready:    func(a net.Addr) { ready <- a },
	}
	ctx, cancel := context.WithCancel(context.Background())
	out := &syncBuf{}
	done := make(chan error, 1)
	go func() { done <- serveWith(ctx, cfg, out, deps) }()

	var addr net.Addr
	select {
	case addr = <-ready:
	case err := <-done:
		t.Fatalf("serve exited early: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("server never became ready")
	}
	resp, err := http.Get("http://" + addr.String() + "/setup")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("/setup status %d", resp.StatusCode)
	}
	if !strings.Contains(out.String(), "HONET SETUP CODE: ") {
		t.Fatalf("no setup code in output:\n%s", out.String())
	}
	if resp.Header.Get("Content-Security-Policy") == "" {
		t.Fatal("security headers missing")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop within 10s")
	}
}

func seqPw(pws ...string) func() (string, error) {
	i := 0
	return func() (string, error) {
		if i >= len(pws) {
			return "", errors.New("no more input")
		}
		i++
		return pws[i-1], nil
	}
}

func withUser(t *testing.T, cfg config.Config) {
	t.Helper()
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	a := auth.New(st, time.Now)
	code, err := a.EnsureSetupCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Register(context.Background(), code, "admin", "old password!"); err != nil {
		t.Fatal(err)
	}
}

func canLogin(t *testing.T, cfg config.Config, pw string) bool {
	t.Helper()
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	return auth.New(st, time.Now).Login(context.Background(), "127.0.0.1", "admin", pw) == nil
}

func TestResetPasswordNoUser(t *testing.T) {
	cfg := testConfig(t)
	var out bytes.Buffer
	err := resetPassword(cfg, strings.NewReader(""), &out, seqPw("new password!", "new password!"))
	if err == nil || !strings.Contains(err.Error(), "No user yet") {
		t.Fatalf("err %v", err)
	}
}

func TestResetPasswordMismatch(t *testing.T) {
	cfg := testConfig(t)
	withUser(t, cfg)
	var out bytes.Buffer
	err := resetPassword(cfg, strings.NewReader(""), &out, seqPw("new password!", "other password"))
	if err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("err %v", err)
	}
	if !canLogin(t, cfg, "old password!") {
		t.Fatal("password changed despite mismatch")
	}
}

func TestResetPasswordTooShort(t *testing.T) {
	cfg := testConfig(t)
	withUser(t, cfg)
	var out bytes.Buffer
	if err := resetPassword(cfg, strings.NewReader(""), &out, seqPw("short", "short")); err == nil {
		t.Fatal("short password accepted")
	}
}

func TestResetPasswordOK(t *testing.T) {
	cfg := testConfig(t)
	withUser(t, cfg)
	var out bytes.Buffer
	if err := resetPassword(cfg, strings.NewReader(""), &out, seqPw("new password!", "new password!")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "systemctl restart honet") {
		t.Fatalf("output %q", out.String())
	}
	if !canLogin(t, cfg, "new password!") {
		t.Fatal("new password does not work")
	}
}

type unavailablePinger struct{}

func (unavailablePinger) Ping(context.Context, netip.Addr, int, time.Duration) ([]time.Duration, error) {
	return nil, netmon.ErrUnavailable
}

func TestServePhase2Pages(t *testing.T) {
	cfg := testConfig(t, "--http", "--listen", "127.0.0.1:0")
	ready := make(chan net.Addr, 1)
	deps := serveDeps{
		Disc:      fakeDisc{},
		Route:     func() (string, netip.Addr, error) { return "", netip.Addr{}, errors.New("fake: no route") },
		IfaceNet:  func(string) (netip.Prefix, error) { return netip.Prefix{}, errors.New("fake") },
		Ready:     func(a net.Addr) { ready <- a },
		Pinger:    unavailablePinger{},
		SpeedBase: "http://127.0.0.1:1",
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveWith(ctx, cfg, &syncBuf{}, deps) }()
	var addr net.Addr
	select {
	case addr = <-ready:
	case err := <-done:
		t.Fatalf("serve exited early: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("server never became ready")
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, p := range []string{"/people", "/internet"} {
		resp, err := client.Get("http://" + addr.String() + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Errorf("%s without login: %d", p, resp.StatusCode)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSeedSchedulerSkipsRecentSpeedTest(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/h.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now()
	inv := inventory.New(st, func() time.Time { return now })
	sched := scheduler.New(func(context.Context, scheduler.Job) error { return nil },
		func() scheduler.Intervals { return scheduler.Intervals{scheduler.KindSpeed: 3 * time.Hour} }, func() time.Time { return now })
	inv.SaveSpeedTest(context.Background(), now.Add(-time.Hour), speedtest.Result{DownMbps: 5}, nil)
	seedScheduler(context.Background(), sched, inv)
	sched.Tick()
	if q := sched.Status().Queued; len(q) != 0 {
		t.Fatalf("queued %+v", q)
	}
}
