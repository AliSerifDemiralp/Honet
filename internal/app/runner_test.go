package app

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/inventory"
	"github.com/AliSerifDemiralp/honet/internal/scan/lan"
	"github.com/AliSerifDemiralp/honet/internal/scheduler"
	"github.com/AliSerifDemiralp/honet/internal/store"
)

type fakeDisc struct {
	hosts  []lan.Host
	err    error
	called bool
	prefix netip.Prefix
}

func (f *fakeDisc) Discover(ctx context.Context, iface string, p netip.Prefix) ([]lan.Host, error) {
	f.called = true
	f.prefix = p
	return f.hosts, f.err
}

type fakeProber struct{ open []int }

func (f fakeProber) Probe(ctx context.Context, ip netip.Addr, ports []int) ([]int, error) {
	return f.open, nil
}

type noNames struct{}

func (noNames) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	return nil, errors.New("nx")
}

func newRunner(t *testing.T, d *fakeDisc) (*Runner, *store.Store, *[]scheduler.Job) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	now := func() time.Time { return time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC) }
	var queued []scheduler.Job
	r := &Runner{
		Inv:      inventory.New(st, now),
		Store:    st,
		Disc:     d,
		Prober:   fakeProber{open: []int{22}},
		Resolver: noNames{},
		OUI:      func(string) string { return "" },
		Route: func() (string, netip.Addr, error) {
			return "wlan0", netip.MustParseAddr("192.168.1.1"), nil
		},
		IfaceNet: func(string) (netip.Prefix, error) { return netip.MustParsePrefix("192.168.1.10/24"), nil },
		Enqueue:  func(j scheduler.Job) bool { queued = append(queued, j); return true },
		Now:      now,
	}
	return r, st, &queued
}

func TestRunnerDiscoveryEnqueuesPorts(t *testing.T) {
	d := &fakeDisc{hosts: []lan.Host{
		{IP: netip.MustParseAddr("192.168.1.1"), MAC: "AA:00:00:00:00:01"},
		{IP: netip.MustParseAddr("192.168.1.2"), MAC: "AA:00:00:00:00:02"},
	}}
	r, st, queued := newRunner(t, d)
	if err := r.Run(context.Background(), scheduler.Job{Kind: scheduler.KindDiscovery}); err != nil {
		t.Fatal(err)
	}
	if len(*queued) != 2 || (*queued)[0].Kind != scheduler.KindPorts || (*queued)[0].DeviceID == 0 {
		t.Fatalf("queued %+v", *queued)
	}
	if d.prefix.String() != "192.168.1.0/24" {
		t.Fatalf("prefix %v", d.prefix)
	}
	var n, found int
	var errText string
	st.DB.QueryRow(`SELECT COUNT(*), MAX(found), MAX(error) FROM scans`).Scan(&n, &found, &errText)
	if n != 1 || found != 2 || errText != "" {
		t.Fatalf("scans %d found %d err %q", n, found, errText)
	}
	if r.LastGood().IsZero() {
		t.Fatal("last good discovery not recorded")
	}
	if err := r.Run(context.Background(), (*queued)[0]); err != nil {
		t.Fatal(err)
	}
	devs, _ := r.Inv.List(context.Background())
	probed := 0
	for _, dv := range devs {
		if len(dv.OpenPorts()) == 1 {
			probed++
		}
	}
	if probed != 1 {
		t.Fatalf("probed %d", probed)
	}
}

func TestRunnerDiscoveryFailureNoEvents(t *testing.T) {
	d := &fakeDisc{err: errors.New("network down")}
	r, st, _ := newRunner(t, d)
	if err := r.Run(context.Background(), scheduler.Job{Kind: scheduler.KindDiscovery}); err == nil {
		t.Fatal("expected error")
	}
	var ev int
	var errText string
	st.DB.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&ev)
	st.DB.QueryRow(`SELECT error FROM scans`).Scan(&errText)
	if ev != 0 || errText == "" || !r.LastGood().IsZero() {
		t.Fatalf("events %d err %q", ev, errText)
	}
}

func TestRunnerRejectsBadCIDRSetting(t *testing.T) {
	d := &fakeDisc{}
	r, st, _ := newRunner(t, d)
	s := store.DefaultSettings()
	s.CIDR = "8.8.8.0/24"
	st.SaveSettings(context.Background(), s)
	if err := r.Run(context.Background(), scheduler.Job{Kind: scheduler.KindDiscovery}); err == nil || d.called {
		t.Fatalf("err %v called %v", err, d.called)
	}
}

func TestRunnerPortsAllNeedsDiscovery(t *testing.T) {
	r, _, _ := newRunner(t, &fakeDisc{})
	if err := r.Run(context.Background(), scheduler.Job{Kind: scheduler.KindPorts}); err == nil {
		t.Fatal("ports/all before any discovery should report an error")
	}
}

func TestAutoRangeNarrowsLargeSubnet(t *testing.T) {
	d := &fakeDisc{}
	r, _, _ := newRunner(t, d)
	r.IfaceNet = func(string) (netip.Prefix, error) { return netip.MustParsePrefix("172.17.0.5/16"), nil }
	r.Run(context.Background(), scheduler.Job{Kind: scheduler.KindDiscovery})
	if d.prefix != netip.MustParsePrefix("172.17.0.0/24") {
		t.Fatalf("scanned %v, want the /24 around this host", d.prefix)
	}
}

func TestExplicitLargeRangeStillRejected(t *testing.T) {
	d := &fakeDisc{}
	r, st, _ := newRunner(t, d)
	s := store.DefaultSettings()
	s.CIDR = "10.0.0.0/16"
	st.SaveSettings(context.Background(), s)
	if err := r.Run(context.Background(), scheduler.Job{Kind: scheduler.KindDiscovery}); err == nil || d.called {
		t.Fatalf("err %v called %v", err, d.called)
	}
}
